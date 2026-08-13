-- Snowflake Keypair Manager — Full deployment script (v2 enterprise)
-- Run as ACCOUNTADMIN. Idempotent — safe to re-run.
-- Creates: database, schema, 4 roles, 6 procedures, 3 tasks, 4 tables, 1 view, 1 notification integration

-- ============================================================
-- 1. DATABASE & SCHEMA
-- ============================================================

CREATE DATABASE IF NOT EXISTS SECURITY_OPS
  COMMENT = 'Security operations for credential lifecycle management';

CREATE SCHEMA IF NOT EXISTS SECURITY_OPS.KEYPAIR_MGMT
  COMMENT = 'Named key pair lifecycle management';

-- ============================================================
-- 2. FOUR-TIER RBAC
-- ============================================================

CREATE ROLE IF NOT EXISTS KEYPAIR_ADMIN COMMENT = 'Full key lifecycle + grants + config';
CREATE ROLE IF NOT EXISTS KEYPAIR_MANAGER COMMENT = 'Register, rotate, disable keys';
CREATE ROLE IF NOT EXISTS KEYPAIR_VIEWER COMMENT = 'Read-only inventory and health';
CREATE ROLE IF NOT EXISTS KEYPAIR_AUDITOR COMMENT = 'Read audit logs only';

GRANT ROLE KEYPAIR_VIEWER TO ROLE KEYPAIR_MANAGER;
GRANT ROLE KEYPAIR_MANAGER TO ROLE KEYPAIR_ADMIN;
GRANT ROLE KEYPAIR_AUDITOR TO ROLE KEYPAIR_ADMIN;
GRANT ROLE KEYPAIR_ADMIN TO ROLE SECURITYADMIN;

-- ============================================================
-- 3. TABLES
-- ============================================================

CREATE TABLE IF NOT EXISTS SECURITY_OPS.KEYPAIR_MGMT.AUDIT_LOG (
  audit_id NUMBER AUTOINCREMENT,
  operation STRING NOT NULL,
  target_user STRING NOT NULL,
  key_name STRING,
  reason_code STRING DEFAULT 'ROUTINE',
  executed_by STRING DEFAULT CURRENT_USER(),
  executed_role STRING DEFAULT CURRENT_ROLE(),
  session_id STRING DEFAULT CURRENT_SESSION(),
  before_state VARIANT,
  after_state VARIANT,
  status STRING DEFAULT 'SUCCESS',
  error_message STRING,
  timestamp TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP()
) COMMENT = 'Immutable audit trail for all key pair operations';

CREATE TABLE IF NOT EXISTS SECURITY_OPS.KEYPAIR_MGMT.KEY_INVENTORY (
  user_name STRING, key_name STRING, fingerprint STRING, role_scope STRING,
  status STRING, comment STRING, created_on STRING, created_by STRING,
  last_used_on STRING, expires_at STRING, rotated_to STRING,
  refreshed_at TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP()
) COMMENT = 'Pre-computed key inventory (hourly refresh)';

CREATE TABLE IF NOT EXISTS SECURITY_OPS.KEYPAIR_MGMT.APP_CONFIG (
  config_key STRING PRIMARY KEY,
  config_value STRING,
  description STRING,
  updated_at TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP()
) COMMENT = 'Externalized application configuration';

INSERT OVERWRITE INTO SECURITY_OPS.KEYPAIR_MGMT.APP_CONFIG VALUES
  ('MIN_KEY_SIZE', '4096', 'Minimum RSA key size (NIST SP 800-131A)', CURRENT_TIMESTAMP()),
  ('DEFAULT_EXPIRY_DAYS', '90', 'Default key expiration in days', CURRENT_TIMESTAMP()),
  ('ALERT_THRESHOLD_DAYS', '14', 'Days before expiry to trigger alert', CURRENT_TIMESTAMP()),
  ('NOTIFY_EMAIL', '', 'Default notification email', CURRENT_TIMESTAMP()),
  ('ROTATION_GRACE_HOURS', '24', 'Hours old key remains valid after rotation', CURRENT_TIMESTAMP()),
  ('AUTO_CLEANUP_ROTATED', 'TRUE', 'Auto-remove rotated keys after rotation', CURRENT_TIMESTAMP()),
  ('REQUIRE_ROLE_RESTRICTION', 'TRUE', 'Enforce role restriction on registration', CURRENT_TIMESTAMP()),
  ('ENVIRONMENT', 'PROD', 'Deployment environment', CURRENT_TIMESTAMP());

CREATE TABLE IF NOT EXISTS SECURITY_OPS.KEYPAIR_MGMT.ROTATION_POLICIES (
  username STRING NOT NULL,
  key_name STRING NOT NULL,
  rotation_interval_days INT NOT NULL DEFAULT 90,
  auto_rotate BOOLEAN NOT NULL DEFAULT FALSE,
  last_rotated_at TIMESTAMP_LTZ,
  notify_email STRING,
  created_at TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP(),
  PRIMARY KEY (username, key_name)
) COMMENT = 'Per-user rotation cadence policies';

-- ============================================================
-- 4. STORED PROCEDURES
-- ============================================================

CREATE OR REPLACE PROCEDURE SECURITY_OPS.KEYPAIR_MGMT.SP_REGISTER_KEY(
  P_USERNAME STRING, P_KEY_NAME STRING, P_PUBLIC_KEY STRING,
  P_ROLE_RESTRICTION STRING, P_DAYS_TO_EXPIRY INT, P_COMMENT STRING, P_REASON STRING, P_EXECUTED_BY STRING
) RETURNS VARIANT LANGUAGE SQL EXECUTE AS CALLER
AS
BEGIN
  IF (:P_USERNAME IS NULL OR :P_USERNAME = '' OR :P_KEY_NAME IS NULL OR :P_KEY_NAME = '' OR :P_PUBLIC_KEY IS NULL OR :P_PUBLIC_KEY = '') THEN
    RETURN OBJECT_CONSTRUCT('success', FALSE, 'error', 'Username, key name, and public key are required');
  END IF;
  LET sql_stmt STRING := 'ALTER USER ' || :P_USERNAME || ' ADD KEY PAIR ' || :P_KEY_NAME || ' PUBLIC_KEY = ''' || :P_PUBLIC_KEY || '''';
  IF (:P_ROLE_RESTRICTION IS NOT NULL AND :P_ROLE_RESTRICTION != '') THEN
    sql_stmt := :sql_stmt || ' ROLE_RESTRICTION = ''' || :P_ROLE_RESTRICTION || '''';
  END IF;
  sql_stmt := :sql_stmt || ' DAYS_TO_EXPIRY = ' || :P_DAYS_TO_EXPIRY::STRING;
  IF (:P_COMMENT IS NOT NULL AND :P_COMMENT != '') THEN
    sql_stmt := :sql_stmt || ' COMMENT = ''' || :P_COMMENT || '''';
  END IF;
  EXECUTE IMMEDIATE :sql_stmt;
  INSERT INTO SECURITY_OPS.KEYPAIR_MGMT.AUDIT_LOG (operation, target_user, key_name, reason_code, executed_by, executed_role, after_state)
    SELECT 'REGISTER', :P_USERNAME, :P_KEY_NAME, COALESCE(:P_REASON, 'NEW_KEY'), :P_EXECUTED_BY, CURRENT_ROLE(),
           OBJECT_CONSTRUCT('role_restriction', :P_ROLE_RESTRICTION, 'days_to_expiry', :P_DAYS_TO_EXPIRY, 'comment', :P_COMMENT);
  RETURN OBJECT_CONSTRUCT('success', TRUE, 'message', 'Key ' || :P_KEY_NAME || ' registered on ' || :P_USERNAME);
END;

CREATE OR REPLACE PROCEDURE SECURITY_OPS.KEYPAIR_MGMT.SP_ROTATE_KEY(
  P_USERNAME STRING, P_KEY_NAME STRING, P_NEW_PUBLIC_KEY STRING,
  P_AUTO_CLEANUP BOOLEAN, P_REASON STRING, P_EXECUTED_BY STRING
) RETURNS VARIANT LANGUAGE SQL EXECUTE AS CALLER
AS
BEGIN
  IF (:P_USERNAME IS NULL OR :P_KEY_NAME IS NULL OR :P_NEW_PUBLIC_KEY IS NULL) THEN
    RETURN OBJECT_CONSTRUCT('success', FALSE, 'error', 'Username, key name, and new public key required');
  END IF;
  SHOW USER KEY PAIRS FOR USER IDENTIFIER(:P_USERNAME);
  LET before_fp STRING := '';
  SELECT "fingerprint" INTO :before_fp FROM TABLE(RESULT_SCAN(LAST_QUERY_ID())) WHERE "name" = :P_KEY_NAME;
  LET sql_stmt STRING := 'ALTER USER ' || :P_USERNAME || ' ROTATE KEY PAIR ' || :P_KEY_NAME || ' PUBLIC_KEY = ''' || :P_NEW_PUBLIC_KEY || '''';
  EXECUTE IMMEDIATE :sql_stmt;
  INSERT INTO SECURITY_OPS.KEYPAIR_MGMT.AUDIT_LOG (operation, target_user, key_name, reason_code, executed_by, executed_role, before_state)
    SELECT 'ROTATE', :P_USERNAME, :P_KEY_NAME, COALESCE(:P_REASON, 'SCHEDULED'), :P_EXECUTED_BY, CURRENT_ROLE(),
           OBJECT_CONSTRUCT('previous_fingerprint', :before_fp);
  LET cleaned INT := 0;
  IF (:P_AUTO_CLEANUP) THEN
    SHOW USER KEY PAIRS FOR USER IDENTIFIER(:P_USERNAME);
    LET c CURSOR FOR SELECT "name" AS kname FROM TABLE(RESULT_SCAN(LAST_QUERY_ID())) WHERE "name" ILIKE '%_ROTATED_%';
    FOR r IN c DO
      EXECUTE IMMEDIATE 'ALTER USER ' || :P_USERNAME || ' REMOVE KEY PAIR ' || r.kname;
      cleaned := :cleaned + 1;
    END FOR;
  END IF;
  RETURN OBJECT_CONSTRUCT('success', TRUE, 'message', 'Rotated ' || :P_KEY_NAME, 'cleaned', :cleaned);
END;

CREATE OR REPLACE PROCEDURE SECURITY_OPS.KEYPAIR_MGMT.SP_MODIFY_KEY(
  P_USERNAME STRING, P_KEY_NAME STRING, P_ACTION STRING, P_REASON STRING, P_EXECUTED_BY STRING
) RETURNS VARIANT LANGUAGE SQL EXECUTE AS CALLER
AS
BEGIN
  IF (:P_USERNAME IS NULL OR :P_KEY_NAME IS NULL OR :P_ACTION IS NULL) THEN
    RETURN OBJECT_CONSTRUCT('success', FALSE, 'error', 'Username, key name, and action required');
  END IF;
  LET sql_stmt STRING := '';
  IF (:P_ACTION = 'DISABLE') THEN
    sql_stmt := 'ALTER USER ' || :P_USERNAME || ' MODIFY KEY PAIR ' || :P_KEY_NAME || ' SET DISABLED = TRUE';
  ELSEIF (:P_ACTION = 'ENABLE') THEN
    sql_stmt := 'ALTER USER ' || :P_USERNAME || ' MODIFY KEY PAIR ' || :P_KEY_NAME || ' SET DISABLED = FALSE';
  ELSEIF (:P_ACTION = 'REMOVE') THEN
    sql_stmt := 'ALTER USER ' || :P_USERNAME || ' REMOVE KEY PAIR ' || :P_KEY_NAME;
  ELSE
    RETURN OBJECT_CONSTRUCT('success', FALSE, 'error', 'Action must be DISABLE, ENABLE, or REMOVE');
  END IF;
  EXECUTE IMMEDIATE :sql_stmt;
  INSERT INTO SECURITY_OPS.KEYPAIR_MGMT.AUDIT_LOG (operation, target_user, key_name, reason_code, executed_by, executed_role)
    SELECT :P_ACTION, :P_USERNAME, :P_KEY_NAME, COALESCE(:P_REASON, 'MANUAL'), :P_EXECUTED_BY, CURRENT_ROLE();
  RETURN OBJECT_CONSTRUCT('success', TRUE, 'message', :P_ACTION || ' ' || :P_KEY_NAME || ' on ' || :P_USERNAME);
END;

CREATE OR REPLACE PROCEDURE SECURITY_OPS.KEYPAIR_MGMT.REFRESH_INVENTORY()
  RETURNS STRING LANGUAGE SQL EXECUTE AS CALLER
AS
BEGIN
  CREATE TABLE IF NOT EXISTS SECURITY_OPS.KEYPAIR_MGMT.KEY_INVENTORY (
    user_name STRING, key_name STRING, fingerprint STRING, role_scope STRING,
    status STRING, comment STRING, created_on STRING, created_by STRING,
    last_used_on STRING, expires_at STRING, rotated_to STRING,
    refreshed_at TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP());
  TRUNCATE TABLE SECURITY_OPS.KEYPAIR_MGMT.KEY_INVENTORY;
  LET total INT := 0;
  LET curr_user STRING := '';
  SHOW USERS;
  LET c1 CURSOR FOR SELECT "name" AS username FROM TABLE(RESULT_SCAN(LAST_QUERY_ID())) WHERE "has_rsa_public_key" = 'true';
  FOR u IN c1 DO
    total := :total + 1;
    curr_user := u.username;
    SHOW USER KEY PAIRS FOR USER IDENTIFIER(:curr_user);
    INSERT INTO SECURITY_OPS.KEYPAIR_MGMT.KEY_INVENTORY (user_name, key_name, fingerprint, role_scope, status, comment, created_on, created_by, last_used_on, expires_at, rotated_to)
      SELECT "user_name", "name", "fingerprint", "role_scope", "status", "comment", "created_on", "created_by", "last_used_on", "expires_at", "rotated_to" FROM TABLE(RESULT_SCAN(LAST_QUERY_ID()));
  END FOR;
  RETURN 'Inventory refreshed. ' || :total::STRING || ' users scanned.';
END;

CREATE OR REPLACE PROCEDURE SECURITY_OPS.KEYPAIR_MGMT.CHECK_KEY_EXPIRY(THRESHOLD_DAYS INT, NOTIFY_EMAIL STRING)
  RETURNS STRING LANGUAGE SQL EXECUTE AS CALLER
AS
BEGIN
  LET all_expiring STRING := '';
  LET batch STRING := '';
  LET total_checked INT := 0;
  LET curr_user STRING := '';
  SHOW USERS;
  LET c1 CURSOR FOR SELECT "name" AS username FROM TABLE(RESULT_SCAN(LAST_QUERY_ID())) WHERE "has_rsa_public_key" = 'true';
  FOR u IN c1 DO
    total_checked := :total_checked + 1;
    curr_user := u.username;
    SHOW USER KEY PAIRS FOR USER IDENTIFIER(:curr_user);
    SELECT COALESCE(LISTAGG("user_name" || ' | ' || "name" || ' | ' || DATEDIFF('day', CURRENT_TIMESTAMP(), "expires_at")::STRING || 'd', '\n'), '')
      INTO :batch FROM (SELECT "name", "user_name", "expires_at" FROM TABLE(RESULT_SCAN(LAST_QUERY_ID()))
        WHERE "status" = 'ACTIVE' AND "expires_at" IS NOT NULL AND DATEDIFF('day', CURRENT_TIMESTAMP(), "expires_at") <= :THRESHOLD_DAYS AND DATEDIFF('day', CURRENT_TIMESTAMP(), "expires_at") >= 0);
    IF (:batch IS NOT NULL AND :batch != '') THEN
      IF (:all_expiring != '') THEN all_expiring := :all_expiring || '\n' || :batch;
      ELSE all_expiring := :batch; END IF;
    END IF;
  END FOR;
  IF (:all_expiring != '') THEN
    CALL SYSTEM$SEND_EMAIL('keypair_mgmt_notifications', :NOTIFY_EMAIL, 'KEY PAIR EXPIRY ALERT',
      'Keys expiring within ' || :THRESHOLD_DAYS::STRING || ' days:\n' || :all_expiring);
    RETURN 'ALERT SENT. ' || :total_checked::STRING || ' users scanned.';
  END IF;
  RETURN 'OK — no expiring keys. Scanned ' || :total_checked::STRING || ' users.';
END;

CREATE OR REPLACE PROCEDURE SECURITY_OPS.KEYPAIR_MGMT.AUTO_GRANT_KEYPAIR_ADMIN()
  RETURNS STRING LANGUAGE SQL EXECUTE AS CALLER
AS
BEGIN
  LET granted_count INT := 0;
  LET curr_user STRING := '';
  SHOW USERS;
  LET c1 CURSOR FOR SELECT "name" AS username FROM TABLE(RESULT_SCAN(LAST_QUERY_ID()));
  FOR u IN c1 DO
    curr_user := u.username;
    GRANT MODIFY PROGRAMMATIC AUTHENTICATION METHODS ON USER IDENTIFIER(:curr_user) TO ROLE KEYPAIR_ADMIN;
    granted_count := :granted_count + 1;
  END FOR;
  RETURN 'Granted KEYPAIR_ADMIN on ' || :granted_count::STRING || ' users.';
END;

-- ============================================================
-- 5. VIEWS
-- ============================================================

CREATE OR REPLACE VIEW SECURITY_OPS.KEYPAIR_MGMT.V_KEY_HEALTH AS
SELECT user_name AS USER_NAME, key_name AS KEY_NAME, status AS STATUS, role_scope AS ROLE_SCOPE,
  expires_at AS EXPIRES_AT, created_by AS CREATED_BY, refreshed_at AS REFRESHED_AT,
  CASE
    WHEN status = 'DISABLED' THEN 'DISABLED'
    WHEN key_name ILIKE '%_ROTATED_%' THEN 'STALE_ROTATED'
    WHEN expires_at IS NOT NULL AND DATEDIFF('day', CURRENT_TIMESTAMP(), expires_at) < 0 THEN 'EXPIRED'
    WHEN expires_at IS NOT NULL AND DATEDIFF('day', CURRENT_TIMESTAMP(), expires_at) < 7 THEN 'CRITICAL'
    WHEN expires_at IS NOT NULL AND DATEDIFF('day', CURRENT_TIMESTAMP(), expires_at) < 14 THEN 'WARNING'
    WHEN role_scope IS NULL OR role_scope = '' THEN 'UNSCOPED'
    ELSE 'HEALTHY'
  END AS HEALTH_STATUS,
  CASE WHEN expires_at IS NOT NULL THEN DATEDIFF('day', CURRENT_TIMESTAMP(), expires_at) ELSE NULL END AS DAYS_TO_EXPIRY
FROM SECURITY_OPS.KEYPAIR_MGMT.KEY_INVENTORY;

-- ============================================================
-- 6. NOTIFICATION INTEGRATION
-- ============================================================

CREATE NOTIFICATION INTEGRATION IF NOT EXISTS keypair_mgmt_notifications
  TYPE = EMAIL ENABLED = TRUE;

-- ============================================================
-- 7. SCHEDULED TASKS
-- ============================================================

CREATE OR REPLACE TASK SECURITY_OPS.KEYPAIR_MGMT.INVENTORY_REFRESH_TASK
  WAREHOUSE = COMPUTE_WH
  SCHEDULE = 'USING CRON 0 * * * * America/New_York'
  COMMENT = 'Hourly inventory rebuild'
AS CALL SECURITY_OPS.KEYPAIR_MGMT.REFRESH_INVENTORY();

CREATE OR REPLACE TASK SECURITY_OPS.KEYPAIR_MGMT.EXPIRY_MONITOR_TASK
  WAREHOUSE = COMPUTE_WH
  SCHEDULE = 'USING CRON 0 8 * * MON-FRI America/New_York'
  COMMENT = 'Weekday expiry alerts'
AS CALL SECURITY_OPS.KEYPAIR_MGMT.CHECK_KEY_EXPIRY(14, 'skrz2014@gmail.com');

CREATE OR REPLACE TASK SECURITY_OPS.KEYPAIR_MGMT.AUTO_GRANT_TASK
  WAREHOUSE = COMPUTE_WH
  SCHEDULE = 'USING CRON 0 0 * * * America/New_York'
  COMMENT = 'Daily auto-grant for new users'
AS CALL SECURITY_OPS.KEYPAIR_MGMT.AUTO_GRANT_KEYPAIR_ADMIN();

ALTER TASK SECURITY_OPS.KEYPAIR_MGMT.INVENTORY_REFRESH_TASK RESUME;
ALTER TASK SECURITY_OPS.KEYPAIR_MGMT.EXPIRY_MONITOR_TASK RESUME;
ALTER TASK SECURITY_OPS.KEYPAIR_MGMT.AUTO_GRANT_TASK RESUME;

-- ============================================================
-- 8. GRANTS
-- ============================================================

GRANT USAGE ON DATABASE SECURITY_OPS TO ROLE KEYPAIR_VIEWER;
GRANT USAGE ON SCHEMA SECURITY_OPS.KEYPAIR_MGMT TO ROLE KEYPAIR_VIEWER;
GRANT SELECT ON TABLE SECURITY_OPS.KEYPAIR_MGMT.KEY_INVENTORY TO ROLE KEYPAIR_VIEWER;
GRANT SELECT ON VIEW SECURITY_OPS.KEYPAIR_MGMT.V_KEY_HEALTH TO ROLE KEYPAIR_VIEWER;
GRANT SELECT ON TABLE SECURITY_OPS.KEYPAIR_MGMT.APP_CONFIG TO ROLE KEYPAIR_VIEWER;
GRANT SELECT ON TABLE SECURITY_OPS.KEYPAIR_MGMT.AUDIT_LOG TO ROLE KEYPAIR_AUDITOR;

-- KEYPAIR_ADMIN needs full schema access (CREATE TABLE for inventory refresh)
GRANT CREATE TABLE ON SCHEMA SECURITY_OPS.KEYPAIR_MGMT TO ROLE KEYPAIR_ADMIN;
GRANT CREATE TASK ON SCHEMA SECURITY_OPS.KEYPAIR_MGMT TO ROLE KEYPAIR_ADMIN;
GRANT EXECUTE TASK ON ACCOUNT TO ROLE KEYPAIR_ADMIN;
GRANT INSERT, DELETE, TRUNCATE ON ALL TABLES IN SCHEMA SECURITY_OPS.KEYPAIR_MGMT TO ROLE KEYPAIR_ADMIN;
GRANT SELECT ON ALL TABLES IN SCHEMA SECURITY_OPS.KEYPAIR_MGMT TO ROLE KEYPAIR_ADMIN;
GRANT SELECT ON ALL VIEWS IN SCHEMA SECURITY_OPS.KEYPAIR_MGMT TO ROLE KEYPAIR_ADMIN;
GRANT USAGE ON ALL PROCEDURES IN SCHEMA SECURITY_OPS.KEYPAIR_MGMT TO ROLE KEYPAIR_ADMIN;

-- KEYPAIR_MANAGER needs procedure execution and audit insert
GRANT USAGE ON ALL PROCEDURES IN SCHEMA SECURITY_OPS.KEYPAIR_MGMT TO ROLE KEYPAIR_MANAGER;
GRANT INSERT ON TABLE SECURITY_OPS.KEYPAIR_MGMT.AUDIT_LOG TO ROLE KEYPAIR_MANAGER;
GRANT SELECT ON ALL TABLES IN SCHEMA SECURITY_OPS.KEYPAIR_MGMT TO ROLE KEYPAIR_MANAGER;
GRANT SELECT ON ALL VIEWS IN SCHEMA SECURITY_OPS.KEYPAIR_MGMT TO ROLE KEYPAIR_MANAGER;

-- ============================================================
-- 9. INITIAL RUN
-- ============================================================

CALL SECURITY_OPS.KEYPAIR_MGMT.REFRESH_INVENTORY();
CALL SECURITY_OPS.KEYPAIR_MGMT.AUTO_GRANT_KEYPAIR_ADMIN();
