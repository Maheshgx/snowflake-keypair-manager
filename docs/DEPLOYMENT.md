# Deployment Guide

## Prerequisites

| Requirement | Minimum |
|-------------|---------|
| Snowflake Edition | Enterprise or higher |
| Account Version | 2026+ (Named Key Pairs GA — July 15, 2026) |
| Role | ACCOUNTADMIN (initial setup only) |
| Workspace | Snowsight Workspace with Container Runtime |
| Python packages | `streamlit`, `cryptography` (in pyproject.toml) |

## Deploy in 3 Steps

**Step 1:** Run `sql/deploy.sql` as ACCOUNTADMIN (idempotent — safe to re-run, 319 lines)

This creates:
- Database: `SECURITY_OPS`
- Schema: `SECURITY_OPS.KEYPAIR_MGMT`
- 4 roles: KEYPAIR_ADMIN, KEYPAIR_MANAGER, KEYPAIR_VIEWER, KEYPAIR_AUDITOR
- 6 stored procedures: SP_REGISTER_KEY, SP_ROTATE_KEY, SP_MODIFY_KEY, REFRESH_INVENTORY, CHECK_KEY_EXPIRY, AUTO_GRANT_KEYPAIR_ADMIN
- 3 tasks: INVENTORY_REFRESH_TASK, EXPIRY_MONITOR_TASK, AUTO_GRANT_TASK
- 4 tables: KEY_INVENTORY, AUDIT_LOG, ROTATION_POLICIES, APP_CONFIG
- 1 view: V_KEY_HEALTH
- All grants (including CREATE TASK, EXECUTE TASK for KEYPAIR_ADMIN)

**Step 2:** Grant the admin role to yourself:
```sql
GRANT ROLE KEYPAIR_ADMIN TO USER <YOUR_USERNAME>;
```

**Step 3:** Upload `snowflake-keypair-manager/` folder to Workspace → Click Run

## Post-Deployment Verification

```sql
-- Verify tasks are running
SHOW TASKS IN SCHEMA SECURITY_OPS.KEYPAIR_MGMT;  -- All should show 'started'

-- Verify auto-grant works
CALL SECURITY_OPS.KEYPAIR_MGMT.AUTO_GRANT_KEYPAIR_ADMIN();

-- Verify inventory refresh
CALL SECURITY_OPS.KEYPAIR_MGMT.REFRESH_INVENTORY();

-- Check config loaded
SELECT * FROM SECURITY_OPS.KEYPAIR_MGMT.APP_CONFIG;
```

## Configuration (APP_CONFIG table)

| Key | Default | Description | Impact |
|-----|---------|-------------|--------|
| `ALERT_THRESHOLD_DAYS` | 14 | Days before expiry to alert | Recreates EXPIRY_MONITOR_TASK |
| `NOTIFY_EMAIL` | (set yours) | Alert recipient (must be Snowflake-verified) | Recreates EXPIRY_MONITOR_TASK |
| `DEFAULT_EXPIRY_DAYS` | 90 | Default for Register form | Runtime |
| `MIN_KEY_SIZE` | 4096 | 2048 or 4096 (NIST SP 800-131A) | Runtime enforcement |
| `INVENTORY_REFRESH_MINUTES` | 60 | Refresh interval | Recreates INVENTORY_REFRESH_TASK |
| `REQUIRE_ROLE_RESTRICTION` | TRUE | Require role restriction on registration | Runtime enforcement |
| `AUTO_CLEANUP_ROTATED` | TRUE | Auto-remove rotated keys on rotation | Runtime (checkbox default) |
| `ENVIRONMENT` | PROD | Informational | None |

## Notification Integration (for email alerts)

```sql
CREATE NOTIFICATION INTEGRATION IF NOT EXISTS KEYPAIR_ALERTS
  TYPE = EMAIL
  ENABLED = TRUE
  ALLOWED_RECIPIENTS = ('your@email.com');
```

## Teardown

Run `sql/teardown.sql` to remove all objects (database, roles, tasks).

## Troubleshooting

| Issue | Resolution |
|-------|------------|
| "Role does not exist" error | Run deploy.sql as ACCOUNTADMIN |
| Tasks not running | `ALTER TASK SECURITY_OPS.KEYPAIR_MGMT.<task> RESUME` |
| Email not received | Verify email in notification integration + check NOTIFY_EMAIL config |
| Register shows no users | All users have keys — check "Show all users" checkbox |
| Rotate shows no keys | Only `_ROTATED_` keys remain — register new key |
| Config save fails | Switch to ACCOUNTADMIN — CREATE TASK requires elevated role |
| App doesn't start | Verify all artifacts listed in `snowflake.yml` (10 files) |
| "Insufficient privileges" | Ensure KEYPAIR_ADMIN has CREATE TASK + EXECUTE TASK grants |
