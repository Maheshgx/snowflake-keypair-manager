# Operations Runbook

## Quarterly Key Rotation
1. Navigate to **Rotate** page
2. Select user (only users with keys shown)
3. Key auto-selected if user has only one
4. Click "Generate" → download new private key (.pem)
5. Execute rotation (auto-cleanup enabled by default)
6. Update service configuration with new private key
7. Verify via **Inventory** drill-down

## New Service Onboarding
1. Create service user: `CREATE USER SVC_NEW TYPE = SERVICE DEFAULT_ROLE = '<role>'`
2. Grant role: `GRANT ROLE <role> TO USER SVC_NEW`
3. Auto-grant task covers key-pair privileges within 24hr (or Admin → Run auto-grant now)
4. Navigate to **Register** → Generate key pair → Select user → Select role from dropdown → Register
5. Download and deploy private key to service

## Incident: Compromised Key
1. **Disable/Remove** → Disable tab → select key → reason: INCIDENT_RESPONSE → instant revocation
2. Investigate (check **Audit log** for recent operations on that key)
3. Once resolved: Generate new key → Register or Rotate

## Cleanup Stale Keys
- Rotation auto-cleanup handles `_ROTATED_` keys automatically (configurable via AUTO_CLEANUP_ROTATED)
- Manual: **Disable/Remove** → Remove tab → select rotated key → reason: CLEANUP

## Configuration Changes
1. Navigate to **Admin** → Config tab
2. Expand the setting to change
3. Modify value (dropdowns for booleans/key sizes, numbers for thresholds)
4. Click Save
5. Task-impacting configs: ensure you're on ACCOUNTADMIN or KEYPAIR_ADMIN (elevated role callout shown)
6. Non-task configs: applied at runtime, no restart needed

## Task Management
1. Navigate to **Admin** → Tasks tab
2. Each task shows: status (🟢/🔴), schedule, description
3. Actions per task:
   - **Suspend** — pause execution
   - **Resume** — restart execution
   - **Save schedule** — change CRON expression
   - **Run now** — manual one-time trigger

## Monitoring

```sql
-- Task execution history (last 7 days)
SELECT * FROM TABLE(INFORMATION_SCHEMA.TASK_HISTORY(
  TASK_NAME => 'EXPIRY_MONITOR_TASK',
  SCHEDULED_TIME_RANGE_START => DATEADD('day', -7, CURRENT_TIMESTAMP())
)) ORDER BY SCHEDULED_TIME DESC;

-- Key health summary
SELECT HEALTH_STATUS, COUNT(*) 
FROM SECURITY_OPS.KEYPAIR_MGMT.V_KEY_HEALTH
GROUP BY HEALTH_STATUS;

-- Recent audit entries
SELECT * FROM SECURITY_OPS.KEYPAIR_MGMT.AUDIT_LOG 
ORDER BY timestamp DESC LIMIT 20;

-- Users without key pairs
SELECT u."name" AS user_name
FROM TABLE(RESULT_SCAN(LAST_QUERY_ID())) u  -- after SHOW USERS
WHERE u."name" NOT IN (SELECT DISTINCT USER_NAME FROM SECURITY_OPS.KEYPAIR_MGMT.KEY_INVENTORY);
```

## Troubleshooting

| Issue | Resolution |
|-------|------------|
| "Role does not exist" | Role must be created first: `CREATE ROLE <name>` |
| "Role not granted to user" | Grant role: `GRANT ROLE <role> TO USER <user>` |
| "Invalid public key" | Use the Generate button — don't paste headers/footers |
| "Insufficient privileges" on task operations | Switch to ACCOUNTADMIN or KEYPAIR_ADMIN via sidebar role switcher |
| Task not running | Admin → Tasks → click Resume |
| Email not received | NOTIFY_EMAIL must be registered and verified in Snowflake notification integration |
| Register shows no users | All users have keys — check "Show all users" checkbox |
| Rotate shows no rotatable keys | Only `_ROTATED_` keys remain — register a new key instead |
| Config save fails with CREATE TASK error | Switch to ACCOUNTADMIN role (elevated privileges required for task recreation) |
| Inventory shows 0 keys | Run Admin → Tasks → INVENTORY_REFRESH_TASK → Run now |
