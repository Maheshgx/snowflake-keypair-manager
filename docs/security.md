# Security Model

## Threat Analysis

| Threat | Mitigation |
|--------|-----------|
| SQL injection | All identifiers validated: alphanumeric + underscore only via `validate_identifier()` |
| Private key exposure | Generated in-memory, never stored; user downloads immediately via browser |
| Privilege escalation | 4-tier RBAC: KEYPAIR_ADMIN > KEYPAIR_MANAGER > KEYPAIR_VIEWER + KEYPAIR_AUDITOR |
| Stale/orphaned keys | Automated expiry monitoring task + auto-cleanup after rotation |
| Unauthorized registration | ROLE_RESTRICTION enforced (only roles granted to user shown in dropdown) |
| Duplicate key errors | Pre-registration validation checks existing key names per user |
| Role not granted to user | Per-user role dropdown via `SHOW GRANTS TO USER` prevents selecting ungranted roles |
| Raw error exposure | `parse_error()` maps Snowflake errors to Title + Reason + Remedy (no stack traces) |
| Config drift | Reactive config — task-impacting changes auto-trigger task recreation |
| Insufficient privileges | Elevated role callout warns user before attempting task-impacting operations |

## RBAC Hierarchy (4-Tier)

```
ACCOUNTADMIN
  └── SECURITYADMIN
        └── KEYPAIR_ADMIN (full lifecycle + grants + admin page + config + task management)
              ├── KEYPAIR_MANAGER (register, rotate, disable — no admin/config)
              │     └── KEYPAIR_VIEWER (read-only dashboard + inventory)
              └── KEYPAIR_AUDITOR (audit log access only)
```

### Grants to KEYPAIR_ADMIN

| Grant | Purpose |
|-------|---------|
| `CREATE TABLE ON SCHEMA` | Inventory refresh (recreates KEY_INVENTORY) |
| `CREATE TASK ON SCHEMA` | Reactive config (recreates tasks on config change) |
| `EXECUTE TASK ON ACCOUNT` | Resume tasks after recreation |
| `INSERT, DELETE, TRUNCATE ON ALL TABLES` | Audit log + inventory management |
| `MODIFY PROGRAMMATIC AUTHENTICATION METHODS ON USER *` | Key pair operations (auto-granted daily) |

## UI Security (Page Gating)

Pages are **hidden** (not just disabled) based on `CURRENT_ROLE()`:

| Role | Visible Pages |
|------|--------------|
| KEYPAIR_VIEWER | Overview, Inventory |
| KEYPAIR_MANAGER | + Register, Rotate, Disable/Remove |
| KEYPAIR_AUDITOR | + Audit log |
| KEYPAIR_ADMIN | + Admin (all pages visible) |

## Key Lifecycle Security

- **Registration:** ROLE_RESTRICTION (per-user roles only) + DAYS_TO_EXPIRY enforced via policy
- **Rotation:** Old key auto-cleaned (no stale credentials left behind)
- **Disable:** Instant revocation (SET DISABLED = TRUE), reversible
- **Remove:** Permanent deletion for decommissioning (irreversible)
- **Audit:** Every operation logged with: timestamp, executed_by, executed_role, reason_code, before/after state

## Error Handling Security

Snowflake errors are **never** shown raw. The `parse_error()` function maps patterns to user-friendly messages:

| Error | User Sees |
|-------|-----------|
| Role does not exist | Title + reason + "Create the role first" |
| Role not granted to user | Title + reason + "Grant role or select a granted one" |
| Invalid public key | Title + reason + "Use the Generate button" |
| Insufficient privileges | Title + reason + "Switch to KEYPAIR_ADMIN" |
| Unknown errors | Truncated message + "Check Audit log" |

## Private Key Handling

- Private keys are generated in-memory using `cryptography` library (RSA 2048/4096)
- Keys exist only in the Streamlit session — never written to Snowflake storage
- User must download via browser before navigating away
- No server-side key storage or retrieval mechanism
