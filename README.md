# Snowflake Keypair Manager

**Enterprise Named Key Pair Lifecycle Management for Snowflake**

Production-grade, multi-page Streamlit in Snowflake application with stored procedure service layer, 4-tier RBAC, immutable audit logging, dark theme, config-driven automation, and reactive system triggers.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    PRESENTATION LAYER                             │
│         Streamlit Multi-Page (st.navigation)                     │
│         Dark theme │ Role toggle │ RBAC-gated pages              │
├──────┬──────────┬──────────┬────────┬──────────┬───────┬────────┤
│ Over │ Inventory│ Register │ Rotate │ Disable  │ Audit │ Admin  │
│ view │          │          │        │          │       │        │
└──┬───┴────┬─────┴────┬─────┴───┬────┴────┬─────┴───┬───┴────┬───┘
   │        │          │         │         │         │        │
┌──▼────────▼──────────▼─────────▼─────────▼─────────▼────────▼───┐
│                    SERVICE LAYER (services.py)                     │
│  call_proc() │ validate_identifier() │ compute_health_score()    │
│  generate_key_pair() │ get_key_inventory() │ get_config()         │
└──────────────────────────────┬───────────────────────────────────┘
                               │
┌──────────────────────────────▼───────────────────────────────────┐
│                 STORED PROCEDURES (no inline DDL)                  │
│  SP_REGISTER_KEY │ SP_ROTATE_KEY │ SP_MODIFY_KEY                  │
│  REFRESH_INVENTORY │ CHECK_KEY_EXPIRY │ AUTO_GRANT_KEYPAIR_ADMIN  │
└──────────────────────────────┬───────────────────────────────────┘
                               │
┌──────────────────────────────▼───────────────────────────────────┐
│                    DATA LAYER                                      │
│  KEY_INVENTORY │ AUDIT_LOG │ ROTATION_POLICIES │ APP_CONFIG       │
│  V_KEY_HEALTH (view) │ PRIVATE_KEYS (encrypted stage)            │
└──────────────────────────────┬───────────────────────────────────┘
                               │
┌──────────────────────────────▼───────────────────────────────────┐
│                    AUTOMATION (Snowflake Tasks)                    │
│  INVENTORY_REFRESH_TASK — hourly (configurable)                   │
│  EXPIRY_MONITOR_TASK — 8am weekdays (threshold + email from config│
│  AUTO_GRANT_TASK — midnight daily                                  │
└──────────────────────────────────────────────────────────────────┘
```

---

## Features

| Page | Role | Capabilities |
|------|------|-------------|
| **Overview** | KEYPAIR_VIEWER+ | Health score, status badges, **tabbed view** (users with keys / users without keys), searchable & filterable inventory |
| **Inventory** | KEYPAIR_VIEWER+ | **All users** summary table (with/without keys), filter/search, live per-user drill-down |
| **Register** | KEYPAIR_MANAGER+ | In-app RSA generation, **per-user role dropdown** (only roles granted to selected user), policy enforcement, duplicate detection |
| **Rotate** | KEYPAIR_MANAGER+ | **Only users with keys shown**, zero-downtime rotation, auto-cleanup, reason codes |
| **Disable/Remove** | KEYPAIR_MANAGER+ | **Only users with keys shown**, instant disable/enable/remove with reason tracking |
| **Audit** | KEYPAIR_AUDITOR+ | Immutable log with operation/status filters, before/after state |
| **Admin** | KEYPAIR_ADMIN | RBAC overview, **per-task edit/save/suspend/resume/run**, **per-config edit/save with reactive triggers**, **elevated role callout** for task-impacting changes |

### UI Features
- **Dark theme** — Google Material dark palette (`#1e1e1e` / `#8ab4f8`)
- **Role toggle** — sidebar expander to switch roles without leaving the app
- **Reactive config** — change a value in Admin → Save → impacted tasks automatically recreated
- **Task explanations** — Admin page describes what each task does in plain language
- **Health score** — computed from key status, expiry proximity, role scoping, stale rotated keys
- **Smart dropdowns** — Role restriction shows only roles granted to the selected user; Rotate/Disable only show users with keys
- **Graceful error handling** — errors parsed into Title + Reason + Remedy (not raw Snowflake traces)
- **Service account scoping** — only `SVC_*` users shown (configurable prefix via `APP_CONFIG.SERVICE_USER_PREFIX`)

---

## Reactive Configuration

When you change a config value and click Save, the app **automatically triggers** the impacted system action:

| Config Changed | Automatic System Action |
|---|---|
| `ALERT_THRESHOLD_DAYS` | Recreates EXPIRY_MONITOR_TASK with new threshold |
| `NOTIFY_EMAIL` | Recreates EXPIRY_MONITOR_TASK with new recipient |
| `INVENTORY_REFRESH_MINUTES` | Recreates INVENTORY_REFRESH_TASK with new cron schedule |
| `MIN_KEY_SIZE` | Enforced on next registration (runtime) |
| `REQUIRE_ROLE_RESTRICTION` | Enforced on next registration (runtime) |
| `AUTO_CLEANUP_ROTATED` | Applied on next rotation (runtime) |
| `DEFAULT_EXPIRY_DAYS` | New default in Register form (runtime) |

No manual SQL needed. Change the value → the system adapts.

---

## RBAC Model (4-Tier)

```
ACCOUNTADMIN
  └── SECURITYADMIN
        └── KEYPAIR_ADMIN (full lifecycle + grants + admin + config)
              ├── KEYPAIR_MANAGER (register, rotate, disable — no admin)
              │     └── KEYPAIR_VIEWER (read-only dashboard + inventory)
              └── KEYPAIR_AUDITOR (audit log access only)
```

Pages **hidden** based on `CURRENT_ROLE()`. Role switcher in sidebar.

---

## Quick Start

```sql
-- Step 1: Run sql/deploy.sql as ACCOUNTADMIN (idempotent, 319 lines)
-- Step 2: GRANT ROLE KEYPAIR_ADMIN TO USER <YOUR_USER>;
-- Step 3: Upload snowflake-keypair-manager/ to Workspace → Run
```

---

## Repository Structure

```
snowflake-keypair-manager/
├── streamlit_app.py              # Entry point (100 lines) — RBAC + role toggle + real user capture
├── app_pages/
│   ├── __init__.py
│   ├── services.py              # Service layer (250 lines) — call_proc, error parsing, real user injection
│   ├── overview.py              # Dashboard + health score + key/non-key users tab (68 lines)
│   ├── inventory.py             # All users summary + live drill-down (55 lines)
│   ├── register.py              # Key gen + per-user role dropdown + policy enforcement (109 lines)
│   ├── rotate.py                # Rotation + auto-cleanup + reason codes (71 lines)
│   ├── disable.py               # Disable / Enable / Remove + reasons (68 lines)
│   ├── audit.py                 # Audit log viewer + filters (27 lines)
│   └── admin.py                 # RBAC, task edit/save, reactive config + elevated role checks (239 lines)
├── sql/
│   ├── deploy.sql               # Full deployment (319 lines, idempotent)
│   └── teardown.sql             # Clean removal
├── docs/
│   ├── medium_article.md        # Ready-to-publish blog post with all doc links
│   ├── DEPLOYMENT.md            # Deployment guide
│   ├── security.md              # Security model
│   └── operations.md            # Runbook
├── .streamlit/config.toml       # Dark Material theme (#1e1e1e / #8ab4f8)
├── .gitignore
├── snowflake.yml                # Manifest (all 10 artifacts listed)
├── pyproject.toml
├── LICENSE
└── README.md
```

---

## Snowflake Objects

| Object | Type | Purpose |
|--------|------|---------|
| `SECURITY_OPS` | Database | Security operations |
| `SECURITY_OPS.KEYPAIR_MGMT` | Schema | All objects |
| `SP_REGISTER_KEY(8 params)` | Procedure | Register + validate + audit (includes P_EXECUTED_BY) |
| `SP_ROTATE_KEY(6 params)` | Procedure | Rotate + before-state + auto-cleanup (includes P_EXECUTED_BY) |
| `SP_MODIFY_KEY(5 params)` | Procedure | Disable/Enable/Remove + audit (includes P_EXECUTED_BY) |
| `REFRESH_INVENTORY()` | Procedure | Rebuild KEY_INVENTORY |
| `CHECK_KEY_EXPIRY(days, email)` | Procedure | Scan + email alert |
| `AUTO_GRANT_KEYPAIR_ADMIN()` | Procedure | Grant RBAC on all users |
| `KEY_INVENTORY` | Table | Materialized inventory |
| `AUDIT_LOG` | Table | Immutable audit (before/after state, reason codes) |
| `ROTATION_POLICIES` | Table | Per-user rotation cadence |
| `APP_CONFIG` | Table | Externalized config (editable from UI) |
| `V_KEY_HEALTH` | View | Computed health status per key |
| `PRIVATE_KEYS` | Stage | Encrypted private key storage (SSE) |
| `INVENTORY_REFRESH_TASK` | Task | Configurable schedule (default hourly) |
| `EXPIRY_MONITOR_TASK` | Task | Configurable threshold + email |
| `AUTO_GRANT_TASK` | Task | Midnight daily |
| `KEYPAIR_ADMIN` | Role | Full access |
| `KEYPAIR_MANAGER` | Role | Operations |
| `KEYPAIR_VIEWER` | Role | Read-only |
| `KEYPAIR_AUDITOR` | Role | Audit only |
| `keypair_mgmt_notifications` | Integration | Email delivery |

---

## Configuration

| Key | Default | Description | Trigger on Change |
|-----|---------|-------------|-------------------|
| `MIN_KEY_SIZE` | 4096 | Minimum RSA bits | Runtime enforcement |
| `DEFAULT_EXPIRY_DAYS` | 90 | Default expiration | Runtime (form default) |
| `ALERT_THRESHOLD_DAYS` | 14 | Days before expiry to alert | Recreates EXPIRY_MONITOR_TASK |
| `NOTIFY_EMAIL` | xxxx@gmail.com | Alert recipient | Recreates EXPIRY_MONITOR_TASK |
| `ROTATION_GRACE_HOURS` | 24 | Grace period for old key | Runtime |
| `INVENTORY_REFRESH_MINUTES` | 60 | Refresh interval | Recreates INVENTORY_REFRESH_TASK |
| `AUTO_CLEANUP_ROTATED` | TRUE | Auto-remove rotated keys | Runtime (rotation checkbox) |
| `REQUIRE_ROLE_RESTRICTION` | TRUE | Block unrestricted keys | Runtime enforcement |
| `SERVICE_USER_PREFIX` | SVC_ | Username prefix filter for service accounts | Runtime (all dropdowns) |
| `ENVIRONMENT` | PROD | Deployment environment | Informational |

---

## Security Design

- **No inline DDL** — all mutations via stored procedures
- **Error propagation** — no EXCEPTION handlers in SQL; errors propagate to Python for structured user-facing messages (Title + Reason + Remedy)
- **Immutable audit** — before/after state, reason codes, session ID, executed_by/role
- **Real user attribution** — `SYSTEM$WHO_AM_I()` captures actual human user (not Streamlit platform service user) for accurate audit trail
- **Input validation** — identifiers validated server-side and client-side
- **Policy enforcement** — config-driven (min key size, require role restriction)
- **Private keys never stored in app** — generated in-memory, downloaded immediately
- **Role-gated UI** — pages hidden based on session role
- **Smart dropdowns** — system roles (ACCOUNTADMIN, ORGADMIN, SECURITYADMIN, SYSADMIN) excluded from role restriction; role dropdown is per-user (only shows roles granted to selected user via `SHOW GRANTS TO USER`)
- **Filtered user lists** — Rotate/Disable only show users who actually have keys
- **Reason codes** — required on every operation
- **4-tier RBAC** — least privilege by default
- **Reactive config** — task recreation on config change (no stale settings)
- **Per-task management** — individual suspend/resume/edit schedule/run now (no bulk operations)

---

## Automated Tasks Explained

| Task | Schedule | What It Does |
|------|----------|-------------|
| **INVENTORY_REFRESH_TASK** | Configurable (default hourly) | Scans all users with key-pair auth, rebuilds KEY_INVENTORY table. Dashboard reads from this for instant loads. |
| **EXPIRY_MONITOR_TASK** | 8am Mon-Fri | Scans all keys, emails a consolidated alert for any expiring within threshold days (both configurable via APP_CONFIG). |
| **AUTO_GRANT_TASK** | Midnight daily | Snowflake has no `GRANT ON ALL FUTURE USERS`. This task grants `MODIFY PROGRAMMATIC AUTHENTICATION METHODS` on every user — ensuring new users are automatically covered. GRANT is idempotent. |

---

## License

MIT — see [LICENSE](LICENSE)

**Built for Snowflake 2026+ | Named Key Pairs GA (July 2026)**
