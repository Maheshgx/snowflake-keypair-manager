# Admin page (RBAC, tasks, config)
import streamlit as st
import pandas as pd
from app_pages.services import get_session, get_conn, get_all_users, validate_identifier, format_error

st.title("Administration")
st.caption("RBAC, task management, and configuration")

session = get_session()
conn = get_conn()

tab1, tab2, tab3 = st.tabs([":material/admin_panel_settings: RBAC", ":material/schedule: Tasks", ":material/settings: Config"])

with tab1:
    st.subheader("Role hierarchy")
    st.code("""ACCOUNTADMIN
  └── SECURITYADMIN
        └── KEYPAIR_ADMIN (full lifecycle + grants + admin page)
              ├── KEYPAIR_MANAGER (register, rotate, disable — no admin)
              │     └── KEYPAIR_VIEWER (read-only dashboard + inventory)
              └── KEYPAIR_AUDITOR (audit log access only)""", language="text")

    st.subheader("Auto-grant status")
    st.caption(
        "**What is auto-grant?** Snowflake requires `MODIFY PROGRAMMATIC AUTHENTICATION METHODS` "
        "granted per-user before you can manage their key pairs. Since there's no "
        "`GRANT ON ALL FUTURE USERS`, a daily task runs at midnight to grant this privilege "
        "on every user in the account — ensuring new users are automatically covered."
    )
    try:
        task_df = pd.DataFrame(session.sql("SHOW TASKS LIKE '%AUTO_GRANT%' IN SCHEMA SECURITY_OPS.KEYPAIR_MGMT").collect())
        if not task_df.empty and "state" in task_df.columns:
            state = task_df["state"].iloc[0]
            if state.upper() == "STARTED":
                st.success("Auto-grant task is **active** — runs midnight daily", icon=":material/check_circle:")
            else:
                st.warning(f"Auto-grant task state: **{state}**. Resume it to cover new users.", icon=":material/warning:")
                if st.button("Resume auto-grant task", icon=":material/play_arrow:"):
                    session.sql("ALTER TASK SECURITY_OPS.KEYPAIR_MGMT.AUTO_GRANT_TASK RESUME").collect()
                    st.rerun()
    except Exception:
        st.error("Could not check task status", icon=":material/error:")

    if st.button("Run auto-grant now (manual trigger)", icon=":material/play_arrow:", key="run_ag"):
        with st.spinner("Granting on all users..."):
            try:
                r = session.sql("CALL SECURITY_OPS.KEYPAIR_MGMT.AUTO_GRANT_KEYPAIR_ADMIN()").collect()
                st.success(r[0][0], icon=":material/check_circle:")
            except Exception as e:
                st.error(f"Failed: {e}", icon=":material/error:")

with tab2:
    st.subheader("Scheduled tasks")
    st.caption("Manage each task individually — edit schedule, suspend, resume, or trigger manually.")

    try:
        tasks = pd.DataFrame(session.sql("SHOW TASKS IN SCHEMA SECURITY_OPS.KEYPAIR_MGMT").collect())
    except Exception as e:
        tasks = pd.DataFrame()
        st.error(f"Failed to load tasks: {e}", icon=":material/error:")

    task_info = {
        "INVENTORY_REFRESH_TASK": "Rebuilds KEY_INVENTORY table by scanning all users. Dashboard reads from this for fast load.",
        "EXPIRY_MONITOR_TASK": "Sends email alert for keys expiring within configured threshold.",
        "AUTO_GRANT_TASK": "Grants MODIFY PROGRAMMATIC AUTHENTICATION METHODS on all users to KEYPAIR_ADMIN.",
    }

    if not tasks.empty:
        for idx, row in tasks.iterrows():
            name = row.get("name", "")
            state = row.get("state", "UNKNOWN").upper()
            schedule = row.get("schedule", "N/A")
            desc = task_info.get(name, row.get("comment", ""))

            with st.expander(f"{'🟢' if state == 'STARTED' else '🔴'} **{name}** — {state}", expanded=False):
                st.caption(desc)
                st.markdown(f"**Current schedule:** `{schedule}`")
                st.markdown(f"**State:** `{state}`")

                # Edit schedule
                new_schedule = st.text_input(
                    "New schedule (CRON)", value=schedule.replace("USING CRON ", "") if "CRON" in str(schedule) else "",
                    key=f"sched_{name}", placeholder="e.g. 0 */1 * * * America/New_York"
                )

                c1, c2, c3 = st.columns(3)
                with c1:
                    if state == "STARTED":
                        if st.button("Suspend", key=f"sus_{name}", icon=":material/pause:", use_container_width=True):
                            try:
                                session.sql(f"ALTER TASK SECURITY_OPS.KEYPAIR_MGMT.{name} SUSPEND").collect()
                                st.success(f"{name} suspended", icon=":material/check_circle:")
                                st.rerun()
                            except Exception as e:
                                st.error(f"Failed: {e}", icon=":material/error:")
                    else:
                        if st.button("Resume", key=f"res_{name}", icon=":material/play_arrow:", use_container_width=True):
                            try:
                                session.sql(f"ALTER TASK SECURITY_OPS.KEYPAIR_MGMT.{name} RESUME").collect()
                                st.success(f"{name} resumed", icon=":material/check_circle:")
                                st.rerun()
                            except Exception as e:
                                st.error(f"Failed: {e}", icon=":material/error:")
                with c2:
                    if st.button("Save schedule", key=f"save_{name}", icon=":material/save:", use_container_width=True, type="primary"):
                        if new_schedule.strip():
                            try:
                                session.sql(f"ALTER TASK SECURITY_OPS.KEYPAIR_MGMT.{name} SUSPEND").collect()
                                session.sql(f"ALTER TASK SECURITY_OPS.KEYPAIR_MGMT.{name} SET SCHEDULE = 'USING CRON {new_schedule.strip()}'").collect()
                                session.sql(f"ALTER TASK SECURITY_OPS.KEYPAIR_MGMT.{name} RESUME").collect()
                                st.success(f"Schedule updated to `{new_schedule.strip()}`", icon=":material/check_circle:")
                                st.rerun()
                            except Exception as e:
                                st.error(f"Failed: {e}", icon=":material/error:")
                        else:
                            st.warning("Enter a CRON expression first", icon=":material/warning:")
                with c3:
                    if st.button("Run now", key=f"run_{name}", icon=":material/play_circle:", use_container_width=True):
                        with st.spinner(f"Running {name}..."):
                            try:
                                if "INVENTORY" in name:
                                    r = session.sql("CALL SECURITY_OPS.KEYPAIR_MGMT.REFRESH_INVENTORY()").collect()
                                elif "EXPIRY" in name:
                                    threshold = conn.query("SELECT config_value FROM SECURITY_OPS.KEYPAIR_MGMT.APP_CONFIG WHERE config_key='ALERT_THRESHOLD_DAYS'").iloc[0][0]
                                    email = conn.query("SELECT config_value FROM SECURITY_OPS.KEYPAIR_MGMT.APP_CONFIG WHERE config_key='NOTIFY_EMAIL'").iloc[0][0]
                                    r = session.sql(f"CALL SECURITY_OPS.KEYPAIR_MGMT.CHECK_KEY_EXPIRY({threshold}, '{email}')").collect()
                                elif "AUTO_GRANT" in name:
                                    r = session.sql("CALL SECURITY_OPS.KEYPAIR_MGMT.AUTO_GRANT_KEYPAIR_ADMIN()").collect()
                                else:
                                    r = [["Task executed"]]
                                st.success(r[0][0], icon=":material/check_circle:")
                            except Exception as e:
                                st.error(f"Failed: {e}", icon=":material/error:")

with tab3:
    st.subheader("Application configuration")
    st.caption("Edit individual settings and save. Changes that impact tasks will auto-trigger task recreation.")

    # Check current role for elevated operations
    current_role = st.session_state.get("current_role", "")
    TASK_CAPABLE_ROLES = {"ACCOUNTADMIN", "SECURITYADMIN", "KEYPAIR_ADMIN"}
    has_task_privileges = current_role in TASK_CAPABLE_ROLES

    if not has_task_privileges:
        st.warning(
            f"Current role **{current_role}** may not have CREATE TASK privileges. "
            f"Task-impacting config changes require **ACCOUNTADMIN** or **KEYPAIR_ADMIN**. "
            f"Use the role switcher in the sidebar to switch.",
            icon=":material/shield:"
        )

    try:
        config_df = conn.query("SELECT config_key, config_value, description FROM SECURITY_OPS.KEYPAIR_MGMT.APP_CONFIG ORDER BY config_key")
    except Exception as e:
        config_df = pd.DataFrame()
        st.error(f"Could not load config: {e}", icon=":material/error:")

    if not config_df.empty:
        for idx, row in config_df.iterrows():
            key = row["CONFIG_KEY"]
            val = row["CONFIG_VALUE"]
            desc = row.get("DESCRIPTION", "")

            with st.expander(f"**{key}** = `{val}`", expanded=False):
                st.caption(desc if desc else f"Configuration setting: {key}")

                # Call out elevated role requirement for task-impacting configs
                TASK_IMPACTING = {"ALERT_THRESHOLD_DAYS", "NOTIFY_EMAIL", "INVENTORY_REFRESH_MINUTES"}
                if key in TASK_IMPACTING:
                    st.caption(f":material/shield: Saving this will recreate a task. Requires **ACCOUNTADMIN** or **KEYPAIR_ADMIN** role.")

                # Determine input type
                if key in ("REQUIRE_ROLE_RESTRICTION", "AUTO_CLEANUP_ROTATED"):
                    new_val = st.selectbox("Value", ["TRUE", "FALSE"],
                                           index=0 if val.upper() == "TRUE" else 1,
                                           key=f"cfg_{key}")
                elif key == "MIN_KEY_SIZE":
                    new_val = st.selectbox("Value (NIST SP 800-131A)", ["2048", "4096"],
                                           index=0 if val == "2048" else 1,
                                           key=f"cfg_{key}")
                elif key in ("ALERT_THRESHOLD_DAYS", "DEFAULT_EXPIRY_DAYS", "INVENTORY_REFRESH_MINUTES"):
                    new_val = str(st.number_input("Value", value=int(val) if val.isdigit() else 0,
                                                  min_value=1, key=f"cfg_{key}"))
                elif key == "NOTIFY_EMAIL":
                    new_val = st.text_input("Value", value=val, key=f"cfg_{key}")
                    st.info("Email must be registered and verified in Snowflake via notification integration.", icon=":material/mail:")
                else:
                    new_val = st.text_input("Value", value=val, key=f"cfg_{key}")

                if st.button("Save", key=f"save_cfg_{key}", type="primary", icon=":material/save:", use_container_width=True):
                    if new_val != val:
                        try:
                            session.sql(
                                f"UPDATE SECURITY_OPS.KEYPAIR_MGMT.APP_CONFIG "
                                f"SET config_value = '{new_val}', updated_at = CURRENT_TIMESTAMP() "
                                f"WHERE config_key = '{key}'"
                            ).collect()
                            st.success(f"**{key}** updated: `{val}` → `{new_val}`", icon=":material/check_circle:")

                            # Auto-trigger impacted tasks (only for task-related configs)
                            if key in ("ALERT_THRESHOLD_DAYS", "NOTIFY_EMAIL"):
                                threshold = new_val if key == "ALERT_THRESHOLD_DAYS" else conn.query(
                                    "SELECT config_value FROM SECURITY_OPS.KEYPAIR_MGMT.APP_CONFIG WHERE config_key='ALERT_THRESHOLD_DAYS'"
                                ).iloc[0][0]
                                email = new_val if key == "NOTIFY_EMAIL" else conn.query(
                                    "SELECT config_value FROM SECURITY_OPS.KEYPAIR_MGMT.APP_CONFIG WHERE config_key='NOTIFY_EMAIL'"
                                ).iloc[0][0]
                                session.sql("ALTER TASK SECURITY_OPS.KEYPAIR_MGMT.EXPIRY_MONITOR_TASK SUSPEND").collect()
                                session.sql(f"""CREATE OR REPLACE TASK SECURITY_OPS.KEYPAIR_MGMT.EXPIRY_MONITOR_TASK
  WAREHOUSE = COMPUTE_WH
  SCHEDULE = 'USING CRON 0 8 * * MON-FRI America/New_York'
  COMMENT = 'Expiry check: {threshold}d threshold, notify {email}'
AS
  CALL SECURITY_OPS.KEYPAIR_MGMT.CHECK_KEY_EXPIRY({threshold}, '{email}')""").collect()
                                session.sql("ALTER TASK SECURITY_OPS.KEYPAIR_MGMT.EXPIRY_MONITOR_TASK RESUME").collect()
                                st.info(f"EXPIRY_MONITOR_TASK recreated (threshold={threshold}d, email={email})", icon=":material/autorenew:")

                            elif key == "INVENTORY_REFRESH_MINUTES":
                                mins = int(new_val)
                                cron = f"*/{mins} * * * *" if mins < 60 else f"0 */{mins // 60} * * *"
                                session.sql("ALTER TASK SECURITY_OPS.KEYPAIR_MGMT.INVENTORY_REFRESH_TASK SUSPEND").collect()
                                session.sql(f"""CREATE OR REPLACE TASK SECURITY_OPS.KEYPAIR_MGMT.INVENTORY_REFRESH_TASK
  WAREHOUSE = COMPUTE_WH
  SCHEDULE = 'USING CRON {cron} America/New_York'
  COMMENT = 'Inventory refresh every {mins} minutes'
AS
  CALL SECURITY_OPS.KEYPAIR_MGMT.REFRESH_INVENTORY()""").collect()
                                session.sql("ALTER TASK SECURITY_OPS.KEYPAIR_MGMT.INVENTORY_REFRESH_TASK RESUME").collect()
                                st.info(f"INVENTORY_REFRESH_TASK recreated (every {mins} min)", icon=":material/autorenew:")

                            else:
                                st.caption("Applied at runtime — no task restart needed.")

                            st.rerun()
                        except Exception as e:
                            st.error(f"Save failed: {e}", icon=":material/error:")
                    else:
                        st.info("No change detected.", icon=":material/info:")
