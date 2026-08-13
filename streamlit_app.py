# Snowflake Keypair Manager — Enterprise key pair lifecycle management (multi-page entry point)
import streamlit as st
import os

st.set_page_config(
    page_title="Snowflake Keypair Manager",
    page_icon=":material/vpn_key:",
    layout="wide",
)

# Initialize connection (shared across all pages via st.session_state)
conn = st.connection("snowflake", ttl=os.getenv("SNOWFLAKE_CONNECTION_TTL"))
session = conn.session()
st.session_state["conn"] = conn
st.session_state["session"] = session

# Load config from Snowflake
try:
    config_rows = conn.query("SELECT config_key, config_value FROM SECURITY_OPS.KEYPAIR_MGMT.APP_CONFIG")
    st.session_state["config"] = dict(zip(config_rows["CONFIG_KEY"], config_rows["CONFIG_VALUE"]))
except Exception:
    st.session_state["config"] = {}

# Detect current role for RBAC
current_role = session.sql("SELECT CURRENT_ROLE()").collect()[0][0]
st.session_state["current_role"] = current_role

# Capture real human username (Streamlit Container Runtime returns platform user for CURRENT_USER)
try:
    real_user = session.sql("SELECT SYSTEM$WHO_AM_I()::VARIANT:name::STRING").collect()[0][0]
except Exception:
    try:
        real_user = session.sql("SELECT CURRENT_USER()").collect()[0][0]
    except Exception:
        real_user = "UNKNOWN"
st.session_state["real_user"] = real_user

# Define pages based on role permissions
overview_page = st.Page("app_pages/overview.py", title="Overview", icon=":material/dashboard:", default=True)
inventory_page = st.Page("app_pages/inventory.py", title="Inventory", icon=":material/inventory_2:")
register_page = st.Page("app_pages/register.py", title="Register", icon=":material/add_circle:")
rotate_page = st.Page("app_pages/rotate.py", title="Rotate", icon=":material/autorenew:")
disable_page = st.Page("app_pages/disable.py", title="Disable / Remove", icon=":material/block:")
audit_page = st.Page("app_pages/audit.py", title="Audit log", icon=":material/history:")
admin_page = st.Page("app_pages/admin.py", title="Admin", icon=":material/admin_panel_settings:")

# RBAC-gated navigation
ADMIN_ROLES = {"ACCOUNTADMIN", "SECURITYADMIN", "KEYPAIR_ADMIN"}
MANAGER_ROLES = ADMIN_ROLES | {"KEYPAIR_MANAGER"}
VIEWER_ROLES = MANAGER_ROLES | {"KEYPAIR_VIEWER"}
AUDITOR_ROLES = ADMIN_ROLES | {"KEYPAIR_AUDITOR"}

pages = [overview_page, inventory_page]

if current_role in MANAGER_ROLES:
    pages.extend([register_page, rotate_page, disable_page])

if current_role in AUDITOR_ROLES:
    pages.append(audit_page)

if current_role in ADMIN_ROLES:
    pages.append(admin_page)

# Sidebar role info + role switcher
st.sidebar.markdown(f":material/shield_person: **{current_role}**")
if current_role in ADMIN_ROLES:
    st.sidebar.caption(":green-badge[Admin]")
elif current_role in MANAGER_ROLES:
    st.sidebar.caption(":blue-badge[Manager]")
elif current_role in AUDITOR_ROLES:
    st.sidebar.caption(":orange-badge[Auditor]")
else:
    st.sidebar.caption(":red-badge[Viewer]")

# Role toggle
available_roles = ["ACCOUNTADMIN", "KEYPAIR_ADMIN", "KEYPAIR_MANAGER", "KEYPAIR_VIEWER", "KEYPAIR_AUDITOR"]
try:
    roles_result = session.sql("SHOW ROLES").collect()
    import pandas as pd
    rdf = pd.DataFrame(roles_result)
    if "name" in rdf.columns:
        available_roles = sorted(rdf["name"].tolist())
except Exception:
    pass

with st.sidebar.expander(":material/swap_horiz: Switch role"):
    new_role = st.selectbox("Role", available_roles,
                            index=available_roles.index(current_role) if current_role in available_roles else 0,
                            key="role_sel", label_visibility="collapsed")
    if new_role != current_role:
        if st.button(f"Switch to {new_role}", type="primary", use_container_width=True):
            try:
                session.sql(f"USE ROLE {new_role}").collect()
                st.rerun()
            except Exception as e:
                st.error(f"{e}")

pg = st.navigation(pages)
pg.run()
