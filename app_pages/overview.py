# Overview dashboard page
import streamlit as st
import pandas as pd
from app_pages.services import get_key_inventory, get_all_users, compute_health_score, get_config, get_service_user_prefix

st.title("Snowflake Keypair Manager")
st.caption("Enterprise key pair lifecycle management for service accounts (SVC_*)")

inventory = get_key_inventory()
all_users_df = get_all_users()
score, label = compute_health_score(inventory)

# Filter to service users only (configurable prefix, default SVC_*)
prefix = get_service_user_prefix()
user_col = "name" if "name" in all_users_df.columns else "NAME"
if user_col in all_users_df.columns:
    all_users = all_users_df[all_users_df[user_col].str.startswith(prefix)]
else:
    all_users = all_users_df

# Health score + metrics
h_col, m1, m2, m3 = st.columns([1.5, 1, 1, 1])
with h_col:
    st.metric("Key health", f"{score}%")
    badge = ":green-badge[Healthy]" if score >= 90 else ":orange-badge[Warning]" if score >= 70 else ":red-badge[Critical]"
    st.caption(badge)
m1.metric("Service users (SVC_*)", len(all_users))
m2.metric("Keys tracked", len(inventory))
m3.metric("Active keys", len(inventory[inventory["HEALTH_STATUS"] == "HEALTHY"]) if "HEALTH_STATUS" in inventory.columns else 0)

# Split view: Service users with keys vs without keys
all_user_names = set(all_users[user_col].tolist()) if user_col in all_users.columns else set()
users_with_keys = set(inventory["USER_NAME"].tolist()) if not inventory.empty and "USER_NAME" in inventory.columns else set()
users_without_keys = sorted(all_user_names - users_with_keys)

tab_keys, tab_nokeys = st.tabs([f":material/vpn_key: Users with keys ({len(users_with_keys)})",
                                 f":material/person_off: Users without keys ({len(users_without_keys)})"])

with tab_keys:
    if not inventory.empty and "HEALTH_STATUS" in inventory.columns:
        # Status breakdown
        k1, k2, k3, k4 = st.columns(4)
        k1.metric("Healthy", len(inventory[inventory["HEALTH_STATUS"] == "HEALTHY"]))
        k2.metric("Warning", len(inventory[inventory["HEALTH_STATUS"].isin(["WARNING", "UNSCOPED"])]))
        k3.metric("Critical", len(inventory[inventory["HEALTH_STATUS"].isin(["CRITICAL", "EXPIRED"])]))
        k4.metric("Disabled", len(inventory[inventory["HEALTH_STATUS"] == "DISABLED"]))

        # Filterable table
        f1, f2, f3 = st.columns(3)
        search = f1.text_input("Search", placeholder="e.g. SVC_DBT or AIRFLOW_KEY", key="ov_search")
        status_filter = f2.selectbox("Health status", ["All", "HEALTHY", "WARNING", "CRITICAL", "EXPIRED", "DISABLED", "STALE_ROTATED", "UNSCOPED"], key="ov_filter")
        expiry_filter = f3.selectbox("Expiry", ["All", "< 7 days", "< 14 days", "< 30 days"], key="ov_exp")

        df = inventory.copy()
        if search:
            df = df[df.apply(lambda r: search.upper() in str(r).upper(), axis=1)]
        if status_filter != "All":
            df = df[df["HEALTH_STATUS"] == status_filter]
        if expiry_filter != "All" and "DAYS_TO_EXPIRY" in df.columns:
            days = {"< 7 days": 7, "< 14 days": 14, "< 30 days": 30}[expiry_filter]
            df = df[df["DAYS_TO_EXPIRY"].notna() & (df["DAYS_TO_EXPIRY"] < days)]

        show_cols = [c for c in ["USER_NAME", "KEY_NAME", "STATUS", "HEALTH_STATUS", "ROLE_SCOPE", "DAYS_TO_EXPIRY"] if c in df.columns]
        st.dataframe(df[show_cols] if show_cols else df, use_container_width=True, hide_index=True)
    else:
        st.info("No key pairs in inventory. Use **Register** to create your first key.", icon=":material/info:")

with tab_nokeys:
    if users_without_keys:
        st.caption(f"{len(users_without_keys)} user(s) have no named key pairs registered")
        nokey_df = pd.DataFrame({"USER_NAME": users_without_keys})
        st.dataframe(nokey_df, use_container_width=True, hide_index=True)
    else:
        st.success("All users have key pairs registered.", icon=":material/check_circle:")
