# Inventory page
import streamlit as st
import pandas as pd
from app_pages.services import get_user_list, get_key_pairs_for_user, validate_identifier, get_key_inventory

st.title("Key pair inventory")
st.caption("Service accounts (SVC_*) — inspect key pairs via SHOW USER KEY PAIRS")

# Show summary: service users with key status
inventory = get_key_inventory()
all_users = get_user_list()  # Already filtered to SVC_* only
users_with_keys = set(inventory["USER_NAME"].tolist()) if not inventory.empty and "USER_NAME" in inventory.columns else set()

summary_data = []
for u in all_users:
    if u in users_with_keys:
        user_keys = inventory[inventory["USER_NAME"] == u]
        key_count = len(user_keys)
        status = ", ".join(user_keys["HEALTH_STATUS"].unique().tolist()) if "HEALTH_STATUS" in user_keys.columns else "ACTIVE"
        summary_data.append({"USER": u, "KEYS": key_count, "STATUS": status, "HAS_KEYS": "Yes"})
    else:
        summary_data.append({"USER": u, "KEYS": 0, "STATUS": "No keys registered", "HAS_KEYS": "No"})

summary_df = pd.DataFrame(summary_data)

# Filter
f1, f2 = st.columns(2)
filter_choice = f1.selectbox("Filter", ["All users", "With keys", "Without keys"], key="inv_filter")
search = f2.text_input("Search user", placeholder="e.g. SVC_AIRFLOW", key="inv_search")

display_df = summary_df.copy()
if filter_choice == "With keys":
    display_df = display_df[display_df["HAS_KEYS"] == "Yes"]
elif filter_choice == "Without keys":
    display_df = display_df[display_df["HAS_KEYS"] == "No"]
if search:
    display_df = display_df[display_df["USER"].str.contains(search.upper())]

st.dataframe(display_df[["USER", "KEYS", "STATUS"]], use_container_width=True, hide_index=True)
st.caption(f"Showing {len(display_df)} of {len(summary_df)} users ({len(users_with_keys)} with keys, {len(all_users) - len(users_with_keys)} without)")

# Drill-down
st.divider()
selected = st.selectbox("Inspect user (live)", options=[""] + all_users, key="inv_user", placeholder="Choose a user for live details...")

if selected:
    clean = validate_identifier(selected)
    if clean:
        with st.spinner("Loading..."):
            kdf = get_key_pairs_for_user(clean)
            if kdf.empty:
                st.info(f"No key pairs registered for **{clean}**. Use Register to add one.", icon=":material/info:")
            else:
                st.dataframe(kdf, use_container_width=True, hide_index=True)
