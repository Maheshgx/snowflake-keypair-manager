# Disable / Remove page
import streamlit as st
from app_pages.services import get_user_list, get_key_pairs_for_user, validate_identifier, call_proc, get_key_inventory, format_error

st.title("Disable or remove keys")
st.caption("Incident response and decommissioning")

# Only show users who have key pairs
inventory = get_key_inventory()
if not inventory.empty and "USER_NAME" in inventory.columns:
    users_with_keys = sorted(inventory["USER_NAME"].unique().tolist())
else:
    users_with_keys = []

mgmt_user = st.selectbox("Select user", [""] + users_with_keys, key="mgmt_user")

user_keys = []
if mgmt_user:
    clean = validate_identifier(mgmt_user)
    if clean:
        kdf = get_key_pairs_for_user(clean)
        if not kdf.empty and "name" in kdf.columns:
            user_keys = kdf["name"].tolist()
            st.dataframe(kdf[["name", "status", "role_scope", "expires_at"]], use_container_width=True, hide_index=True)

tab1, tab2, tab3 = st.tabs([":material/block: Disable", ":material/check_circle: Enable", ":material/delete: Remove"])

with tab1:
    st.caption("Instant revocation — reversible")
    dk = st.selectbox("Key to disable", [""] + user_keys, key="dis_sel")
    reason = st.selectbox("Reason", ["INCIDENT_RESPONSE", "COMPLIANCE", "POLICY", "MANUAL"], key="dis_reason")
    if st.button("Disable", type="primary", icon=":material/block:"):
        cu, ck = validate_identifier(mgmt_user), validate_identifier(dk)
        if cu and ck:
            r = call_proc("SP_MODIFY_KEY", cu, ck, "DISABLE", reason)
            if r.get("success"):
                st.success(r["message"], icon=":material/check_circle:")
                get_key_inventory.clear()
            else:
                st.error(format_error(r), icon=":material/error:")

with tab2:
    st.caption("Re-enable a disabled key")
    ek = st.selectbox("Key to enable", [""] + user_keys, key="en_sel")
    if st.button("Enable", type="primary", icon=":material/check_circle:"):
        cu, ck = validate_identifier(mgmt_user), validate_identifier(ek)
        if cu and ck:
            r = call_proc("SP_MODIFY_KEY", cu, ck, "ENABLE", "RE_ENABLE")
            if r.get("success"):
                st.success(r["message"], icon=":material/check_circle:")
                get_key_inventory.clear()
            else:
                st.error(format_error(r), icon=":material/error:")

with tab3:
    st.caption("Permanent removal — irreversible")
    rk = st.selectbox("Key to remove", [""] + user_keys, key="rem_sel")
    reason = st.selectbox("Reason", ["DECOMMISSION", "INCIDENT_RESPONSE", "MIGRATION", "CLEANUP"], key="rem_reason")
    if st.button("Remove permanently", type="primary", icon=":material/delete_forever:"):
        cu, ck = validate_identifier(mgmt_user), validate_identifier(rk)
        if cu and ck:
            r = call_proc("SP_MODIFY_KEY", cu, ck, "REMOVE", reason)
            if r.get("success"):
                st.success(r["message"], icon=":material/check_circle:")
                get_key_inventory.clear()
            else:
                st.error(format_error(r), icon=":material/error:")
