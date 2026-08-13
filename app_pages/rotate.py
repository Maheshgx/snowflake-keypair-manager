# Rotate key pair page
import streamlit as st
from app_pages.services import (
    get_user_list, get_key_pairs_for_user, validate_identifier,
    generate_key_pair, call_proc, get_config, get_key_inventory, format_error
)

st.title("Rotate key pair")
st.caption("Replace public key with auto-cleanup of old rotated keys")

# Only show users who have key pairs
inventory = get_key_inventory()
if not inventory.empty and "USER_NAME" in inventory.columns:
    users_with_keys = sorted(inventory["USER_NAME"].unique().tolist())
else:
    users_with_keys = []

rot_user = st.selectbox("Select user", [""] + users_with_keys, key="rot_user")

existing_keys = []
if rot_user:
    clean = validate_identifier(rot_user)
    if clean:
        kdf = get_key_pairs_for_user(clean)
        if not kdf.empty and "name" in kdf.columns:
            active = kdf[kdf["status"].astype(str).str.upper() == "ACTIVE"]
            rotatable = active[~active["name"].str.contains("_ROTATED_", case=False)]
            existing_keys = rotatable["name"].tolist()
            st.dataframe(kdf[["name", "status", "role_scope", "expires_at"]], use_container_width=True, hide_index=True)
            if not existing_keys and not active.empty:
                st.warning("Only rotated keys remain. Register a new key instead.", icon=":material/warning:")

if not existing_keys and rot_user:
    st.info("No rotatable keys. Register a new key first.", icon=":material/info:")

rot_key = st.selectbox("Key to rotate", existing_keys if len(existing_keys) == 1 else [""] + existing_keys,
                       index=0, key="rot_key")

with st.expander(":material/lock_reset: Generate new key"):
    if st.button("Generate", key="gen_rot", icon=":material/lock_reset:"):
        priv, pub = generate_key_pair(4096)
        st.session_state["rot_priv"] = priv
        st.session_state["rot_pub"] = pub
        st.rerun()

if "rot_priv" in st.session_state:
    st.download_button(":material/download: New private key", data=st.session_state["rot_priv"],
                       file_name="rotated_key.pem", mime="application/x-pem-file", use_container_width=True)

new_pub = st.text_area("New public key (base64)", value=st.session_state.get("rot_pub", ""),
                       height=80, placeholder="e.g. MIIBIjANBgkqhkiG9w... (use Generate above)")
auto_cleanup = st.checkbox("Auto-cleanup rotated keys", value=get_config("AUTO_CLEANUP_ROTATED", "TRUE") == "TRUE")
reason = st.selectbox("Reason", ["SCHEDULED", "POLICY", "INCIDENT_RESPONSE", "COMPLIANCE"], key="rot_reason")

if st.button("Execute rotation", type="primary", icon=":material/autorenew:"):
    cu = validate_identifier(rot_user) if rot_user else None
    ck = validate_identifier(rot_key) if rot_key else None
    pub = new_pub.strip().replace("\n", "").replace(" ", "")

    if not cu or not ck or not pub:
        st.error("User, key, and new public key required.", icon=":material/error:")
    else:
        result = call_proc("SP_ROTATE_KEY", cu, ck, pub, auto_cleanup, reason)
        if result.get("success"):
            st.success(result["message"], icon=":material/check_circle:")
            if auto_cleanup and result.get("cleaned", 0) > 0:
                st.success(f"Cleaned {result['cleaned']} rotated key(s)", icon=":material/cleaning_services:")
            get_key_inventory.clear()
        else:
            st.error(format_error(result), icon=":material/error:")
