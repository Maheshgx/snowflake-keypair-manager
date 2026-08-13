# Register key pair page
import streamlit as st
from app_pages.services import (
    get_user_list, get_key_pairs_for_user, validate_identifier,
    generate_key_pair, call_proc, get_config, get_key_inventory,
    get_available_roles, get_roles_for_user, format_error
)

st.title("Register named key pair")
st.caption("Generate and register with role restriction and expiration")

# Step 1: Generate
with st.expander(":material/key: Generate key pair", expanded="gen_pub" not in st.session_state):
    min_size = int(get_config("MIN_KEY_SIZE", "4096"))
    key_size = st.radio("Key size (bits)", [2048, 4096], index=1 if min_size <= 4096 else 0, horizontal=True)
    if key_size < min_size:
        st.warning(f"Policy requires minimum {min_size}-bit keys.", icon=":material/warning:")
    if st.button("Generate key pair", type="primary", icon=":material/lock_reset:"):
        priv, pub = generate_key_pair(key_size)
        st.session_state["gen_priv"] = priv
        st.session_state["gen_pub"] = pub
        st.rerun()

if "gen_pub" in st.session_state:
    c1, c2 = st.columns(2)
    c1.download_button(":material/download: Private key (.pem)", data=st.session_state["gen_priv"],
                       file_name="service_key.pem", mime="application/x-pem-file", use_container_width=True)
    c2.success("Public key ready", icon=":material/check_circle:")

# Step 2: Register
st.subheader("Register on user")

# Filter users who don't have keys yet
all_users = get_user_list()
users_with_keys = {}
for u in all_users:
    try:
        kdf = get_key_pairs_for_user(u)
        if not kdf.empty and "name" in kdf.columns:
            keys = kdf[~kdf["name"].str.contains("_ROTATED_", case=False)]["name"].tolist()
            if keys:
                users_with_keys[u] = keys
    except Exception:
        pass

users_without = [u for u in all_users if u not in users_with_keys]
show_all = False
if users_with_keys:
    with st.expander(f"{len(users_with_keys)} user(s) already have keys"):
        for u, keys in users_with_keys.items():
            st.caption(f"**{u}** — {', '.join(keys)}")
    show_all = st.checkbox("Show all users", value=False)

user_options = all_users if show_all else users_without

# User selection outside form so role dropdown can be reactive
reg_user = st.selectbox("User", [""] + user_options, key="reg_user")

# Get roles for selected user
user_roles = []
if reg_user:
    clean_user = validate_identifier(reg_user)
    if clean_user:
        user_roles = get_roles_for_user(clean_user)
        if not user_roles:
            st.warning(f"No custom roles granted to {clean_user}. Grant a role first.", icon=":material/warning:")

with st.form("register_form"):
    r1, r2 = st.columns(2)
    with r1:
        key_name = st.text_input("Key name", placeholder="e.g. ETL_PIPELINE_2026Q3")
    with r2:
        required = get_config("REQUIRE_ROLE_RESTRICTION") == "TRUE"
        role_options = [""] + user_roles if not required else user_roles
        role_restriction = st.selectbox("Role restriction (user's roles only)", role_options, key="reg_role",
                                         help="Only roles granted to the selected user are shown")
        days = st.number_input("Days to expiry", 1, 730, int(get_config("DEFAULT_EXPIRY_DAYS", "90")))
        comment = st.text_input("Comment", placeholder="e.g. dbt production deploy key for nightly builds")

    pub_key = st.text_area("Public key (base64)", value=st.session_state.get("gen_pub", ""),
                           height=80, placeholder="e.g. MIIBIjANBgkqhkiG9w... (use Generate above)")
    reason = st.selectbox("Reason", ["NEW_KEY", "REPLACEMENT", "MIGRATION", "COMPLIANCE"])
    submitted = st.form_submit_button("Register", type="primary", icon=":material/add_circle:")

if submitted:
    cu = validate_identifier(reg_user) if reg_user else None
    ck = validate_identifier(key_name) if key_name else None
    pub = pub_key.strip().replace("\n", "").replace(" ", "")

    if not cu:
        st.error("Select a user.", icon=":material/error:")
    elif not ck:
        st.error("Key name required.", icon=":material/error:")
    elif not pub:
        st.error("Public key required.", icon=":material/error:")
    elif get_config("REQUIRE_ROLE_RESTRICTION") == "TRUE" and not role_restriction:
        st.error("Role restriction is required by policy.", icon=":material/error:")
    elif ck in users_with_keys.get(cu, []):
        st.error(f"Key `{ck}` already exists on `{cu}`. Use Rotate.", icon=":material/error:")
    else:
        role_val = validate_identifier(role_restriction) if role_restriction and role_restriction.strip() else ""
        result = call_proc("SP_REGISTER_KEY", cu, ck, pub, role_val or "", days, comment.strip() or "", reason)

        if result.get("success"):
            st.success(result["message"], icon=":material/check_circle:")
            get_key_inventory.clear()
        else:
            st.error(format_error(result), icon=":material/error:")
