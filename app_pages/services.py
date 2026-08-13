# Shared service layer for Snowflake Keypair Manager
import streamlit as st
import pandas as pd
import json
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


def get_conn():
    return st.session_state["conn"]


def get_session():
    return st.session_state["session"]


def get_config(key: str, default: str = "") -> str:
    return st.session_state.get("config", {}).get(key, default)


def validate_identifier(value: str) -> str | None:
    cleaned = value.strip().upper()
    if not cleaned:
        return None
    if not all(c.isalnum() or c == '_' for c in cleaned):
        return None
    return cleaned


def generate_key_pair(key_size: int = 4096) -> tuple[str, str]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    pub_b64 = "".join(l for l in public_pem.splitlines() if "BEGIN" not in l and "END" not in l)
    return private_pem, pub_b64


def get_current_user() -> str:
    """Get the real human username (not Streamlit platform user)."""
    return st.session_state.get("real_user", "UNKNOWN")


def call_proc(proc_name: str, *args) -> dict:
    """Call stored procedure returning VARIANT, parse as dict. Appends real username automatically."""
    session = get_session()
    real_user = get_current_user()
    all_args = list(args) + [real_user]
    params = ", ".join(
        f"'{a}'" if isinstance(a, str) else str(a).upper() if isinstance(a, bool) else str(a)
        for a in all_args
    )
    try:
        result = session.sql(f"CALL SECURITY_OPS.KEYPAIR_MGMT.{proc_name}({params})").collect()
    except Exception as e:
        return {"success": False, "error": str(e), "parsed": parse_error(str(e))}
    raw = result[0][0] if result else "{}"
    if isinstance(raw, str):
        return json.loads(raw)
    return raw


def parse_error(error_msg: str) -> dict:
    """Parse Snowflake error into user-friendly message with reason and remedy."""
    msg = error_msg.upper()

    if "DOES NOT EXIST OR NOT AUTHORIZED" in msg or "DOES NOT EXIST" in msg:
        if "ROLE" in msg and "NOT GRANTED" not in msg:
            return {
                "title": "Role does not exist",
                "reason": "The specified role restriction references a role not created in this account.",
                "remedy": "Create the role first with CREATE ROLE <name>, or select an existing role from the dropdown."
            }
        if "USER" in msg:
            return {
                "title": "User does not exist",
                "reason": "The target user may have been dropped or the name is misspelled.",
                "remedy": "Verify the user exists with SHOW USERS LIKE '<name>' or select from the dropdown."
            }
        return {
            "title": "Object not found or not authorized",
            "reason": "The referenced object doesn't exist or your current role lacks access.",
            "remedy": "Switch to a role with appropriate privileges (KEYPAIR_ADMIN or ACCOUNTADMIN)."
        }

    if "NOT GRANTED TO USER" in msg:
        return {
            "title": "Role not granted to user",
            "reason": "The selected role is not granted to this user. ROLE_RESTRICTION requires the role to be assigned.",
            "remedy": "Grant the role to the user first (GRANT ROLE <role> TO USER <user>), or select a role already assigned to them."
        }

    if "INVALID" in msg and "PUBLIC KEY" in msg:
        return {
            "title": "Invalid public key format",
            "reason": "The public key is not valid base64-encoded DER (PKCS#8/SubjectPublicKeyInfo).",
            "remedy": "Generate a new key pair using the Generate button, or ensure your key is base64 without headers/footers."
        }

    if "ALREADY EXISTS" in msg or "DUPLICATE" in msg:
        return {
            "title": "Key pair already exists",
            "reason": "A key with this name is already registered on this user.",
            "remedy": "Use a different key name, or Rotate the existing key instead of registering a new one."
        }

    if "CANNOT ROTATE" in msg or "ROTATED" in msg:
        return {
            "title": "Key cannot be rotated",
            "reason": "This key has already been rotated (renamed with _ROTATED_ suffix).",
            "remedy": "Select the current active key for rotation, not the old rotated copy."
        }

    if "INSUFFICIENT PRIVILEGES" in msg or "ACCESS CONTROL" in msg or "NOT AUTHORIZED" in msg:
        return {
            "title": "Insufficient privileges",
            "reason": "Your current role does not have permission to perform this operation.",
            "remedy": "Switch to KEYPAIR_ADMIN or ACCOUNTADMIN role using the role switcher in the sidebar."
        }

    if "KEY PAIR" in msg and "NOT FOUND" in msg:
        return {
            "title": "Key pair not found",
            "reason": "The specified key name does not exist on this user — it may have been removed.",
            "remedy": "Refresh the page to reload current keys, or check the Audit log for recent removals."
        }

    if "DISABLED" in msg and "CANNOT" in msg:
        return {
            "title": "Key is already disabled",
            "reason": "The key is currently in DISABLED state.",
            "remedy": "Use the Enable tab to re-enable the key before performing other operations."
        }

    if "TIMEOUT" in msg or "TIMED OUT" in msg:
        return {
            "title": "Operation timed out",
            "reason": "The Snowflake operation took longer than expected.",
            "remedy": "Try again. If persistent, check warehouse status or scale up COMPUTE_WH."
        }

    if "COMPILATION" in msg or "SYNTAX" in msg:
        return {
            "title": "SQL compilation error",
            "reason": "An internal query failed — possible invalid characters in input.",
            "remedy": "Ensure key name uses only alphanumeric characters and underscores (A-Z, 0-9, _)."
        }

    return {
        "title": "Operation failed",
        "reason": error_msg[:200],
        "remedy": "Check the Audit log or Snowflake QUERY_HISTORY for details. Contact your KEYPAIR_ADMIN."
    }


def format_error(result: dict) -> str:
    """Format error result into a multi-line user-friendly message."""
    if "parsed" in result:
        p = result["parsed"]
        return f"**{p['title']}**\n\n**Reason:** {p['reason']}\n\n**Remedy:** {p['remedy']}"
    return result.get("error", "Unknown error")


@st.cache_data(ttl=900)
def get_all_users() -> pd.DataFrame:
    rows = get_session().sql("SHOW USERS").collect()
    return pd.DataFrame(rows) if rows else pd.DataFrame()


@st.cache_data(ttl=300)
def get_key_inventory() -> pd.DataFrame:
    try:
        return get_conn().query("SELECT * FROM SECURITY_OPS.KEYPAIR_MGMT.V_KEY_HEALTH")
    except Exception:
        return pd.DataFrame()


@st.cache_data(ttl=300)
def get_audit_log(limit: int = 50) -> pd.DataFrame:
    try:
        return get_conn().query(
            f"SELECT timestamp, operation, target_user, key_name, executed_by, executed_role, reason_code, status, error_message "
            f"FROM SECURITY_OPS.KEYPAIR_MGMT.AUDIT_LOG ORDER BY timestamp DESC LIMIT {limit}"
        )
    except Exception:
        return pd.DataFrame()


def get_key_pairs_for_user(username: str) -> pd.DataFrame:
    result = get_session().sql(f"SHOW USER KEY PAIRS FOR USER {username}").collect()
    return pd.DataFrame(result) if result else pd.DataFrame()


SERVICE_USER_PREFIX = "SVC_"


def get_service_user_prefix() -> str:
    """Get the service user prefix from config or default."""
    return get_config("SERVICE_USER_PREFIX", SERVICE_USER_PREFIX)


def get_user_list() -> list[str]:
    """Get only service users (matching configured prefix pattern)."""
    df = get_all_users()
    col = "name" if "name" in df.columns else "NAME"
    if col not in df.columns:
        return []
    prefix = get_service_user_prefix()
    all_users = df[col].tolist()
    return sorted([u for u in all_users if u.startswith(prefix)])


SYSTEM_ROLES = {"ORGADMIN", "SECURITYADMIN", "SYSADMIN", "ACCOUNTADMIN"}


@st.cache_data(ttl=900)
def get_available_roles() -> list[str]:
    try:
        rows = get_session().sql("SHOW ROLES").collect()
        df = pd.DataFrame(rows)
        col = "name" if "name" in df.columns else "NAME"
        all_roles = sorted(df[col].tolist()) if col in df.columns else []
        return [r for r in all_roles if r not in SYSTEM_ROLES]
    except Exception:
        return []


def get_roles_for_user(username: str) -> list[str]:
    """Get roles granted to a specific user (excludes system roles)."""
    try:
        rows = get_session().sql(f"SHOW GRANTS TO USER {username}").collect()
        df = pd.DataFrame(rows)
        col = "role" if "role" in df.columns else "ROLE"
        if col in df.columns:
            return sorted([r for r in df[col].tolist() if r not in SYSTEM_ROLES])
        return []
    except Exception:
        return []


def compute_health_score(inventory: pd.DataFrame) -> tuple[int, str]:
    if inventory.empty:
        return 100, "Healthy"
    total = len(inventory)
    issues = 0
    if "HEALTH_STATUS" in inventory.columns:
        issues += len(inventory[inventory["HEALTH_STATUS"] == "EXPIRED"]) * 4
        issues += len(inventory[inventory["HEALTH_STATUS"] == "CRITICAL"]) * 3
        issues += len(inventory[inventory["HEALTH_STATUS"] == "WARNING"]) * 2
        issues += len(inventory[inventory["HEALTH_STATUS"] == "STALE_ROTATED"]) * 2
        issues += len(inventory[inventory["HEALTH_STATUS"] == "DISABLED"]) * 1
        issues += len(inventory[inventory["HEALTH_STATUS"] == "UNSCOPED"]) * 1
    score = max(0, 100 - int((issues / max(total, 1)) * 20))
    label = "Healthy" if score >= 90 else "Warning" if score >= 70 else "Critical"
    return min(100, score), label
