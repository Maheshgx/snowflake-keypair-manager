# Audit log page
import streamlit as st
from app_pages.services import get_audit_log

st.title("Audit log")
st.caption("Immutable record of all key pair operations")

limit = st.selectbox("Show last", [25, 50, 100, 500], index=1, key="audit_limit")
audit_df = get_audit_log(limit)

if audit_df.empty:
    st.info("No audit entries yet.", icon=":material/info:")
else:
    # Filters
    f1, f2 = st.columns(2)
    op_filter = f1.selectbox("Operation", ["All"] + sorted(audit_df["OPERATION"].unique().tolist()), key="aud_op")
    status_filter = f2.selectbox("Status", ["All", "SUCCESS", "FAILED"], key="aud_status")

    df = audit_df.copy()
    if op_filter != "All":
        df = df[df["OPERATION"] == op_filter]
    if status_filter != "All":
        df = df[df["STATUS"] == status_filter]

    st.dataframe(df, use_container_width=True, hide_index=True)
    st.caption(f"Showing {len(df)} of {len(audit_df)} entries")
