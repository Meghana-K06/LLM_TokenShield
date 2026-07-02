import streamlit as st
import time
from components.api_client import get_metrics

def render():
    st.title("🪙 Token Usage")

    refresh = st.sidebar.slider("Auto-refresh (sec)", 5, 60, 15, key="refresh_token")

    metrics = get_metrics()

    st.subheader("Token Budget Allocation Rules")
    st.markdown("""
    | Risk Level | Base Tokens | With Trust Multiplier |
    |---|---|---|
    | 🟢 Low (score < 30) | 5,000 | Up to 5,000 |
    | 🟡 Medium (30–60) | 2,000 | Up to 2,000 |
    | 🔴 High (> 60) | 500 | Up to 500 |
    """)
    st.subheader("Trust Multipliers")
    st.markdown("""
    | Tier | Multiplier |
    |---|---|
    | Trusted (≥ 0.75) | 1.0x |
    | Authenticated (0.45–0.74) | 0.75x |
    | Anonymous (< 0.45) | 0.5x |
    """)
    st.metric("Total Requests", metrics.get("total_requests", 0))
    st.metric("Successful (tokens used)", metrics.get("successful_requests", 0))

    time.sleep(refresh)
    st.rerun()
