import streamlit as st
from pages.api_client import get_metrics

def render():
    st.title("👤 Reputation Monitor")
    metrics = get_metrics()
    st.metric("Total Requests Tracked", metrics.get("total_requests", 0))
    st.metric("Attacks Detected", metrics.get("attacks_detected", 0))
    st.info("💡 Full per-user reputation scores are tracked in Redis. "
            "Use the Transparency Viewer to inspect individual users.")
    st.subheader("Trust Score Tiers")
    st.markdown("""
    | Tier | Score Range | Token Budget |
    |---|---|---|
    | 🟢 Trusted | 0.75 – 1.0 | 100% allocation |
    | 🟡 Authenticated | 0.45 – 0.74 | 75% allocation |
    | 🔴 Anonymous | 0.0 – 0.44 | 50% allocation |
    """)
