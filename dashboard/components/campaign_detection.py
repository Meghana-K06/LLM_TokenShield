import streamlit as st
import time
from components.api_client import get_campaigns

def render():
    st.title("🔗 Campaign Detection")
    st.caption("Tracks coordinated attacks across users and IPs.")

    refresh = st.sidebar.slider("Auto-refresh (sec)", 5, 60, 15, key="refresh_campaign")

    campaigns = get_campaigns()
    if not campaigns:
        st.success("✅ No active campaigns detected.")
        st.info("Campaigns are triggered when 3+ users send similar prompts within 5 minutes.")
    else:
        st.error(f"⚠️ {len(campaigns)} active campaign(s) detected!")
        for c in campaigns:
            st.json(c)

    time.sleep(refresh)
    st.rerun()
