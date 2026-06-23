import streamlit as st
from pages.api_client import get_campaigns

def render():
    st.title("🔗 Campaign Detection")
    st.caption("Tracks coordinated attacks across users and IPs.")
    campaigns = get_campaigns()
    if not campaigns:
        st.success("✅ No active campaigns detected.")
        st.info("Campaigns are triggered when 3+ users send similar prompts within 5 minutes.")
    else:
        st.error(f"⚠️ {len(campaigns)} active campaign(s) detected!")
        for c in campaigns:
            st.json(c)
