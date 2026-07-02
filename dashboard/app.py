import streamlit as st

st.set_page_config(
    page_title="TwinShield MXDR",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.sidebar.image("https://img.icons8.com/color/96/shield.png", width=80)
st.sidebar.title("🛡️ TwinShield")
st.sidebar.caption("Multi-Layer LLM Defense System")
st.sidebar.divider()

page = st.sidebar.radio("Navigation", [
    "🏠 Overview",
    "📡 Live Requests",
    "🚨 Threat Monitor",
    "👤 Reputation Monitor",
    "🔗 Campaign Detection",
    "🪙 Token Usage",
])

st.sidebar.divider()
st.sidebar.caption("Backend: http://localhost:8000/docs")
st.sidebar.caption("Reddis: http://localhost:5540")

if page == "🏠 Overview":
    from components import overview
    overview.render()
elif page == "📡 Live Requests":
    from components import live_requests
    live_requests.render()
elif page == "🚨 Threat Monitor":
    from components import threat_monitor
    threat_monitor.render()
elif page == "👤 Reputation Monitor":
    from components import reputation_monitor
    reputation_monitor.render()
elif page == "🔗 Campaign Detection":
    from components import campaign_detection
    campaign_detection.render()
elif page == "🪙 Token Usage":
    from components import token_usage
    token_usage.render()
