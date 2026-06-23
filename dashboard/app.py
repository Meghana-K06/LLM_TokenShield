import streamlit as st

st.set_page_config(
    page_title="TwinShield MXDR",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ── Sidebar ───────────────────────────────────────────────────────────
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
    "🔍 Transparency Viewer",
    "⚔️ Attack Simulator",
])

st.sidebar.divider()
st.sidebar.caption("Backend: http://localhost:8000")

# ── Page routing ──────────────────────────────────────────────────────
if page == "🏠 Overview":
    from pages import overview
    overview.render()
elif page == "📡 Live Requests":
    from pages import live_requests
    live_requests.render()
elif page == "🚨 Threat Monitor":
    from pages import threat_monitor
    threat_monitor.render()
elif page == "👤 Reputation Monitor":
    from pages import reputation_monitor
    reputation_monitor.render()
elif page == "🔗 Campaign Detection":
    from pages import campaign_detection
    campaign_detection.render()
elif page == "🪙 Token Usage":
    from pages import token_usage
    token_usage.render()
elif page == "🔍 Transparency Viewer":
    from pages import transparency_viewer
    transparency_viewer.render()
elif page == "⚔️ Attack Simulator":
    from pages import attack_simulator
    attack_simulator.render()
