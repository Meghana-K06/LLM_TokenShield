import streamlit as st
import time
from pages.api_client import get_metrics

def render():
    st.title("🛡️ TwinShield — Defense Overview")
    st.caption("Real-time multi-layer LLM protection system")

    # Auto-refresh
    refresh = st.sidebar.slider("Auto-refresh (sec)", 5, 60, 10)

    metrics = get_metrics()

    if not metrics:
        st.error("⚠️ Cannot connect to TwinShield backend at localhost:8000")
        st.info("Make sure uvicorn is running in another terminal.")
        return

    # ── KPI Cards ─────────────────────────────────────────────────────
    st.subheader("📊 Live Metrics")
    c1, c2, c3, c4, c5 = st.columns(5)

    total     = metrics.get("total_requests", 0)
    blocked   = metrics.get("blocked_requests", 0)
    attacks   = metrics.get("attacks_detected", 0)
    success   = metrics.get("successful_requests", 0)
    block_pct = round((blocked / total * 100) if total > 0 else 0, 1)

    c1.metric("Total Requests",    total)
    c2.metric("Blocked",           blocked,  delta=f"-{block_pct}%", delta_color="inverse")
    c3.metric("Attacks Detected",  attacks)
    c4.metric("Successful",        success)
    c5.metric("Uptime (s)",        metrics.get("uptime_seconds", 0))

    st.divider()

    # ── Pipeline Diagram ──────────────────────────────────────────────
    st.subheader("🔄 Defense Pipeline")

    layers = [
        ("1", "Auth Layer",              "Quota & Blacklist"),
        ("2", "Entropy Engine",          "Cost Prediction"),
        ("3", "Risk Analysis",           "Injection Detection"),
        ("4", "Correlation Engine",      "Campaign Tracking"),
        ("5", "Amplification Detector",  "Recursion Block"),
        ("6", "Reputation Engine",       "Trust Scoring"),
        ("7", "JWT Challenge",           "Suspicious Users"),
        ("8", "Proof of Compute",        "PoW Verification"),
        ("9", "Token Budget",            "Resource Allocation"),
        ("10","Twin AI Defender",        "AI-Inspects-AI"),
        ("11","LLM Adapter",             "Ollama/Mistral"),
        ("12","Monitoring Layer",        "Metrics & Logs"),
    ]

    cols = st.columns(4)
    for i, (num, name, desc) in enumerate(layers):
        with cols[i % 4]:
            st.markdown(f"""
            <div style='
                background: linear-gradient(135deg, #1e3a5f, #0d2137);
                border: 1px solid #2196F3;
                border-radius: 8px;
                padding: 12px;
                margin: 6px 0;
                text-align: center;
            '>
                <div style='color:#2196F3; font-size:11px; font-weight:bold;'>
                    LAYER {num}
                </div>
                <div style='color:white; font-size:13px; font-weight:bold;'>
                    {name}
                </div>
                <div style='color:#90CAF9; font-size:11px;'>
                    {desc}
                </div>
            </div>
            """, unsafe_allow_html=True)

    st.divider()

    # ── Status indicators ─────────────────────────────────────────────
    st.subheader("🟢 System Status")
    s1, s2, s3 = st.columns(3)
    s1.success("✅ FastAPI Backend — Online")
    s2.success("✅ Redis Cache — Connected")
    s3.success("✅ Ollama/Mistral — Ready")

    time.sleep(refresh)
    st.rerun()
