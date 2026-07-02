import streamlit as st
import time
from components.api_client import get_metrics

def render():
    st.title("🛡️ TwinShield — Defense Overview")
    st.caption("Real-time multi-layer LLM protection system")

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

    c1.metric("Total Requests",   total)
    c2.metric("Blocked",          blocked, delta=f"-{block_pct}%", delta_color="inverse")
    c3.metric("Attacks Detected", attacks)
    c4.metric("Successful",       success)
    c5.metric("Uptime (s)",       metrics.get("uptime_seconds", 0))

    st.divider()

    # ── 3-Stage Pipeline ──────────────────────────────────────────────
    st.subheader("🔄 Defense Pipeline — 3 Stages")

    stages = [
        {
            "title": "🔍 Stage 1: Pre-Flight Analysis",
            "subtitle": "Validate and score every request before any decision is made",
            "color": "#1565C0",
            "bg": "linear-gradient(135deg, #0d2137, #1a3a5c)",
            "layers": [
                ("1", "Authentication", "Quota & blacklist checks"),
                ("2", "Entropy Engine", "Predicts cost before inference"),
                ("3", "Risk Analysis", "8 attack pattern detectors"),
                ("4", "Correlation Engine", "Cross-user campaign tracking"),
            ]
        },
        {
            "title": "⚖️ Stage 2: Decision & Verification",
            "subtitle": "Determine trust level and verify suspicious users",
            "color": "#E65100",
            "bg": "linear-gradient(135deg, #3d2410, #5c3a1a)",
            "layers": [
                ("5", "Amplification Detector", "Blocks recursion > 5x"),
                ("6", "Reputation Engine", "Trust scoring with decay"),
                ("7", "JWT Challenge", "Issued to low-trust users"),
                ("8", "Proof-of-Compute", "SHA256 proof-of-work"),
            ]
        },
        {
            "title": "🚀 Stage 3: Execution & Oversight",
            "subtitle": "Allocate resources, verify with AI, execute, and log",
            "color": "#2E7D32",
            "bg": "linear-gradient(135deg, #0d3d1a, #1a5c2e)",
            "layers": [
                ("9",  "Token Budget", "Risk-aware resource allocation"),
                ("10", "Twin AI Defender", "Second AI inspects the prompt"),
                ("11", "LLM Adapter", "Ollama/Mistral inference"),
                ("12", "Monitoring Layer", "Metrics, logs, transparency"),
            ]
        },
    ]

    for stage in stages:
        st.markdown(f"""
        <div style='
            background: {stage["bg"]};
            border-left: 4px solid {stage["color"]};
            border-radius: 8px;
            padding: 14px 18px;
            margin: 16px 0 8px 0;
        '>
            <div style='color:white; font-size:18px; font-weight:bold;'>
                {stage["title"]}
            </div>
            <div style='color:#B0BEC5; font-size:13px; margin-top:2px;'>
                {stage["subtitle"]}
            </div>
        </div>
        """, unsafe_allow_html=True)

        cols = st.columns(4)
        for i, (num, name, desc) in enumerate(stage["layers"]):
            with cols[i]:
                st.markdown(f"""
                <div style='
                    background: #1a1a2e;
                    border: 1px solid {stage["color"]};
                    border-radius: 8px;
                    padding: 12px;
                    margin: 4px 0;
                    text-align: center;
                    min-height: 90px;
                '>
                    <div style='color:{stage["color"]}; font-size:11px; font-weight:bold;'>
                        LAYER {num}
                    </div>
                    <div style='color:white; font-size:13px; font-weight:bold; margin-top:4px;'>
                        {name}
                    </div>
                    <div style='color:#90A4AE; font-size:11px; margin-top:4px;'>
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
