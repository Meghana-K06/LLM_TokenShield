import streamlit as st
import time
import plotly.graph_objects as go
import plotly.express as px
from components.api_client import get_request_history
from components.api_client import get_metrics

def render():
    st.title("🚨 Threat Monitor")
    refresh = st.sidebar.slider("Auto-refresh (sec)", 5, 60, 10, key="refresh_threat")
    
    metrics = get_metrics()
    if not metrics:
        st.error("Backend not reachable.")
        return

    total   = metrics.get("total_requests", 0)
    blocked = metrics.get("blocked_requests", 0)
    attacks = metrics.get("attacks_detected", 0)
    success = metrics.get("successful_requests", 0)

    # ── Gauge chart ───────────────────────────────────────────────────
    st.subheader("🎯 Threat Level Gauge")
    threat_pct = (blocked / total * 100) if total > 0 else 0

    fig = go.Figure(go.Indicator(
        mode  = "gauge+number+delta",
        value = threat_pct,
        title = {"text": "Threat Level (% Blocked)"},
        delta = {"reference": 20},
        gauge = {
            "axis": {"range": [0, 100]},
            "bar":  {"color": "darkred"},
            "steps": [
                {"range": [0,  30], "color": "green"},
                {"range": [30, 60], "color": "orange"},
                {"range": [60,100], "color": "red"},
            ],
            "threshold": {
                "line":  {"color": "red", "width": 4},
                "thickness": 0.75,
                "value": 80
            }
        }
    ))
    fig.update_layout(height=300, paper_bgcolor="rgba(0,0,0,0)",
                      font_color="white")
    st.plotly_chart(fig, use_container_width=True)

    # ── Bar chart ─────────────────────────────────────────────────────
    st.subheader("📊 Request Breakdown")
    fig2 = px.bar(
        x      = ["Total", "Successful", "Blocked", "Attacks"],
        y      = [total, success, blocked, attacks],
        color  = ["Total", "Successful", "Blocked", "Attacks"],
        color_discrete_map={
            "Total":      "#2196F3",
            "Successful": "#4CAF50",
            "Blocked":    "#FF5252",
            "Attacks":    "#FF9800",
        },
        labels = {"x": "Category", "y": "Count"},
    )
    fig2.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor ="rgba(0,0,0,0)",
        font_color   ="white",
        showlegend   =False
    )
    st.plotly_chart(fig2, use_container_width=True)

    # ── Attack types ──────────────────────────────────────────────────
    st.subheader("🔍 Detection Layers Active")
    layers = {
        "Entropy Engine":           "cost_score > 70 triggers high alert",
        "Risk Analysis":            "8 attack pattern detectors",
        "Amplification Detector":   "blocks multiplier > 5x",
        "Twin AI Defender":         "Mistral-based AI inspection",
        "Correlation Engine":       "cross-user campaign detection",
        "Reputation Engine":        "trust decay + abuse tracking",
    }
    for layer, desc in layers.items():
        st.markdown(f"✅ **{layer}** — {desc}")

    st.divider()
    st.subheader("📜 Recent Attack History")
    history = get_request_history(20)
    blocked_history = [h for h in history if h.get("report", {}).get("blocked")]

    if blocked_history:
        for h in blocked_history[:10]:
            report = h.get("report", {})
            st.error(f"🚫 {report.get('user_id','?')} — {report.get('block_reason','unknown')}")
    else:
        st.success("✅ No attacks in recent history")

    time.sleep(refresh)
    st.rerun()

    if st.button("🔄 Refresh"):
        st.rerun()
