import streamlit as st
from pages.api_client import send_prompt

def render():
    st.title("🔍 Transparency Viewer")
    st.caption("Submit any prompt and see the full protection pipeline breakdown.")

    prompt  = st.text_area("Prompt to analyze:", height=120)
    user_id = st.text_input("User ID:", value="transparency_test")

    if st.button("🔬 Analyze", type="primary"):
        if prompt:
            with st.spinner("Running through all 12 layers..."):
                result = send_prompt(prompt, user_id)

            report = result.get("protection_report", {})

            st.subheader("🧭 Pipeline Decision Flow")
            steps = [
                ("Auth Layer",           "✅ Passed",  not report.get("blocked")),
                ("Entropy Engine",       f"Cost Score: {report.get('cost_score', 0)}", True),
                ("Risk Analysis",        f"Flags: {report.get('risk_flags', [])}", True),
                ("Amplification",        f"Recursive: {report.get('recursive_detected')}", True),
                ("Reputation",           f"Trust: {report.get('trust_score', 0)}", True),
                ("Token Budget",         f"Allocated: {report.get('tokens_allocated', 0)}", True),
                ("Twin AI Defender",     f"Risk: {report.get('defender_risk', 0)}", True),
                ("Final Decision",       "🔴 BLOCKED" if report.get("blocked") else "🟢 ALLOWED",
                                         not report.get("blocked")),
            ]

            for step_name, value, passed in steps:
                icon = "✅" if passed else "🔴"
                st.markdown(f"{icon} **{step_name}** → {value}")

            st.divider()
            st.subheader("📄 Full Protection Report")
            st.json(report)

            if result.get("response"):
                st.subheader("💬 LLM Response")
                st.write(result["response"])
