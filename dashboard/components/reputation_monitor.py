import streamlit as st
import pandas as pd
import datetime
import time
from components.api_client import get_all_reputation, blacklist_user, unblacklist_user, reset_reputation

TIER_COLORS = {
    "trusted":       "🟢",
    "authenticated": "🟡",
    "anonymous":     "🟠",
    "expired":       "⚪",
    "blacklisted":   "🔴",
}

def render():
    st.title("👤 Reputation Monitor")
    refresh = st.sidebar.slider("Auto-refresh (sec)", 5, 60, 15, key="refresh_reputation")
    
    st.caption("Every user who has sent a prompt through TwinShield, with live trust scores.")

    users = get_all_reputation()

    if not users:
        st.info("No users tracked yet. Send some prompts via Live Requests to populate this list.")
        return

    # ── Summary KPIs ──────────────────────────────────────────────────
    total_users   = len(users)
    blacklisted   = sum(1 for u in users if u.get("is_blacklisted"))
    trusted_count = sum(1 for u in users if u.get("tier") == "trusted")
    avg_trust     = round(sum(u.get("trust_score", 0) for u in users) / total_users, 3) if total_users else 0

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Users",      total_users)
    c2.metric("Trusted Users",    trusted_count)
    c3.metric("Blacklisted",      blacklisted)
    c4.metric("Avg Trust Score",  avg_trust)

    st.divider()

    # ── Tier explanation ─────────────────────────────────────────────
    with st.expander("ℹ️ How tiers and token allocation work"):
        st.markdown("""
        | Tier | Score Range | Token Multiplier | Meaning |
        |---|---|---|---|
        | 🟢 Trusted | 0.75 – 1.0 | 100% of base allocation | Consistently clean requests |
        | 🟡 Authenticated | 0.45 – 0.74 | 75% of base allocation | Normal standing |
        | 🟠 Anonymous | 0.0 – 0.44 | 50% of base allocation | New or flagged users |
        | 🔴 Blacklisted | — | **0 — cannot send prompts** | Manually blocked |
        | ⚪ Expired | — | Resets to default on next request | Reputation data expired (30-day TTL) |

        **Bad reputation directly reduces token budget.** A user with trust 0.3 gets half the
        tokens of a user with trust 0.9 — even for the same risk-level prompt.
        """)

    st.divider()

    # ── User table ────────────────────────────────────────────────────
    st.subheader(f"📋 All Users ({total_users})")

    search = st.text_input("🔍 Filter by user ID:", "")
    filtered = [u for u in users if search.lower() in u["user_id"].lower()] if search else users

    for u in filtered:
        tier = u.get("tier", "anonymous")
        icon = TIER_COLORS.get(tier, "⚪")
        is_bl = u.get("is_blacklisted", False)

        last_seen = u.get("last_seen", 0)
        last_seen_str = (
            datetime.datetime.fromtimestamp(last_seen).strftime("%Y-%m-%d %H:%M")
            if last_seen else "—"
        )

        with st.container(border=True):
            col1, col2, col3, col4, col5, col6 = st.columns([2, 1, 1, 1, 1.2, 1.3])

            col1.markdown(f"**{icon} {u['user_id']}**")
            col2.metric("Trust", u.get("trust_score", 0), label_visibility="collapsed")
            col3.metric("Requests", u.get("total_requests", 0), label_visibility="collapsed")
            col4.metric("Abuses", u.get("abuse_count", 0), label_visibility="collapsed")
            col5.caption(f"Tier: **{tier}**")
            col5.caption(f"Last seen: {last_seen_str}")

            with col6:
                if is_bl:
                    if st.button("✅ Unblock", key=f"unbl_{u['user_id']}", use_container_width=True):
                        if unblacklist_user(u["user_id"]):
                            st.success(f"Unblocked {u['user_id']}")
                            st.rerun()
                else:
                    if st.button("🚫 Blacklist", key=f"bl_{u['user_id']}", use_container_width=True):
                        if blacklist_user(u["user_id"]):
                            st.success(f"Blacklisted {u['user_id']}")
                            st.rerun()

                if st.button("🔄 Reset", key=f"reset_{u['user_id']}", use_container_width=True):
                    if reset_reputation(u["user_id"]):
                        st.info(f"Reset reputation for {u['user_id']}")
                        st.rerun()

    st.divider()

    # ── Manual blacklist by ID ───────────────────────────────────────
    st.subheader("➕ Manually Blacklist a User ID")
    col1, col2 = st.columns([3, 1])
    with col1:
        manual_id = st.text_input("Enter user_id to blacklist directly:", key="manual_bl_input")
    with col2:
        st.markdown("####")
        if st.button("🚫 Blacklist User", type="primary"):
            if manual_id.strip():
                if blacklist_user(manual_id.strip()):
                    st.success(f"✅ {manual_id} blacklisted. They can no longer send prompts.")
                    st.rerun()
            else:
                st.warning("Enter a user_id first.")

    time.sleep(refresh)
    st.rerun()
