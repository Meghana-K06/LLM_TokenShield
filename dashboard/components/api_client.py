import requests
import streamlit as st

BASE_URL = "http://localhost:8000"

def get_metrics() -> dict:
    try:
        r = requests.get(f"{BASE_URL}/metrics", timeout=5)
        r.raise_for_status()
        return r.json()
    except requests.exceptions.ConnectionError:
        st.error("⚠️ Cannot connect to TwinShield backend at localhost:8000")
        return {}
    except Exception as e:
        st.error(f"Metrics error: {e}")
        return {}

def send_prompt(prompt: str, user_id: str = "dashboard_user") -> dict:
    try:
        r = requests.post(
            f"{BASE_URL}/v1/chat",
            json={"prompt": prompt, "user_id": user_id},
            timeout=180
        )
        return r.json()
    except requests.exceptions.ConnectionError:
        st.error("⚠️ Backend not running. Start uvicorn first.")
        return {"error": "connection failed", "protection_report": {}}
    except requests.exceptions.Timeout:
        st.error("⚠️ Request timed out — Ollama may be slow.")
        return {"error": "timeout", "protection_report": {}}
    except Exception as e:
        st.error(f"Request error: {e}")
        return {"error": str(e), "protection_report": {}}

def get_all_reputation() -> list:
    try:
        r = requests.get(f"{BASE_URL}/reputation", timeout=5)
        r.raise_for_status()
        return r.json()
    except Exception:
        return []

def get_campaigns() -> list:
    try:
        r = requests.get(f"{BASE_URL}/campaigns", timeout=5)
        r.raise_for_status()
        return r.json()
    except Exception:
        return []

def blacklist_user(user_id: str) -> bool:
    try:
        r = requests.post(f"{BASE_URL}/blacklist/user/{user_id}", timeout=5)
        return r.status_code == 200
    except Exception:
        return False

def unblacklist_user(user_id: str) -> bool:
    try:
        r = requests.delete(f"{BASE_URL}/blacklist/user/{user_id}", timeout=5)
        return r.status_code == 200
    except Exception:
        return False

def reset_reputation(user_id: str) -> bool:
    try:
        r = requests.delete(f"{BASE_URL}/reputation/{user_id}", timeout=5)
        return r.status_code == 200
    except Exception:
        return False

def get_request_history(limit: int = 50) -> list:
    try:
        r = requests.get(f"{BASE_URL}/requests/history", params={"limit": limit}, timeout=5)
        r.raise_for_status()
        return r.json()
    except Exception:
        return []
