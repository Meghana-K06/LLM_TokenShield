import requests
import streamlit as st

BASE_URL = "http://localhost:8000"

def get_metrics() -> dict:
    try:
        r = requests.get(f"{BASE_URL}/metrics", timeout=3)
        return r.json()
    except Exception:
        return {}

def send_prompt(prompt: str, user_id: str = "dashboard_user") -> dict:
    try:
        r = requests.post(
            f"{BASE_URL}/v1/chat",
            json={"prompt": prompt, "user_id": user_id},
            timeout=120
        )
        return r.json()
    except Exception as e:
        return {"error": str(e)}

def get_reputation(user_id: str) -> dict:
    try:
        r = requests.get(f"{BASE_URL}/reputation/{user_id}", timeout=3)
        return r.json()
    except Exception:
        return {}

def get_campaigns() -> list:
    try:
        r = requests.get(f"{BASE_URL}/campaigns", timeout=3)
        return r.json()
    except Exception:
        return []
