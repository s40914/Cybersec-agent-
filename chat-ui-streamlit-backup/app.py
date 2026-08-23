import os
import uuid

import requests
import streamlit as st

ORCHESTRATOR_URL = os.getenv("ORCHESTRATOR_URL", "http://orchestrator:8010")
REQUEST_TIMEOUT = float(os.getenv("REQUEST_TIMEOUT", "180"))

st.set_page_config(page_title="Cybersec Agent", page_icon="🛡️", layout="centered")
st.title("🛡️ Cybersec Agent")
st.caption("Agent diagnostyki bezpieczeństwa serwera - firewall, fail2ban, wazuh, suricata, nmap")

if "thread_id" not in st.session_state:
    st.session_state.thread_id = str(uuid.uuid4())

if "messages" not in st.session_state:
    st.session_state.messages = []

# Wyświetl historię rozmowy
for msg in st.session_state.messages:
    with st.chat_message(msg["role"]):
        st.markdown(msg["content"])

# Panel boczny - nowa rozmowa
with st.sidebar:
    st.subheader("Sesja")
    st.text(f"thread_id: {st.session_state.thread_id[:8]}...")
    if st.button("🔄 Nowa rozmowa"):
        st.session_state.thread_id = str(uuid.uuid4())
        st.session_state.messages = []
        st.rerun()

    st.subheader("Przykładowe polecenia")
    st.markdown(
        "- sprawdź firewall i fail2ban\n"
        "- czy wazuh i suricata działają?\n"
        "- zrób pełny audyt bezpieczeństwa\n"
        "- przeprowadź skan nmap na localhost\n"
    )

prompt = st.chat_input("Zadaj pytanie o bezpieczeństwo serwera...")

if prompt:
    st.session_state.messages.append({"role": "user", "content": prompt})
    with st.chat_message("user"):
        st.markdown(prompt)

    with st.chat_message("assistant"):
        placeholder = st.empty()
        placeholder.markdown("⏳ Wywołuję narzędzia diagnostyczne...")
        try:
            resp = requests.post(
                f"{ORCHESTRATOR_URL}/chat",
                json={"message": prompt, "thread_id": st.session_state.thread_id},
                timeout=900.0,
            )
            resp.raise_for_status()
            answer = resp.json()["response"]
        except Exception as e:
            answer = f"⚠️ Błąd komunikacji z orchestratorem: {e}"

        placeholder.markdown(answer)
        st.session_state.messages.append({"role": "assistant", "content": answer})
