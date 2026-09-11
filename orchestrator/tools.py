"""
Narzędzia (tools) wywołujące realne, deterministyczne endpointy admin-agent.

WAŻNE: te funkcje NIE używają LLM - to zwykłe wywołania HTTP.
Dzięki temu wywołanie narzędzia nigdy nie zależy od "nastroju" modelu
(dokładnie to, co szwankowało w AnythingLLM przy modelach 8B).
"""
import json
import os

import httpx

ADMIN_AGENT_URL = os.getenv("ADMIN_AGENT_URL", "http://host.docker.internal:8765")
ADMIN_AGENT_TOKEN = os.getenv("ADMIN_AGENT_TOKEN", "")
HTTP_TIMEOUT = float(os.getenv("ADMIN_AGENT_TIMEOUT", "60"))


def _call_admin_agent(endpoint: str, params: dict | None = None) -> dict:
    headers = {"X-API-Token": ADMIN_AGENT_TOKEN}
    try:
        resp = httpx.get(
            f"{ADMIN_AGENT_URL}/{endpoint}",
            headers=headers,
            params=params or {},
            timeout=HTTP_TIMEOUT,
        )
        resp.raise_for_status()
        return resp.json()
    except httpx.HTTPStatusError as e:
        return {
            "status": "error",
            "message": f"HTTP {e.response.status_code}: {e.response.text}",
        }
    except Exception as e:
        return {"status": "error", "message": f"Błąd połączenia z admin-agent: {e}"}


def make_tools():
    """Zwraca listę narzędzi LangChain gotowych do podpięcia pod agenta."""
    from langchain_core.tools import tool

    @tool
    def check_firewall() -> str:
        """Sprawdza status i reguły firewalla (UFW) na serwerze."""
        return json.dumps(_call_admin_agent("check_firewall"), ensure_ascii=False)

    @tool
    def check_fail2ban() -> str:
        """Sprawdza status fail2ban i statystyki bana IP (jail sshd)."""
        return json.dumps(_call_admin_agent("check_fail2ban"), ensure_ascii=False)

    @tool
    def check_ssh() -> str:
        """Sprawdza konfigurację demona SSH (port, autentykacja, root login)."""
        return json.dumps(_call_admin_agent("check_ssh"), ensure_ascii=False)

    @tool
    def check_recent_alerts() -> str:
        """Sprawdza alarmy Wazuh/Suricata (IDS/IPS) z ostatnich 15 minut - do
        weryfikacji, czy systemy detekcji wykryły podejrzaną aktywność."""
        return json.dumps(_call_admin_agent("check_recent_alerts"), ensure_ascii=False)

    @tool
    def check_local_ports(target: str = "127.0.0.1") -> str:
        """Sprawdza otwarte porty i nasluchujace uslugi NA TYM SERWERZE (localhost) za pomoca
        polecenia `ss` (socket statistics). Parametr target jest IGNOROWANY przez admin-agent
        (endpoint zawsze zwraca dane dla samego hosta) - zachowany w sygnaturze tylko dla
        kompatybilnosci wstecznej. (Nazwa narzedzia do 2026-09 brzmiala 'scan_nmap', co bylo
        mylace - sugerowala skan zdalnego celu, podczas gdy to zawsze lokalny `ss`.)"""
        return json.dumps(_call_admin_agent("scan_ports"), ensure_ascii=False)

    @tool
    def check_updates() -> str:
        """Sprawdza dostępne aktualizacje systemu, w tym aktualizacje bezpieczeństwa."""
        return json.dumps(_call_admin_agent("check_updates"), ensure_ascii=False)

    @tool
    def check_docker() -> str:
        """Zwraca listę działających kontenerów Docker."""
        return json.dumps(_call_admin_agent("check_docker"), ensure_ascii=False)

    @tool
    def list_services() -> str:
        """Zwraca listę usług systemd i ich status (active/inactive)."""
        return json.dumps(_call_admin_agent("list_services"), ensure_ascii=False)

    @tool
    def list_users() -> str:
        """Zwraca listę użytkowników systemowych i członków grupy sudo."""
        return json.dumps(_call_admin_agent("list_users"), ensure_ascii=False)

    @tool
    def check_lynis() -> str:
        """Wykonuje pelny audyt bezpieczenstwa systemu narzedziem Lynis - setki
        testow (kernel, uwierzytelnianie, uslugi, firewall, SSH, hardening,
        malware). Trwa dluzej niz pozostale narzedzia (30-90s). Zwraca ocene
        Hardening Index oraz liste konkretnych ostrzezen i sugestii."""
        return json.dumps(_call_admin_agent("check_lynis"), ensure_ascii=False)

    @tool
    def full_audit() -> str:
        """Wykonuje pełny audyt bezpieczeństwa naraz (firewall, fail2ban, ssh, users,
        updates, docker, services, wazuh, suricata) - jedno wywołanie zamiast wielu osobnych."""
        return json.dumps(_call_admin_agent("full_audit"), ensure_ascii=False)

    return [
        check_firewall,
        check_fail2ban,
        check_ssh,
        check_recent_alerts,
        check_local_ports,
        check_updates,
        check_docker,
        list_services,
        list_users,
        check_lynis,
        full_audit,
    ]
