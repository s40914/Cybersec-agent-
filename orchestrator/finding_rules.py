from __future__ import annotations
import re

from finding_builder import FindingBuilder
from security_models import RawResult


def process_finding_rules(
    raw: RawResult,
    evidence,
    builder: FindingBuilder,
):
    """
    Deterministyczne reguły wykrywania Findingów.

    Brak LLM.
    Finding powstaje wyłącznie po spełnieniu jawnej reguły.
    """

    # ------------------------------------------------------------
    # Nmap open ports discovered (Deterministic)
    # ------------------------------------------------------------
    if raw.tool_name in ("nmap_scan_ip", "nmap_stealth_scan", "nmap_vuln_scan"):
        stdout_text = raw.stdout or ""
        if "Nmap scan report" in stdout_text:
            for line_item in stdout_text.splitlines():
                match = re.match(r"^(\d+)/(tcp|udp)\s+open\s+(\S+)", line_item.strip())
                if match:
                    port, proto, service = match.group(1), match.group(2), match.group(3)
                    title = f"Otarty port {port}/{proto} ({service})"
                    description = f"Skaner Nmap wykrył otwarty port {port}/{proto} z uruchomioną usługą: {service} na celu {raw.target}."
                    builder.create_finding(
                        target=raw.target,
                        category="network",
                        title=title,
                        description=description,
                        severity="medium" if port in ("22", "80", "443", "3306") else "low",
                        confidence=0.98,
                        evidence=evidence,
                    )

    stdout = raw.stdout or ""

    # ------------------------------------------------------------
    # DVWA detected by WhatWeb
    # ------------------------------------------------------------
    if (
        raw.tool_name == "whatweb_scan"
        and "DVWA" in stdout
    ):
        return builder.create_finding(
            target=raw.target,
            category="web",
            title="DVWA wykryte",
            description=(
                "WhatWeb wykrył aplikację Damn Vulnerable Web Application (DVWA)."
            ),
            severity="medium",
            confidence=0.95,
            evidence=evidence,
        )

    # ------------------------------------------------------------
    # SQL injection confirmed by sqlmap (Deterministic)
    # ------------------------------------------------------------
    if (
        raw.tool_name == "sqlmap_scan"
        and "sqlmap identified the following injection point(s)" in stdout
    ):
        param_names = []
        for pname, method in re.findall(r"Parameter:\s*(\S+)\s*\((\w+)\)", stdout):
            label = f"{pname} ({method})"
            if label not in param_names:
                param_names.append(label)
        params_str = ", ".join(param_names) if param_names else "nieustalony"
        return builder.create_finding(
            target=raw.target,
            category="web",
            title=f"SQL injection potwierdzone (parametr: {params_str})",
            description=(
                f"sqlmap potwierdził (faktyczne wstrzyknięcie, nie przypuszczenie) "
                f"podatność SQL injection na celu {raw.target}. Podatny parametr: {params_str}."
            ),
            severity="critical",
            confidence=0.98,
            evidence=evidence,
        )

    # ------------------------------------------------------------
    # Working SSH credentials found by hydra (Deterministic)
    # ------------------------------------------------------------
    if raw.tool_name == "hydra_ssh":
        found = re.findall(
            r"\[(\d+)\]\[(\w+)\]\s+host:\s+(\S+)\s+login:\s+(\S+)\s+password:\s+(\S*)",
            stdout,
        )
        for port, proto, host, login, password in found:
            builder.create_finding(
                target=raw.target,
                category="auth",
                title=f"Słabe hasło SSH znalezione (login: {login})",
                description=(
                    f"hydra znalazła działającą parę danych logowania SSH na "
                    f"{host}:{port} - login: {login}, haslo: {password}. "
                    f"Wymagana natychmiastowa zmiana hasla."
                ),
                severity="critical",
                confidence=0.98,
                evidence=evidence,
            )
        if found:
            return None

    # ------------------------------------------------------------
    # SMB null session allowed - enum4linux (Deterministic)
    # ------------------------------------------------------------
    if raw.tool_name == "enum4linux_scan":
        clean_stdout = re.sub(r"\x1b\[[0-9;]*[a-zA-Z]", "", stdout)
        null_session_denied = "doesn't allow session using username" in clean_stdout
        no_workgroup = "Can\'t find workgroup/domain" in clean_stdout
        if not (null_session_denied and no_workgroup):
            shares = re.findall(
                r"Sharename\s+Type\s+Comment\s*\n\s*-+\s+-+\s+-+\s*\n((?:.+\n)+?)\n",
                clean_stdout,
            )
            if shares:
                return builder.create_finding(
                    target=raw.target,
                    category="network",
                    title="SMB null session dozwolona (udziały sieciowe dostępne)",
                    description=(
                        f"enum4linux wykazał, że cel {raw.target} zezwala na "
                        f"sesję SMB bez uwierzytelnienia (null session) i "
                        f"udostępnia widoczne udziały sieciowe. To pozwala "
                        f"atakującemu na enumerację zasobów bez znajomości hasła."
                    ),
                    severity="medium",
                    confidence=0.9,
                    evidence=evidence,
                )

    return None
