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

    return None
