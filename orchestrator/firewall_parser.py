"""
Deterministyczny parser wyjścia `ufw status verbose` + klasyfikacja ryzyka.

DLACZEGO TO ISTNIEJE:
Modele 8-14B w tym pipeline wielokrotnie gubiły lub błędnie liczyły reguły
firewalla przy transkrypcji surowego tekstu na listę (zwłaszcza reguły bez
"on <interfejs>", warianty IPv6, i rozróżnienie ALLOW/DENY). Zamiast prosić
LLM żeby "policzył i nie pominął żadnej reguły" (zawodne mimo wielu poprawek
promptu), parsujemy `ufw status` w Pythonie - ze 100% powtarzalną poprawnością
- i wstrzykujemy gotową, już sklasyfikowaną tabelę do promptu. LLM dostaje
wtedy zadanie "skomentuj tę gotową tabelę", a nie "przepisz i policz surowy
tekst", co eliminuje całą klasę błędów widzianą w tym projekcie.
"""
import re

_PRIVATE_CIDR_RE = re.compile(
    r"(192\.168\.\d{1,3}\.\d{1,3}/\d{1,2}"
    r"|10\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}"
    r"|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}/\d{1,2})"
)
_INTERFACE_RE = re.compile(r"\bon (\S+)")
_TRUSTED_INTERFACES = {"tailscale0", "docker0"}
# Kotwiczymy na słowach kluczowych ALLOW IN / DENY IN zamiast liczyć spacje -
# szerokość kolumn w `ufw status` jest zmienna (zależy od długości najdłuższego
# wpisu w danych), więc liczba spacji między polami nie jest stała.
_RULE_LINE_RE = re.compile(r"^(.*?)\s+(ALLOW IN|DENY IN)\s+(.*)$")


def parse_ufw_rules(stdout: str) -> list[dict]:
    """Parsuje surowe wyjście `ufw status verbose` na listę reguł.
    Zwraca listę dictów: to, action, from, is_ipv6, interface, risk, risk_reason.
    Pomija linie nagłówkowe/puste - bierze tylko linie z ALLOW IN / DENY IN.
    """
    rules = []
    for raw_line in stdout.split("\n"):
        line = raw_line.strip()
        if not line or ("ALLOW IN" not in line and "DENY IN" not in line):
            continue
        match = _RULE_LINE_RE.match(line)
        if not match:
            continue
        to_field, action_raw, from_field = match.groups()
        to_field = to_field.strip()
        from_field = from_field.strip()

        is_ipv6 = "(v6)" in to_field or "(v6)" in from_field
        iface_match = _INTERFACE_RE.search(to_field)
        interface = iface_match.group(1) if iface_match else None
        action_type = "ALLOW" if action_raw == "ALLOW IN" else "DENY"
        is_private_cidr = bool(_PRIVATE_CIDR_RE.search(from_field))

        if action_type == "DENY":
            risk, reason = "BRAK", "reguła blokuje ruch, nie stanowi ryzyka"
        elif interface in _TRUSTED_INTERFACES:
            risk, reason = "NISKIE", f"ograniczone do interfejsu {interface}"
        elif is_private_cidr:
            risk, reason = "NISKIE", f"ograniczone do sieci prywatnej {from_field}"
        elif action_type == "ALLOW" and from_field.startswith("Anywhere"):
            risk, reason = (
                "WYMAGA WERYFIKACJI NAT",
                "UFW nie ogranicza źródła na tym interfejsie - to oznacza dostępność "
                "z całej sieci lokalnej (LAN). Rzeczywista dostępność z internetu "
                "zależy od konfiguracji NAT/port forwarding na routerze, czego to "
                "narzędzie NIE weryfikuje. Sprawdź ręcznie panel routera lub użyj "
                "zewnętrznego skanera portów (np. canyouseeme.org) z sieci spoza domu."
            )
        else:
            risk, reason = "DO WERYFIKACJI", "nietypowy wzorzec reguły, wymaga ręcznej oceny"

        rules.append({
            "to": to_field,
            "action": action_type,
            "from": from_field,
            "is_ipv6": is_ipv6,
            "interface": interface,
            "risk": risk,
            "risk_reason": reason,
        })
    return rules


def format_firewall_block(rules: list[dict]) -> str:
    """Formatuje listę reguł jako gotowy blok tekstowy do wstrzyknięcia w prompt."""
    if not rules:
        return ""

    total = len(rules)
    ipv4 = [r for r in rules if not r["is_ipv6"]]
    ipv6 = [r for r in rules if r["is_ipv6"]]
    allow = [r for r in rules if r["action"] == "ALLOW"]
    deny = [r for r in rules if r["action"] == "DENY"]
    high_risk = [r for r in rules if r["risk"] in ("WYSOKIE", "WYMAGA WERYFIKACJI NAT")]

    lines = []
    lines.append("### DANE FIREWALLA - PRZETWORZONE AUTOMATYCZNIE (deterministyczny parser, NIE LLM)")
    lines.append("")
    lines.append(
        f"Ten blok zawiera WSZYSTKIE {total} reguł z surowego `ufw status` "
        f"({len(ipv4)} IPv4, {len(ipv6)} IPv6; {len(allow)} ALLOW, {len(deny)} DENY), "
        f"już sparsowane i ocenione pod kątem ryzyka przez deterministyczny kod, nie przez model językowy."
    )
    lines.append(
        "UŻYJ TEJ TABELI JAKO JEDYNEGO ŹRÓDŁA PRAWDY dla sekcji firewalla. "
        "NIE licz ręcznie reguł z surowego stdout, NIE twórz własnej klasyfikacji ryzyka dla "
        "firewalla - ocena poniżej jest już poprawna i kompletna. Twoim zadaniem jest przepisać "
        "tę listę do raportu (możesz dodać kontekst/rekomendacje), zachowując WSZYSTKIE pozycje."
    )
    lines.append("")
    lines.append(f"Liczba referencyjna do weryfikacji: dokładnie {total} reguł musi się znaleźć w finalnym raporcie.")
    lines.append("")
    for i, r in enumerate(rules, start=1):
        v6_tag = " [IPv6]" if r["is_ipv6"] else ""
        lines.append(
            f"{i}. {r['to']} {r['action']} IN {r['from']}{v6_tag} "
            f"-> RYZYKO: {r['risk']} ({r['risk_reason']})"
        )
    lines.append("")
    if high_risk:
        lines.append(f"UWAGA - {len(high_risk)} reguł WYSOKIEGO ryzyka wymaga wyraźnego wypunktowania w raporcie:")
        for r in high_risk:
            lines.append(f"  - {r['to']} {r['action']} IN {r['from']}")
    else:
        lines.append("Brak reguł WYSOKIEGO ryzyka w tych danych.")
    lines.append("### KONIEC DANYCH PRZETWORZONYCH AUTOMATYCZNIE")

    return "\n".join(lines)


def extract_and_format_firewall_block(raw_results: str) -> str:
    """Szuka sekcji firewalla w raw_results (JSON od check_firewall lub full_audit),
    parsuje ją i zwraca gotowy blok tekstowy do doklejenia do raw_results.
    Zwraca pusty string, jeśli nie znaleziono danych firewalla."""
    import json

    for segment in raw_results.split("\n\n"):
        segment = segment.strip()
        if not segment:
            continue
        try:
            obj = json.loads(segment)
        except (json.JSONDecodeError, ValueError):
            continue
        if not isinstance(obj, dict):
            continue

        candidates = []
        if "stdout" in obj:
            candidates.append(obj)
        for v in obj.values():
            if isinstance(v, dict) and "stdout" in v:
                candidates.append(v)

        for c in candidates:
            stdout = c.get("stdout") or ""
            if "ALLOW IN" in stdout or "DENY IN" in stdout:
                rules = parse_ufw_rules(stdout)
                if rules:
                    return format_firewall_block(rules)
    return ""
