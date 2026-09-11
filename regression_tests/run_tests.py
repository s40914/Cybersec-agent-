#!/usr/bin/env python3
"""
Silnik testów regresyjnych dla cybersec-agent.

WAŻNA ZASADA PROJEKTOWA: żaden przypadek testowy nie zawiera wartości
"na sztywno" (np. konkretnego portu SSH, liczby aktualizacji, nazwy
użytkownika) - takie wartości są RÓŻNE na każdym serwerze, więc test
oparty o nie działałby tylko u jednej konkretnej osoby.

Zamiast tego każdy przypadek deklaruje ground_truth: skąd pobrać prawdę
(admin_agent lub pentest_agent, jaki endpoint, jakie pole) - a ten skrypt
POBIERA rzeczywistą wartość z serwera TUŻ PRZED testem i porównuje z nią.
Dzięki temu te same pliki YAML działają poprawnie na dowolnym serwerze
z inną konfiguracją.

Uzycie:
    python3 run_tests.py                    # wszystkie przypadki z cases/
    python3 run_tests.py audyt_ssh           # tylko jeden przypadek
"""
import json
import os
import re
import sys
import time
from pathlib import Path

import httpx
import yaml

ORCHESTRATOR_URL = "http://localhost:8010"
ADMIN_AGENT_URL = "http://localhost:8765"
PENTEST_AGENT_URL = "http://localhost:8766"
CASES_DIR = Path(__file__).parent / "cases"
RESULTS_DIR = Path(__file__).parent / "results"
ENV_FILE = Path(__file__).parent.parent / ".env"
POLL_INTERVAL = 2.0


def _load_env_var(name: str) -> str:
    """Wczytuje wartość zmiennej z pliku .env (ADMIN_AGENT_TOKEN /
    PENTEST_AGENT_TOKEN) - nie polegamy na zmiennych środowiskowych
    shella, żeby skrypt działał niezależnie od tego, czy zostały
    wyeksportowane w bieżącej sesji terminala."""
    if not ENV_FILE.exists():
        return ""
    text = ENV_FILE.read_text(encoding="utf-8")
    match = re.search(rf"^{name}=(.*)$", text, re.MULTILINE)
    return match.group(1).strip() if match else ""


ADMIN_AGENT_TOKEN = _load_env_var("ADMIN_AGENT_TOKEN")
PENTEST_AGENT_TOKEN = _load_env_var("PENTEST_AGENT_TOKEN")


def _get_field(data: dict, dotted_path: str):
    """Wyciąga wartość z zagnieżdżonego słownika/listy po ścieżce kropkowej,
    np. 'settings.Port' -> data['settings']['Port'], albo
    'human_users.0.username' -> data['human_users'][0]['username']
    (segmenty bedace cyframi sa traktowane jako indeks listy)."""
    value = data
    for key in dotted_path.split("."):
        if isinstance(value, dict):
            value = value.get(key)
        elif isinstance(value, list):
            if key.isdigit() and int(key) < len(value):
                value = value[int(key)]
            else:
                return None
        else:
            return None
    return value


def fetch_ground_truth(gt: dict) -> dict:
    """Pobiera świeże, rzeczywiste dane z admin_agent lub pentest_agent
    - TUŻ PRZED każdym testem, żeby wzorzec prawdy zawsze odzwierciedlał
    aktualny stan TEGO KONKRETNEGO serwera, niezależnie kto go uruchamia."""
    source = gt["source"]
    endpoint = gt["endpoint"]

    if source == "admin_agent":
        resp = httpx.get(
            f"{ADMIN_AGENT_URL}/{endpoint}",
            headers={"X-API-Token": ADMIN_AGENT_TOKEN},
            timeout=30.0,
        )
        resp.raise_for_status()
        return resp.json()

    if source == "pentest_agent":
        payload = {
            "tool": endpoint,
            "params": gt.get("params", {}),
        }

        # Ground truth może wymagać restricted tool.
        # Nie przechowujemy hasła w YAML - pobieramy je wyłącznie
        # z głównego .env i dodajemy do żądania tutaj, poza promptem/modeliem.
        if endpoint == "nmap_stealth_scan":
            admin_password = _load_env_var("PENTEST_ADMIN_PASSWORD")
            if not admin_password:
                raise RuntimeError(
                    "Brak PENTEST_ADMIN_PASSWORD w głównym .env "
                    "wymaganego do ground_truth restricted tool."
                )

            payload["explicit_authorization"] = True
            payload["admin_password"] = admin_password

        resp = httpx.post(
            f"{PENTEST_AGENT_URL}/run_tool",
            headers={"X-API-Token": PENTEST_AGENT_TOKEN},
            json=payload,
            timeout=gt.get("fetch_timeout", 60.0),
        )
        resp.raise_for_status()
        return resp.json()

    raise ValueError(f"Nieznane źródło ground_truth: {source}")


def _extract_exposed_firewall_ports(ufw_output: str) -> list[str]:
    """Używa firewall_parser.parse_ufw_rules() - tego samego deterministycznego
    parsera co orchestrator - do znalezienia reguł wymagających jawnej oceny
    ryzyka ekspozycji (klasyfikacja WYMAGA WERYFIKACJI NAT lub WYSOKIE).
    Uniwersalne - logika klasyfikacji jest utrzymywana w jednym miejscu
    (firewall_parser.py), bez duplikacji."""
    import sys
    import os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "orchestrator"))
    try:
        from firewall_parser import parse_ufw_rules
        rules = parse_ufw_rules(ufw_output)
        ports = set()
        for r in rules:
            if r["risk"] in ("WYSOKIE", "WYMAGA WERYFIKACJI NAT"):
                match = re.search(r"^(\d+)", r["to"])
                if match:
                    ports.add(match.group(1))
        return sorted(ports, key=int)
    except Exception as e:
        print(f"  ⚠ UWAGA: nie udało się użyć firewall_parser: {e}")
        return []


def _extract_nmap_open_ports(nmap_output: str) -> list[str]:
    """Wyciąga numery otwartych portów z surowego wyjścia nmap (linie w
    formacie 'NNNN/tcp open  nazwa_uslugi'). Odrębne od
    _extract_listening_ports, bo format nmap różni się od `ss -tulpn`."""
    ports = set()
    for line in nmap_output.splitlines():
        match = re.match(r"^(\d+)/(tcp|udp)\s+open", line.strip())
        if match:
            ports.add(match.group(1))
    return sorted(ports, key=int)


def _extract_listening_ports(ss_output: str) -> list[str]:
    """Wyciąga unikalne numery portów nasłuchujących z surowego wyjścia
    `ss -tulpn` (kolumna Local Address:Port, linie LISTEN/UNCONN).
    Uniwersalne - nie zależy od konkretnych numerów portów, więc działa
    identycznie na dowolnym hoście klienta, nie tylko na tym serwerze."""
    ports = set()
    for line in ss_output.splitlines():
        if "LISTEN" not in line and "UNCONN" not in line:
            continue
        parts = line.split()
        if len(parts) < 5:
            continue
        match = re.search(r":(\d+)$", parts[4])
        if match:
            ports.add(match.group(1))
    return sorted(ports, key=int)


def resolve_checks(case: dict) -> tuple[list[str], list[str]]:
    """Zamienia deklaratywne ground_truth.checks na konkretne listy
    must_contain / must_not_contain, pobierając świeże dane z serwera.
    Zwraca (must_contain, must_not_contain) połączone z ewentualnymi
    statycznymi wpisami must_contain/must_not_contain z samego case'a
    (te są dozwolone TYLKO dla wartości, które są takie same niezależnie
    od serwera, np. nazwa aplikacji 'DVWA' zaszyta w obrazie Dockera)."""
    must_contain = list(case.get("must_contain", []))
    must_not_contain = list(case.get("must_not_contain", []))

    gt = case.get("ground_truth")
    if not gt:
        return must_contain, must_not_contain

    try:
        data = fetch_ground_truth(gt)
    except Exception as e:
        raise RuntimeError(f"Nie udało się pobrać ground_truth ({gt['source']}/{gt['endpoint']}): {e}")

    for check in gt.get("checks", []):
        field_path = check["field"]
        value = _get_field(data, field_path)
        if value is None:
            print(f"  ⚠ UWAGA: pole '{field_path}' nie istnieje w odpowiedzi {gt['endpoint']} - pomijam ten check")
            continue
        if check.get("language_variants"):
            variants_map = check["language_variants"]
            value_str = str(value)
            group = variants_map.get(value_str, [value_str])
            if check.get("must_contain"):
                must_contain.append(group)
            if check.get("must_not_contain"):
                must_not_contain.extend(group)
            continue

        if check.get("extract") == "exposed_firewall_ports":
            extracted = _extract_exposed_firewall_ports(str(value))
            if not extracted:
                print(f"  ⚠ UWAGA: brak reguł szerszych niż VPN/lokalna sieć w '{field_path}' - pomijam ten check (serwer może mieć w pełni ograniczoną konfigurację, to nie błąd)")
                continue
            if check.get("must_contain"):
                must_contain.extend(extracted)
            if check.get("must_not_contain"):
                must_not_contain.extend(extracted)
            continue

        if check.get("extract") == "nmap_open_ports":
            extracted = _extract_nmap_open_ports(str(value))
            if not extracted:
                print(f"  ⚠ UWAGA: nmap nie znalazł otwartych portów w '{field_path}' - pomijam ten check")
                continue
            if check.get("must_contain"):
                must_contain.extend(extracted)
            if check.get("must_not_contain"):
                must_not_contain.extend(extracted)
            continue

        if check.get("extract") == "listening_ports":
            extracted = _extract_listening_ports(str(value))
            if not extracted:
                print(f"  ⚠ UWAGA: nie znaleziono żadnych nasłuchujących portów w '{field_path}' - pomijam ten check")
                continue
            if check.get("must_contain"):
                must_contain.extend(extracted)
            if check.get("must_not_contain"):
                must_not_contain.extend(extracted)
            continue

        value_str = str(value)
        if check.get("must_contain"):
            must_contain.append(value_str)
        if check.get("must_not_contain"):
            must_not_contain.append(value_str)

    return must_contain, must_not_contain


def load_cases(filter_name: str | None = None) -> list[dict]:
    cases = []
    for path in sorted(CASES_DIR.glob("*.yaml")):
        if filter_name and path.stem != filter_name:
            continue
        with open(path, "r", encoding="utf-8") as f:
            case = yaml.safe_load(f)
            case["_file"] = path.name
            cases.append(case)
    return cases


def run_case(case: dict) -> dict:
    name = case.get("name", case["_file"])
    prompt = case["prompt"]
    selected_tools = case.get("selected_tools")
    max_duration = case.get("max_duration_seconds", 300)

    print(f"\n{'='*70}\n▶ {name}\n  Prompt: {prompt}")

    try:
        must_contain, must_not_contain = resolve_checks(case)
    except RuntimeError as e:
        return {"name": name, "status": "ERROR", "detail": str(e)}

    print(f"  Ground truth - MUSI zawierać: {must_contain}")
    if must_not_contain:
        print(f"  Ground truth - NIE MOŻE zawierać: {must_not_contain}")

    start = time.time()
    try:
        resp = httpx.post(
            f"{ORCHESTRATOR_URL}/chat",
            json={"message": prompt, "selected_tools": selected_tools},
            timeout=30.0,
        )
        resp.raise_for_status()
        thread_id = resp.json()["thread_id"]
    except Exception as e:
        return {"name": name, "status": "ERROR", "detail": f"Nie udało się wysłać zapytania: {e}"}

    result_text = None
    while time.time() - start < max_duration:
        time.sleep(POLL_INTERVAL)
        try:
            status_resp = httpx.get(f"{ORCHESTRATOR_URL}/status/{thread_id}", timeout=10.0)
            status = status_resp.json()
        except Exception:
            continue
        if status.get("stage") == "done":
            result_text = status.get("result", "")
            break
        if status.get("stage") == "error":
            return {"name": name, "status": "ERROR", "detail": status.get("detail", "błąd pipeline'u")}

    duration = round(time.time() - start, 1)

    if result_text is None:
        return {"name": name, "status": "TIMEOUT", "detail": f"Przekroczono limit {max_duration}s", "duration": duration}

    def _entry_missing(entry) -> bool:
        """Grupa (lista) alternatyw - wystarczy jedna. Pojedynczy string
        - musi wystąpić dokładnie ten."""
        variants = entry if isinstance(entry, list) else [entry]
        return not any(v.lower() in result_text.lower() for v in variants)

    missing = [entry for entry in must_contain if _entry_missing(entry)]
    forbidden_found = [phrase for phrase in must_not_contain if phrase.lower() in result_text.lower()]

    passed = not missing and not forbidden_found
    return {
        "name": name,
        "status": "PASS" if passed else "FAIL",
        "duration": duration,
        "ground_truth_must_contain": must_contain,
        "ground_truth_must_not_contain": must_not_contain,
        "missing_required_phrases": missing,
        "forbidden_phrases_found": forbidden_found,
        "full_report": result_text,
    }


def main():
    filter_name = sys.argv[1] if len(sys.argv) > 1 else None
    cases = load_cases(filter_name)

    if not cases:
        print(f"Brak przypadków testowych{f' o nazwie {filter_name}' if filter_name else ''} w {CASES_DIR}")
        sys.exit(1)

    if not ADMIN_AGENT_TOKEN:
        print("⚠ UWAGA: ADMIN_AGENT_TOKEN nie został wczytany z .env - testy z ground_truth admin_agent zawiodą")

    print(f"Uruchamiam {len(cases)} przypadków testowych...")
    results = [run_case(case) for case in cases]

    passed = sum(1 for r in results if r["status"] == "PASS")
    total = len(results)

    print(f"\n{'='*70}")
    print("PODSUMOWANIE")
    print(f"{'='*70}")
    for r in results:
        icon = {"PASS": "✅", "FAIL": "❌", "TIMEOUT": "⏱️", "ERROR": "💥"}.get(r["status"], "?")
        print(f"{icon} {r['name']}: {r['status']}", end="")
        if r["status"] == "FAIL":
            if r.get("missing_required_phrases"):
                print(f" | brakuje: {r['missing_required_phrases']}", end="")
            if r.get("forbidden_phrases_found"):
                print(f" | zakazane znalezione: {r['forbidden_phrases_found']}", end="")
        if r["status"] == "ERROR":
            print(f" | {r.get('detail')}", end="")
        print()

    percent = round(100 * passed / total, 1) if total else 0
    print(f"\nWYNIK: {passed}/{total} testów PASS ({percent}%)")

    RESULTS_DIR.mkdir(exist_ok=True)
    result_file = RESULTS_DIR / f"{time.strftime('%Y-%m-%d_%H%M%S')}.json"
    with open(result_file, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    print(f"Pełne wyniki zapisane w: {result_file}")


if __name__ == "__main__":
    main()
