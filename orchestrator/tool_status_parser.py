"""
Deterministyczny parser statusu wykonania narzedzia (sukces/blad/przerwane),
wstrzykiwany do promptu tak samo jak firewall_parser.py i z tego samego
powodu: modele 8-14B w tym pipeline wielokrotnie WYMYŚLAŁY bledy wykonania
narzedzia (np. nieistniejacy kod HTTP, "przekroczony limit czasu") mimo ze
surowy JSON zwrocony przez pentest-agent/admin-agent jawnie ma pole
"status": "ok"/"error" i prawdziwy "returncode". Zamiast liczyc na to, ze
model "poprawnie zinterpretuje" surowy JSON, parsujemy go w Pythonie i
wstrzykujemy niepodwazalny fakt przed reszta danych.
"""
import json


def extract_and_format_tool_status_block(new_raw_part: str) -> str:
    """Szuka w new_raw_part segmentow JSON zwracanych przez narzedzia (kazdy
    ToolMessage to jeden segment oddzielony podwojnym entererm) i dla kazdego
    zawierajacego pola 'status' + 'tool' generuje deterministyczny wpis o
    powodzeniu/niepowodzeniu wykonania. Zwraca gotowy blok tekstowy albo
    pusty string, jesli nic pasujacego nie znaleziono"""
    entries = []
    for segment in new_raw_part.split("\n\n"):
        segment = segment.strip()
        if not segment:
            continue
        try:
            obj = json.loads(segment)
        except (json.JSONDecodeError, ValueError):
            continue
        if not isinstance(obj, dict):
            continue
        if "status" not in obj or "tool" not in obj:
            continue

        tool = obj.get("tool", "nieznane narzędzie")
        status = obj.get("status")
        returncode = obj.get("returncode")
        message = obj.get("message")

        if status == "ok":
            verdict = "SUKCES"
            detail = f"returncode={returncode}" if returncode is not None else "wykonano poprawnie"
        elif status == "stopped":
            verdict = "PRZERWANE RĘCZNIE PRZEZ UŻYTKOWNIKA"
            detail = ("użytkownik zatrzymał skan przed naturalnym zakończeniem - "
                       "częściowe dane mogą być dostępne w stdout, ale skan się nie dokończył")
        elif status == "odrzucone":
            verdict = "ODRZUCONE PRZEZ WALIDACJĘ"
            detail = message or "cel nie przeszedł walidacji (np. spoza dozwolonej sieci)"
        else:
            verdict = "BłąD"
            detail = message or (f"returncode={returncode}" if returncode is not None else "nieznany błąd")

        entries.append((tool, verdict, detail))

    if not entries:
        return ""

    lines = []
    lines.append("### STATUS WYKONANIA NARZĘDZI - ZWERYFIKOWANY AUTOMATYCZNIE (deterministyczny parser, NIE LLM)")
    lines.append("")
    lines.append(
        "Poniższa lista to JEDYNE ŹRÓDŁO PRAWDY co do tego, czy każde narzędzie "
        "wykonało się poprawnie. NIE wymyślaj własnej interpretacji sukcesu/błędu "
        "na podstawie treści stdout - jeśli poniżej jest SUKCES, narzędzie "
        "zadziałało poprawnie NIEZALEŻNIE od tego jaz wygląda/ile ma treść stdout. "
        "NIGDY nie zgłaszaj błędu (np. konkretnego kodu HTTP, timeoutu), którego "
        "nie ma w tej liście - to byłaby halucynacja."
    )
    lines.append("")
    for tool, verdict, detail in entries:
        lines.append(f"- {tool}: {verdict} ({detail})")
    lines.append("### KONIEC STATUSU ZWERYFIKOWANEGO AUTOMATYCZNIE")

    return "\n".join(lines)
