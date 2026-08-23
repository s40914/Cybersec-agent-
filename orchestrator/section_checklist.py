"""
Deterministyczny detektor "wielosekcyjnych" wyników narzędzi (np. full_audit),
który wstrzykuje do promptu jawną, policzoną listę sekcji obecnych w surowych
danych.

DLACZEGO TO ISTNIEJE:
Przy wielu sekcjach naraz (firewall + fail2ban + ssh + users + updates +
docker + services + recent_alerts) modele 8-14B systematycznie gubiły część
sekcji, mimo ogólnej instrukcji w REPORT_PROMPT "omów wszystko z tą samą
rygorystycznością". Ta instrukcja bez twardej, policzonej listy do odhaczenia
nie wystarczała - zaobserwowano regresję, gdzie finalny raport z full_audit
pokrywał tylko firewall + recent_alerts, pomijając całkowicie fail2ban, ssh,
users, updates, docker i services (i pisząc raport po angielsku).

Firewall ma już analogiczny mechanizm (firewall_parser.py) z policzoną
liczbą referencyjną reguł ALLOW/DENY - ten moduł generalizuje ten sam wzorzec
na poziom całych sekcji, dla dowolnego wielokluczowego wyniku JSON.
"""
import json

SECTION_LABELS = {
    "firewall": "Firewall (UFW)",
    "fail2ban": "Fail2ban",
    "ssh_config": "Konfiguracja SSH",
    "users": "Użytkownicy systemowi",
    "updates": "Aktualizacje systemowe",
    "docker": "Kontenery Docker",
    "services": "Usługi systemd",
    "recent_alerts": "Alarmy Wazuh/Suricata (weryfikacja detekcji)",
}


def extract_and_format_section_checklist(raw_results: str) -> str:
    """Szuka w raw_results obiektu JSON z wieloma kluczami najwyższego
    poziomu (charakterystyczne dla full_audit) i zwraca gotowy blok
    tekstowy z jawną, ponumerowaną listą sekcji do wstrzyknięcia w prompt.
    Zwraca pusty string, jeśli nie znaleziono takiego obiektu."""
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

        if len(obj) < 3:
            continue
        dict_values = sum(1 for v in obj.values() if isinstance(v, dict))
        if dict_values < len(obj) - 1:
            continue

        keys = list(obj.keys())
        lines = []
        lines.append(
            "### CHECKLISTA SEKCJI - WYGENEROWANA AUTOMATYCZNIE "
            "(deterministyczny kod, NIE LLM)"
        )
        lines.append("")
        lines.append(
            f"Surowe dane zawierają dokładnie {len(keys)} niezależnych sekcji "
            f"(wynik kilku narzędzi wywołanych naraz, np. full_audit). KAŻDA "
            f"z poniższych sekcji MUSI mieć własny, osobny nagłówek w "
            f"finalnym raporcie - nawet jeśli dana sekcja nie zawiera żadnych "
            f"problemów (wtedy napisz to wprost, np. 'Brak nieprawidłowości')."
        )
        lines.append("")
        for i, key in enumerate(keys, start=1):
            label = SECTION_LABELS.get(key, key)
            lines.append(f'{i}. {label} (klucz danych: "{key}")')
        lines.append("")
        lines.append(
            f"Liczba referencyjna do weryfikacji: dokładnie {len(keys)} sekcji "
            f"musi się znaleźć w finalnym raporcie, w tej samej kolejności "
            f"co powyżej."
        )
        lines.append("### KONIEC CHECKLISTY")
        return "\n".join(lines)
    return ""
