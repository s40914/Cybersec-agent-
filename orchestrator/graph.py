"""
Architektura (kaskadowy multi-model pipeline z weryfikacją anty-halucynacyjną):

  Krok 1: security_agent (create_react_agent na TOOL_MODEL_NAME)
          - JEDYNY etap wywołujący realne narzędzia diagnostyczne
          - zwraca SUROWE wyniki (jedyne źródło prawdy w całym pipeline)
          - jeśli wynik pierwszej próby jest mało informacyjny (patrz
            ESCALATION_MAP), graf automatycznie próbuje głębszego narzędzia
            na tym samym celu (warunkowa krawędź, max MAX_ESCALATIONS razy)
        |
        v
  Krok 2: N niezależnych "report writerów" (REPORT_MODEL_NAMES, ładowane
          KASKADOWO - jeden po drugim, żeby nie przeciążać VRAM)
          - każdy dostaje TE SAME surowe dane i prośbę użytkownika
          - każdy pisze WŁASNY, niezależny szkic raportu
        |
        v
  Krok 3: critic (CRITIC_MODEL_NAME - najsilniejszy dostępny model)
          - dostaje: surowe dane + wszystkie szkice
          - porównuje każdy fakt ze szkiców ZE SUROWYMI DANYMI (nie tylko
            między sobą - to kluczowe, bo kilka modeli może zgodnie
            popełnić ten sam błąd)
          - usuwa fakty niepotwierdzone w surowych danych
          - ujawnia rozbieżności między modelami (przydatne diagnostycznie)
          - pisze JEDEN finalny raport

Dlaczego nie MessagesState:
Ten pipeline ma jawny, ustrukturyzowany stan (raw_results, draft_reports,
final_report) zamiast listy wiadomości - dzięki temu critic ma czysty,
jednoznaczny dostęp do wszystkiego naraz. Efekt uboczny: każde zapytanie
jest niezależnym audytem "od zera", bez pamięci poprzednich tur rozmowy
(to pasuje do charakteru narzędzia - komenda audytowa, nie czat).

ESKALACJA NARZĘDZI (Faza 2):
security_agent to pętla ReAct (create_react_agent) - model już z natury
może wywołać kilka narzędzi po kolei w jednym przebiegu. Dorzucamy do tego
DODATKOWĄ, jawną warunkową krawędź NA POZIOMIE GRAFU: jeśli pierwsza próba
(np. check_local_ports) da wynik "mało informacyjny" (host up, zero otwartych
portów), graf automatycznie kieruje przepływ z powrotem do security_agent,
tym razem wymuszając głębsze narzędzie (nmap_vuln_scan) na tym samym celu.
To NIE jest tylko instrukcja w prompt - to realna decyzja podejmowana przez
kod (funkcja decide_after_security), więc działa deterministycznie
niezależnie od tego, czy model "zapamięta" wskazówkę z prompta.
"""
import json
import logging
import httpx
import os
from typing import TypedDict, List, Optional

logger = logging.getLogger("orchestrator")

from langchain_ollama import ChatOllama
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import StateGraph, START, END
from langgraph.prebuilt import create_react_agent
from langgraph.errors import GraphRecursionError

from tools import make_tools, _call_admin_agent
from pentest_tools import make_pentest_tools
from artifact_pipeline import ArtifactPipeline
from evidence_store import EvidenceStore
import time
import status_store
from firewall_parser import extract_and_format_firewall_block
from section_checklist import extract_and_format_section_checklist
from tool_status_parser import extract_and_format_tool_status_block
from facts_parser import (
    extract_and_format_updates_block,
    extract_and_format_users_block,
    extract_and_format_docker_block,
    extract_and_format_fail2ban_block,
    extract_and_format_ssh_block,
    extract_and_format_services_block,
    extract_and_format_alerts_block,
    extract_and_format_port_exposure_guard,
    extract_and_format_lynis_block,
    extract_and_format_nuclei_block,
    extract_and_format_whatweb_block,
    extract_and_format_wafw00f_block,
    extract_and_format_searchsploit_block,
    extract_and_format_testssl_block,
    compact_raw_results,
    extract_and_format_ports_block,
    extract_and_format_nmap_block,
    extract_and_format_hydra_block,
    extract_and_format_connection_guard,
    extract_and_format_sqlmap_block,
    extract_and_format_gobuster_block,
    extract_and_format_ffuf_block,
    extract_and_format_enum4linux_block,
    extract_and_format_nikto_block,
)

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://host.docker.internal:11434")

# Model do wykonywania narzędzi - MUSI wspierać natywny tool-calling.
# Potwierdzone testem: llama3.1:8b działa poprawnie.
TOOL_MODEL_NAME = os.getenv("TOOL_MODEL_NAME", "llama3.1:8b")

# Modele piszące niezależne szkice raportu - lista oddzielona przecinkami.
# Żaden z nich nie musi wspierać tool-callingu (czysta analiza tekstu).
REPORT_MODEL_NAMES = os.getenv(
    "REPORT_MODEL_NAMES",
    "qwen2.5-coder:14b,SpeakLeash/bielik-11b-v3.0-instruct:Q5_K_M,dolphin-mistral:latest",
).split(",")

# Model-recenzent (critic) - powinien być Twoim najsilniejszym/najbardziej
# dokładnym modelem, bo to on ma ostatnie słowo. mistral-small3.1:24b jest
# potencjalnie najmocniejszy, ale nie mieści się w całości w VRAM (15GB przy
# 11.4GB dostępnych) - część warstw poleci na CPU i będzie wolniej.
# qwen2.5:14b to rozsądny kompromis szybkość/jakość.
CRITIC_MODEL_NAME = os.getenv("CRITIC_MODEL_NAME", "qwen2.5:14b")

# Twardy limit kroków ReAct (AI message + tool message = 2 kroki) w JEDNYM
# wywołaniu security_agent.invoke(). Zapobiega nieskończonym pętlom, gdyby
# model 8B zapętlił się w wywoływaniu narzędzi. 20 to dużo zapasu na kilka
# narzędzi po kolei, ale wciąż twardy sufit.
AGENT_RECURSION_LIMIT = 20

# Mapa eskalacji: jeśli narzędzie z lewej strony da "mało informacyjny"
# wynik (patrz _looks_uninformative), graf automatycznie spróbuje narzędzia
# z prawej strony NA TYM SAMYM celu. Rozszerzaj świadomie - oba narzędzia
# w parze muszą przyjmować ten sam typ celu (tu: oba "ip").
# Automatyczna eskalacja narzędzi jest wyłączona.
#
# Kolejne narzędzia są proponowane przez warstwę raportującą/UI,
# ale nie są uruchamiane bez jawnego wyboru użytkownika.
ESCALATION_MAP = {}
MAX_ESCALATIONS = 0

# Narzędzia, po których automatycznie sprawdzamy, czy system detekcji
# (Wazuh/Suricata) zauważył ruch. Osobna, jednorazowa ścieżka - nie łączy
# się z pętlą eskalacji powyżej.
DETECTION_CHECK_TOOLS = {"nmap_stealth_scan"}
# Krótka pauza przed odczytem alarmów - logi Suricaty/Wazuh potrzebują
# chwili, żeby się zapisać i przefiltrować przez korelację Wazuh.
DETECTION_CHECK_DELAY_SECONDS = 5



def _process_artifact_for_thread(
    artifact_path: str,
    thread_id: str,
    target: str,
) -> dict:
    """
    Deterministyczny Artifact -> RE pipeline.
    Nie używa LLM i nie wykonuje artefaktu.
    """
    store = EvidenceStore()
    pipeline = ArtifactPipeline(store)

    artifact = pipeline.ingest(
        path=artifact_path,
        thread_id=thread_id,
        target=target,
    )

    # Import lokalny, żeby zachować istniejącą architekturę modułów.
    from re_pipeline import REPipeline

    re_result = REPipeline(store).inspect(artifact)

    return {
        "artifact": artifact.model_dump(mode="json"),
        "re": re_result,
    }



def _looks_uninformative(raw: str) -> bool:
    """Heurystyka: czy wynik narzędzia sieciowego (nmap) jest "pusty" -
    host odpowiedział, ale nie znaleziono żadnych otwartych portów/usług.
    Celowo prosta i czytelna - to sygnał do eskalacji, nie ocena bezpieczeństwa."""
    if not raw:
        return True
    lower = raw.lower()
    if "host up" in lower and "/tcp" not in lower and "/udp" not in lower:
        return True
    return False


SECURITY_AGENT_PROMPT = """Jesteś agentem technicznym do diagnostyki bezpieczeństwa serwera.

ZASADY (bezwzględne):
- Zawsze odpowiadaj wyłącznie po polsku.
- Twoje JEDYNE zadanie to wywołać odpowiednie narzędzia zgodnie z prośbą i zwrócić
  ich SUROWE wyniki. NIE interpretuj, NIE podsumowuj, NIE wyciągaj wniosków.
- NIGDY nie zmyślaj pól, wartości ani wyników, których narzędzie nie zwróciło.
- Jeśli prośba dotyczy kilku obszarów, wywołaj odpowiednio kilka narzędzi po kolei.
- Jeśli nie masz pewności które narzędzie pasuje, wybierz najbliższe znaczeniowo
  z listy dostępnych, nie improwizuj własnego formatu odpowiedzi.
- KRYTYCZNA ZASADA ŁĄCZENIA NARZĘDZI: jeśli użytkownik prosi o zalogowanie się
  (web_login) I PÓŹNIEJ o test narzędziem wymagającym autoryzacji (sqlmap_scan,
  gobuster_dir, whatweb_scan) NA TYM SAMYM CELU - MUSISZ wykonać te kroki w
  DOKŁADNIE takiej kolejności:
  1. Wywołaj web_login jako PIERWSZE narzędzie.
  2. Z wyniku JSON zwróconego przez web_login ODCZYTAJ dosłowną wartość pola
     "cookie" (np. "PHPSESSID=abc123; security=low").
  3. Wywołaj DRUGIE narzędzie (sqlmap_scan/gobuster_dir/whatweb_scan) PODAJĄC
     TĘ DOKŁADNĄ WARTOŚĆ jako parametr "cookie" - skopiuj ją literalnie ze
     stringa zwróconego przez web_login, NIE zostawiaj parametru "cookie"
     pustego ani nie pomijaj go, jeśli web_login zwrócił status "ok".
  Pominięcie kroku 2-3 (wywołanie drugiego narzędzia BEZ przekazania cookie)
  jest błędem - drugie narzędzie przetestuje wtedy niezalogowaną, statyczną
  wersję strony i da fałszywy wynik.
"""

PENTEST_ESCALATION_PROMPT = """

KONTEKST PENTESTINGOWY (narzędzia ofensywne):
- Pracujesz na własnej, dozwolonej infrastrukturze (allowlist wymusza to
  po stronie serwera - nie musisz o tym pamiętać, ale nie próbuj celów
  spoza tego, co podał użytkownik).
- Jeśli podstawowy skan portów (check_local_ports) nie znajdzie żadnych otwartych
  portów, system SAM automatycznie spróbuje głębszego skanu podatności
  (nmap_vuln_scan) na tym samym celu - nie musisz o to prosić ponownie.
- Narzędzia nikto_scan i gobuster_dir wymagają URL-a (http://IP:PORT), nie
  samego IP - użyj ich tylko gdy użytkownik poda adres z portem/protokołem,
  albo gdy wcześniejszy skan portów w TEJ SAMEJ rozmowie ujawnił konkretny
  port HTTP/HTTPS.
- Narzędzie ffuf_fuzz wymaga literalnego placeholdera 'FUZZ' w URL-u. Jeśli
  użytkownik lub wcześniejszy krok podał URL BEZ placeholdera 'FUZZ', a masz
  do dyspozycji ffuf_fuzz - SKONSTRUUJ poprawny URL SAMODZIELNIE, doklejając
  '/FUZZ' na końcu ścieżki (np. http://host:port/ staje się
  http://host:port/FUZZ). NIE pomijaj ffuf_fuzz tylko dlatego, że surowy URL
  nie zawierał jeszcze placeholdera - Twoim zadaniem jest go dodać.
"""

REPORT_PROMPT = """Jesteś analitykiem systemu diagnostyki bezpieczeństwa (SecOps) domowego serwera.

Dostajesz: (1) oryginalną prośbę użytkownika, (2) surowe dane zwrócone przez
narzędzia diagnostyczne.

ZASADY:
- Zawsze odpowiadaj wyłącznie po polsku.
- KOMPLETNOŚĆ JEST PRIORYTETEM NAD ZWIĘZŁOŚCIĄ: wymień KAŻDĄ regułę/pozycję
  obecną w surowych danych - nie pomijaj żadnego wpisu.
- JEŚLI surowe dane zawierają WIELE SEKCJI naraz (np. pełny audyt: firewall +
  fail2ban + ssh + users + updates + docker + services) - każda sekcja
  dostaje TĘ SAMĄ rygorystyczność co przy pojedynczym zapytaniu. NIE skracaj
  ani nie streszczaj wcześniejszych sekcji "żeby zmieścić" kolejne. Długość
  raportu ma wynikać z ilości danych, nie z limitu objętości w Twojej głowie.
- ZAKAZ GRUPOWANIA WIELU ELEMENTÓW W JEDNO ZDANIE Z PRZECINKAMI: jeśli surowe
  dane zawierają listę wielu pozycji tego samego typu (np. porty z wyniku
  scan_ports/nmap, użytkownicy, aktualizacje, procesy) - KAŻDA pozycja MUSI
  dostać WŁASNĄ, osobną linię/wypunktowanie. NIE WOLNO pisać w stylu "Port
  8082, 8010, 53, 9200, 8765: nasłuchuje na 127.0.0.1" - taka kondensacja w
  praktyce prowadzi do gubienia pozycji z listy (łatwo pominąć jedną liczbę
  w długim ciągu oddzielonym przecinkami, czego nie widać na pierwszy rzut
  oka ani przy weryfikacji). Zamiast tego wypisz:
  "- Port 8082: nasłuchuje na 127.0.0.1 (proces X)
   - Port 8010: nasłuchuje na 127.0.0.1 (proces Y)
   - Port 53: nasłuchuje na 127.0.0.1 (proces Z)"
  i tak dalej dla KAŻDEGO portu osobno, nawet jeśli opis się powtarza. To
  dotyczy każdej listy z surowych danych, nie tylko portów - PRZED oddaniem
  odpowiedzi policz pozycje w surowych danych i policz linie w swoim raporcie
  - liczby muszą się zgadzać.
- JEŚLI surowe dane NIE zawierają reguł firewalla (np. to wynik skanu nmap,
  nikto, gobustera) - NIE twórz sekcji o firewallu ani nie pisz "0 reguł
  ALLOW/DENY". Opisz TYLKO to, co faktycznie jest w surowych danych, w
  formacie odpowiednim dla tego konkretnego narzędzia.
- KRYTYCZNE: jeśli surowe dane zawierają fragment z "status": "error" lub
  wzmiankę o niepowodzeniu/timeout/błędzie połączenia dla JAKIEGOKOLWIEK
  narzędzia - MUSISZ to zgłosić WPROST jako pierwsze zdanie raportu (np.
  "Skan nmap_stealth_scan NIE POWIÓDŁ SIĘ - przekroczony limit czasu.").
  NIE pomijaj milcząco błędu narzędzia, nawet jeśli inne dane (np. alarmy
  z weryfikacji detekcji) są dostępne i wyglądają na kompletne - błąd
  głównego narzędzia jest zawsze najważniejszą informacją w raporcie.
- REGUŁY FIREWALLA Z DOPISKIEM "(v6)" TO OSOBNE, PEŁNOPRAWNE REGUŁY, nie
  duplikaty do pominięcia. Firewall (ufw) w tych danych zawsze zwraca komplet
  reguł IPv4 a zaraz po nich lustrzany komplet reguł IPv6 - to standardowy,
  zamierzony format wyjścia, nie błąd czy powtórzenie. Jeśli widzisz regułę
  "X on tailscale0 ALLOW IN Anywhere" a kilka linii dalej "X (v6) on
  tailscale0 ALLOW IN Anywhere (v6)" - to DWIE osobne reguły, obie muszą się
  znaleźć na liście z osobną oceną ryzyka, nawet jeśli treść wygląda niemal
  identycznie jak poprzednia reguła.
- OBOWIĄZKOWA WERYFIKACJA LICZBOWA PRZED NAPISANIEM RAPORTU (TYLKO jeśli
  surowe dane faktycznie zawierają reguły firewalla): policz ile linii
  zawierających "ALLOW IN" oraz ile linii zawierających "DENY IN" jest w
  surowych danych firewalla (osobno IPv4 i IPv6). Napisz ten wynik jako
  pierwsze zdanie sekcji firewalla, np. "Surowe dane zawierają N reguł ALLOW
  i M reguł DENY (w tym K wariantów IPv6)." Następnie Twoja lista reguł MUSI
  zawierać dokładnie N+M pozycji - jeśli masz mniej, wróć i uzupełnij brakujące
  zanim oddasz odpowiedź. NIE dziel reguł na osobne tabele/kategorie w sposób,
  który pozwoliłby Ci pominąć całą kategorię (np. tabela tylko dla "ALLOW" bez
  osobnej tabeli dla "DENY") - wszystkie reguły muszą się znaleźć w raporcie.
- Dla reguł firewalla ZAWSZE zachowaj informację o interfejsie/zakresie źródłowym
  dokładnie tak, jak w surowych danych (np. "tylko przez tailscale0" vs
  "z dowolnego adresu" to zupełnie różny poziom ryzyka).
- OCENA RYZYKA REGUŁY FIREWALLA - dotyczy WYŁĄCZNIE reguł ALLOW (reguły DENY
  ograniczają ruch, więc same w sobie NIGDY nie są ryzykiem - pomijaj je przy
  ocenie ryzyka, chyba że blokują coś co powinno być dozwolone).
  Dla każdej reguły ALLOW sprawdź DOSŁOWNY tekst kolumny "To"/opisu reguły
  z surowych danych i zakwalifikuj wg DOKŁADNIE tych dwóch kategorii:
    * Tekst reguły zawiera literalnie "on tailscale0" (np. "22 on tailscale0")
      LUB kolumna From to prywatna podsieć (192.168.0.0/24, 10.0.0.0/8,
      172.16.0.0/12) = dostęp OGRANICZONY do sieci VPN Tailscale lub sieci
      lokalnej - NIE zakładaj, że tailscale0 może być "publiczne"; to prywatna
      sieć VPN typu mesh, dostępna tylko dla podłączonych do niej urządzeń,
      chyba że surowe dane WPROST wspominają o Funnel/Serve/publicznym
      udostępnieniu (jeśli nie wspominają - traktuj jako prywatne).
      -> NISKI priorytet ryzyka.
    * Tekst reguły NIE zawiera "on tailscale0" i From to "Anywhere" (bez
      żadnego ograniczenia CIDR) = port dostępny z CAŁEGO INTERNETU, bez
      VPN, bez ograniczenia do sieci lokalnej.
      -> WYSOKI priorytet ryzyka - to jest najważniejsza kategoria do
      wypunktowania w sekcji problemów bezpieczeństwa, NIEZALEŻNIE od numeru
      portu (dotyczy to zarówno portu 22 jak i mniej oczywistych portów typu
      2847 czy 8765, jeśli akurat tak skonfigurowane w danych).
  PRZYKŁAD z realnych danych: "22 on tailscale0 ALLOW IN Anywhere" = NISKIE
  ryzyko (ograniczone do VPN). "2847/tcp ALLOW IN Anywhere" (BEZ
  "on tailscale0") = WYSOKIE ryzyko (dostępne z całego internetu). Te dwie
  reguły MUSZĄ mieć różną ocenę ryzyka, mimo że obie mają "Anywhere" w
  kolumnie From - liczy się to, czy jest "on tailscale0" w opisie reguły.
- Przy wskazywaniu "najbardziej ryzykownych" portów/usług NIE zakładaj z góry,
  że port 22 jest automatycznie najważniejszym problemem tylko dlatego, że to
  standardowy port SSH - wypisz realnie WSZYSTKIE porty z kategorii WYSOKIE
  ryzyko wg powyższej reguły, i to one są priorytetem, niezależnie od numeru.
- KRYTYCZNE OGRANICZENIE WNIOSKOWANIA O EKSPOZYCJI: nasłuchiwanie procesu na adresie
  "0.0.0.0" (w wyniku np. `ss`/`scan_ports`) oznacza TYLKO, że proces przyjmuje
  połączenia na dowolnym interfejsie SIECIOWYM TEGO HOSTA - to NIE jest to samo
  co "dostępność z internetu". O rzeczywistej ekspozycji na zewnątrz decyduje
  WYŁĄCZNIE firewall (UFW) i konfiguracja NAT/routera. Jeśli surowe dane w TYM
  KONKRETNYM wyniku NIE zawierają danych z check_firewall (regul ALLOW/DENY),
  NIE WOLNO Ci pisać, że port jest "dostępny z internetu", "otwarty na świat"
  ani nadawać mu priorytetu "WYSOKI"/"KRYTYCZNY" z tego powodu - zamiast tego
  napisz wprost: "Port X nasłuchuje lokalnie: rzeczywista dostępność z zewnątrz
  wymaga weryfikacji przez check_firewall (dane niedostępne w tym wyniku)."
- Jasno wskaż ewentualne problemy bezpieczeństwa, jeśli wynikają z danych.
- Jeśli czegoś nie sprawdzono, powiedz to wprost zamiast zgadywać.
- NIGDY nie podawaj danych, których nie ma w surowych danych - jeśli surowe
  dane są puste, niekompletne albo wskazują na błąd (np. brak autoryzacji),
  NAPISZ TO WPROST zamiast wymyślać przykładowe wartości.
- Nie wywołujesz żadnych narzędzi - Twoja rola to wyłącznie analiza tekstu.
- JEŚLI surowe dane zawierają sekcję "### WERYFIKACJA DETEKCJI (Wazuh/Suricata)":
  to jest DODATKOWY kontekst do omówienia NA KOŃCU raportu, NIE główna treść.
  Główną treścią jest zawsze wynik narzędzia diagnostycznego (nmap, nikto itd.).
  Struktura raportu ZAWSZE musi być:
  1. Wyniki głównego narzędzia (nmap/nikto/sqlmap/etc.) - omów jako PIERWSZY,
     kompletnie, niezależnie od tego ile danych zawiera sekcja detekcji.
  2. JEŚLI surowe dane zawierają blok "ARTIFACT_RE_RESULTS": sekcja
     "Analiza artefaktu" - omów jako DRUGI element, PRZED weryfikacją
     detekcji, z pełnymi konkretami (patrz osobna instrukcja poniżej o
     ARTIFACT_RE_RESULTS). Ta sekcja jest RÓWNIE OBOWIĄZKOWA jak wyniki
     głównego narzędzia z punktu 1 - to trzeci pełnoprawny element
     struktury raportu, nie opcjonalny dodatek.
  3. Weryfikacja detekcji - omów jako OSTATNI element, krótko (1-3 zdania):
     czy system IDS/IPS zauwaŸył ruch, jakie alerty (typy, liczba, poziom).
     NIE pisz osobnego długiego raportu SOC o alertach Suricaty/Wazuh -
     to jest tylko informacja pomocnicza, czy skan był widoczny dla systemu.
  NIE WOLNO napisać raportu, który zawiera TYLKO sekcję detekcji bez wyniku
  głównego narzędzia - to byłby raport niekompletny. NIE WOLNO pominąć
  sekcji "Analiza artefaktu", jeśli dane ARTIFACT_RE_RESULTS są obecne w
  surowych danych - pominięcie jej jest błędem tej samej wagi co
  pominięcie wyników głównego narzędzia.
- DANE ŹRóDŁOWE PO ANGIELSKU: jeśli surowe dane (np. alerty Suricata/Wazuh,
  opisy CVE, komunikaty systemowe) są po angielsku - PRZETŁUMACZ je na polski
  w swoim raporcie. Nigdy nie kopiuj obcojęzycznych bloków tekstu 1:1 do
  raportu - zawsze pisz własną analizę PO POLSKU na podstawie tych danych.
- JEŚLI surowe dane zawierają blok "### STATUS WYKONANIA NARZĘDZI - ZWERYFIKOWANY
  AUTOMATYCZNIE": to jest JEDYNE ƹRÓDŁO PRAWDY o sukcesie/błędzie narzędzia.
  NIE nadpisuj tego statusu własną interpretacją stdout. Jeśli blok mówi
  SUKCES - narzędzie zadziałało, niezależnie od wyglądu stdout.
- JEŚLI surowe dane zawierają blok "ARTIFACT_RE_RESULTS": oznacza to, że
  użytkownik przesłał plik/artefakt do analizy (reverse engineering).
  MUSISZ dodać w raporcie OSOBNĄ sekcję "Analiza artefaktu", zawierającą
  WSZYSTKIE poniższe elementy, jeśli są obecne w danych:
    - NAJWAŻNIEJSZE, SPRAWDŹ TO PIERWSZE: jeśli surowe dane zawierają blok
      "### WERDYKT HASH-LOOKUP ARTEFAKTU - ZWERYFIKOWANY AUTOMATYCZNIE": to
      jest JEDYNE ŹRÓDŁO PRAWDY o wyniku sprawdzenia SHA256 przeciw bazie
      zagrożeń. Przepisz odpowiednią linię z tego bloku DOSŁOWNIE, bez
      zmian, jako PIERWSZE zdanie sekcji "Analiza artefaktu". NIE
      interpretuj samodzielnie pola "hash_lookup" w danych JSON poniżej -
      werdykt jest już gotowy w tym bloku. Jeśli werdykt to "ZNANY
      MALWARE", ta informacja ma najwyższy priorytet w całym raporcie,
      niezależnie od severity pozostałych ustaleń.
    - Nazwa/typ pliku (pole "file_type") oraz suma kontrolna (pole "sha256")
      i rozmiar (pole "size_bytes").
    - Wskaźniki z pola "summary.indicators" (has_urls, has_ip_addresses,
      has_shell_commands, has_crypto_terms, has_network_terms,
      has_debug_symbols, has_symbols) - wypisz KAŻDY wskaźnik, który ma
      wartość true, jako osobne, konkretne ustalenie (nie tylko
      "true/false", tylko co to oznacza dla bezpieczeństwa).
    - KONKRETNE dane z pola "evidence": jeśli "evidence.urls_found" nie
      jest puste, wymień KAŻDY znaleziony URL osobno. To samo dla
      "evidence.ip_addresses_found" (adresy IP),
      "evidence.suspicious_symbols_found" (funkcje/symbole takie jak
      system, execve, socket - wskazujące na możliwe działanie:
      wykonywanie poleceń powłoki, komunikację sieciową itp.) oraz
      "evidence.crypto_terms_found".
    - Jeśli pole "omitted.objdump_included" to false, wspomnij, że pełny
      disassembly nie był analizowany przez model językowy (dostępny
      osobno do analizy narzędziowej), żeby nie sugerować pełnej
      analizy binarnej.
    - Jeśli pole "evidence.yara_matches" nie jest puste: to są trafienia
      DETERMINISTYCZNYCH reguł sygnaturowych YARA - najsilniejszy sygnał
      w całej analizie artefaktu, MUSISZ je wymienić jako pierwsze w
      sekcji "Analiza artefaktu". Dla każdego trafienia podaj nazwę
      reguły (pole "rule"), poziom (pole "severity": high/medium/low) i
      opis (pole "description"). Reguła z severity="high" jest zawsze
      najważniejszym ustaleniem całego raportu artefaktu, niezależnie od
      innych wskaźników.
    - Jeśli pole "evidence.embedded_files_found" nie jest puste: binwalk
      wykrył sygnatury innych plików/archiwów osadzonych wewnątrz
      analizowanego artefaktu (np. archiwum ZIP, obraz, inna binarka
      ukryta w środku). To jest częsty wzorzec w malware-dropperach -
      wymień KAŻDE znalezisko z jego offsetem i opisem, i zaznacz to
      jako ustalenie WYSOKIEGO ryzyka wymagające dalszej ręcznej analizy.
  Sekcja "Analiza artefaktu" jest RÓWNIE OBOWIĄZKOWA jak pozostałe
  sekcje audytu hosta - pominięcie jej, gdy dane ARTIFACT_RE_RESULTS są
  obecne, jest błędem tej samej wagi co pominięcie reguły firewalla.
"""

CRITIC_PROMPT = """Jesteś głównym recenzentem (critic) w systemie diagnostyki bezpieczeństwa.

Dostajesz:
1. Oryginalną prośbę użytkownika.
2. SUROWE dane zwrócone bezpośrednio przez narzędzia diagnostyczne - to JEDYNE
   źródło prawdy w tym zadaniu.
3. Kilka niezależnie napisanych szkiców raportu od różnych modeli, bazujących
   na tych samych surowych danych.

ZADANIE (wykonaj dokładnie w tej kolejności):
1. Porównaj KAŻDY szkic ze SUROWYMI danymi, zdanie po zdaniu.
1b. OBOWIĄZKOWA WERYFIKACJA LICZBOWA - TYLKO jeśli surowe dane faktycznie
    zawierają reguły firewalla (linie z "ALLOW IN"/"DENY IN"): policz
    dokładnie ile linii zawiera "ALLOW IN" i ile zawiera "DENY IN" (osobno
    policz ile z nich ma dopisek "(v6)"). To jest Twoja liczba referencyjna -
    np. "28 reguł łącznie: 16 IPv4 (14 ALLOW + 2 DENY), 12 IPv6 (10 ALLOW +
    2 DENY)". Następnie dla KAŻDEGO szkicu policz, ile reguł faktycznie
    wymienił. Jeśli suma w szkicu jest MNIEJSZA niż liczba referencyjna z
    surowych danych, to szkic jest niekompletny - wypisz explicite w sekcji
    "Rozbieżności", ile reguł dany szkic pominął. Jeśli surowe dane NIE
    zawierają reguł firewalla - pomiń ten krok całkowicie, nie wymyślaj liczby
    reguł ani nie pisz "0 reguł ALLOW/DENY" dla danych innego typu (np. wyniku
    skanu nmap/nikto/gobuster).
1c. TWÓJ finalny raport MUSI zawierać wszystkie reguły z surowych danych (o
    ile surowe dane dotyczą firewalla) - policz swoją własną finalną listę
    reguł i upewnij się, że suma zgadza się z liczbą referencyjną z kroku 1b,
    zanim oddasz odpowiedź.
2. Każdy fakt w szkicach (adres IP, port, ścieżka, nazwa, wartość liczbowa),
   który NIE występuje dosłownie lub jednoznacznie w surowych danych - jest
   HALUCYNACJĄ. Usuń go całkowicie, nie przenoś go do finalnego raportu.
3. Jeśli szkice się różnią między sobą, rozstrzygnij na podstawie surowych
   danych - nie na podstawie tego, który szkic "brzmi pewniej".
4. Jeśli surowe dane zawierają coś istotnego, czego żaden szkic nie uwzględnił,
   dopisz to samodzielnie NA PODSTAWIE SUROWYCH DANYCH.
4b. Zweryfikuj SPÓJNOŚĆ WEWNĘTRZNĄ każdego szkicu: jeśli szkic w sekcji
    "problemy bezpieczeństwa" nazywa jakiś port/usługę ryzykowną, sprawdź czy
    ta ocena zgadza się z regułą tego samego portu wymienioną wcześniej w tym
    samym szkicu. Taka sprzeczność to błąd analizy modelu, nie halucynacja
    faktu - popraw ją w finalnym raporcie na podstawie surowych danych.
4c. Zawsze wskaż w finalnym raporcie, które konkretne porty/usługi są
    dostępne "Anywhere" (bez ograniczenia do tailscale0 lub prywatnej
    podsieci) - to jest realny wektor ataku z internetu i priorytet numer
    jeden, niezależnie od tego, czy któryś szkic to zauważył.
4bb. Zweryfikuj, czy szkic nie nazwal portu "dostępnym z internetu"/"otwartym na
     świat" WYŁĄCZNIE na podstawie tego, że proces nasłuchuje na "0.0.0.0" (np.
     wynik ss/scan_ports), BEZ danych z check_firewall w tym samym przebiegu.
     Nasłuchiwanie lokalne NIE dowodzi dostępności z internetu - jeśli szkic
     zrobił ten skrót myślowy, popraw to w finalnym raporcie na neutralne
     sformułowanie ("wymaga weryfikacji przez check_firewall").
4d. Zweryfikuj, czy szkice nie oznaczyły reguł DENY jako "ryzykowne" - reguła
    DENY blokuje ruch, więc obniża ryzyko, nigdy go nie podwyższa. Jeśli
    któryś szkic to pomylił, popraw w finalnym raporcie.
4e. Zweryfikuj, czy szkice nie potraktowały WSZYSTKICH reguł "on tailscale0"
    i reguł BEZ "on tailscale0" jako tego samego poziomu ryzyka. Konkretnie
    sprawdź reguły dla portów, które w surowych danych NIE mają
    "on tailscale0" przy sobie - to one są priorytetem.
4f. Jeśli surowe dane zawierają blok "ARTIFACT_RE_RESULTS", sprawdź czy
    KAŻDY szkic zawiera sekcję "Analiza artefaktu" z konkretnymi danymi
    (sha256, file_type, wskaźniki, znalezione URL-e/IP/symbole - nie
    tylko ogólnikowe "wykryto ślady"). Jeśli któryś szkic pominął tę
    sekcję albo podał ją bez konkretów, dopisz ją samodzielnie w
    finalnym raporcie NA PODSTAWIE surowych danych ARTIFACT_RE_RESULTS -
    pominięcie analizy artefaktu jest błędem tej samej wagi co
    pominięcie reguły firewalla.
5. Napisz JEDEN finalny raport po polsku, zawierający WYŁĄCZNIE fakty
   potwierdzone w surowych danych.
6. Na końcu dodaj krótką sekcję "Rozbieżności wykryte między modelami" -
   wypisz, które modele podały błędne/wymyślone informacje, jeśli takie były.
   KRYTYCZNE OGRANICZENIE: możesz przypisać błąd konkretnemu modelowi TYLKO
   jeśli potrafisz krótko sparafrazować, CO DOKŁADNIE ten model napisał
   błędnie (np. "podał liczbę 5 użytkowników zamiast 1"). Jeśli nie pamiętasz
   konkretnej, weryfikowalnej treści szkicu - NIE przypisuj błędu żadnemu
   nazwanemu modelowi; napisz ogólnie "wykryto niespójność" bez wskazywania
   winnego, albo pomiń tę sekcję. Wymyślanie zarzutów wobec modeli, których
   szkic nie zawierał opisywanego błędu, jest samo w sobie halucynacją.
   Jeśli wszystkie szkice były zgodne ze źródłem, napisz to wprost.
7. OZNACZANIE ISTOTNYCH USTALEŃ: dla każdego konkretnego, istotnego ustalenia
   (nie dla całych sekcji, tylko dla pojedynczych faktów wartych uwagi -
   otwarty port z nietypową usługą, przestarzałe oprogramowanie, brak
   autoryzacji, podejrzany endpoint itp.) dodaj w tekście raportu, obok
   normalnego opisu, blok w formacie:
   ::finding[POZIOM]{concern="NAZWA_CONCERN" title="krótki tytuł po polsku"}
   Treść ustalenia (1-2 zdania, na podstawie surowych danych).
   ::
   - POZIOM to jedno z: high, medium, low.
   - NAZWA_CONCERN MUSI być DOKŁADNIE jedną z poniższej zamkniętej listy -
     NIGDY nie wymyślaj własnej nazwy, jeśli żadna nie pasuje idealnie,
     wybierz najbliższą znaczeniowo albo pomiń blok dla tego ustalenia:
     - outdated_software (przestarzała wersja usługi/oprogramowania z
       możliwymi CVE)
     - open_web_service (wykryto działającą usługę HTTP/HTTPS)
     - web_app_present (zidentyfikowano konkretną aplikację/CMS webową)
     - possible_sqli (parametr URL wygląda na potencjalnie podatny na SQL
       injection)
     - weak_auth_candidate (usługa z logowaniem, wartą sprawdzenia pod
       kątem słabych/domyślnych haseł)
     - smb_service_present (wykryto usługę SMB/Windows)
     - unidentified_service (port otwarty, ale usługa nierozpoznana)
     - hidden_endpoints_suspected (może istnieć ukryty katalog/panel/plik)
     - detection_untested (nie zweryfikowano czy system IDS/IPS wykrywa ten
       ruch)
   - Nie każde ustalenie wymaga bloku - używaj tylko dla rzeczy realnie
     wartych dalszej weryfikacji narzędziem pentestowym. Reguły firewalla,
     ogólne podsumowania i rekomendacje NIE dostają bloku ::finding.
   - Jeśli surowe dane nie dają podstaw do żadnego z powyższych concern, nie
     dodawaj żadnego bloku ::finding - to w pełni poprawny wynik.

Zawsze odpowiadaj wyłącznie po polsku. Nie wywołujesz żadnych narzędzi.
"""


class AuditState(TypedDict):
    thread_id: str
    admin_password: Optional[str]
    user_email: Optional[str]
    user_request: str
    selected_tools: Optional[List[str]]
    tool_params: Optional[dict]
    raw_results: str
    deterministic_facts: str
    firewall_facts_snapshot: str
    docker_facts_snapshot: str
    services_facts_snapshot: str
    lynis_facts_snapshot: str
    nuclei_facts_snapshot: str
    searchsploit_facts_snapshot: str
    testssl_facts_snapshot: str
    draft_reports: List[dict]
    final_report: str
    escalation_count: Optional[int]
    last_tool_used: Optional[str]
    detection_checked: Optional[bool]
    tool_call_count: int
    artifact_results: list[dict]


def build_artifact_verdict_block(artifact_results: list[dict]) -> str:
    """
    Deterministyczny blok werdyktu hash-lookup dla artefaktow, wstrzykiwany
    tym samym wzorcem co tool_status_parser.py - modele 8-14B w tym
    pipeline myliły/pomijały warunkową instrukcję "jeśli hash_lookup ...
    inaczej ..." (raz sklejały oba warianty naraz, raz pomijały sekcję
    całkowicie), więc zamiast liczyć na poprawną interpretację warunku
    przez LLM, budujemy gotowy, niepodważalny werdykt w Pythonie.
    """
    if not artifact_results:
        return ""

    lines = []
    lines.append(
        "### WERDYKT HASH-LOOKUP ARTEFAKTU - ZWERYFIKOWANY AUTOMATYCZNIE "
        "(deterministyczny parser, NIE LLM)"
    )
    lines.append("")
    lines.append(
        "Poniższa lista to JEDYNE ŹRÓDŁO PRAWDY co do wyniku sprawdzenia "
        "SHA256 artefaktu przeciw lokalnej bazie znanych zagrożeń. Każdą "
        "z poniższych linii MUSISZ przepisać DOSŁOWNIE jako pierwsze "
        "zdanie sekcji \"Analiza artefaktu\" dla danego artefaktu - NIE "
        "interpretuj samodzielnie pola \"hash_lookup\" w danych JSON "
        "poniżej, werdykt jest już gotowy tutaj."
    )
    lines.append("")

    for item in artifact_results:
        artifact_id = item.get("artifact_id", "nieznany")
        hl = item.get("hash_lookup")
        if hl:
            threat = hl.get("threat_name", "nieznany")
            source = hl.get("source", "nieznane źródło")
            verdict = f"ZNANY MALWARE: {threat} (źródło: {source})."
        else:
            verdict = (
                "SHA256 nie występuje w lokalnej bazie znanych zagrożeń "
                "(co NIE jest dowodem nieszkodliwości pliku)."
            )
        lines.append(f"- artefakt {artifact_id}: {verdict}")
        fm = item.get("fuzzy_matches") or []
        for m in fm:
            lines.append(
                f"  - PODOBIENSTWO {m.get('similarity')}% do znanego zagrozenia: "
                f"{m.get('threat_name')} (zrodlo: {m.get('source')})"
            )

    lines.append("### KONIEC WERDYKTU ZWERYFIKOWANEGO AUTOMATYCZNIE")
    return "\n".join(lines)


def build_sast_verdict_block(sast_results: list[dict]) -> str:
    """
    Deterministyczny blok werdyktu SAST (Semgrep), tym samym wzorcem co
    build_artifact_verdict_block. Liczba i tresc findings jest gotowa
    z Pythona - LLM przepisuje, nie interpretuje warunkowo.
    """
    if not sast_results:
        return ""

    lines = []
    lines.append(
        "### WERDYKT SAST (SEMGREP) - ZWERYFIKOWANY AUTOMATYCZNIE "
        "(deterministyczny parser, NIE LLM)"
    )
    lines.append("")
    lines.append(
        "Poniższa lista to JEDYNE ŹRÓDŁO PRAWDY co do liczby i treści "
        "podatności wykrytych statyczną analizą kodu (Semgrep, oficjalne "
        "rulesety p/sql-injection, p/security-audit, p/owasp-top-ten). "
        "MUSISZ przepisać poniższe linie DOSŁOWNIE jako sekcję \"Analiza "
        "artefaktu (SAST)\" - NIE licz findings samodzielnie z pola "
        "\"findings\" w danych JSON poniżej, liczba jest już policzona "
        "tutaj."
    )
    lines.append("")

    for item in sast_results:
        artifact_id = item.get("artifact_id", "nieznany")
        count = item.get("findings_count", 0)
        if count == 0:
            verdict = "brak wykrytych podatności statyczną analizą kodu."
        else:
            verdict = f"wykryto {count} potencjalnych podatności:"
        lines.append(f"- artefakt {artifact_id}: {verdict}")
        for f in item.get("findings", []):
            lines.append(
                f"  - [{f.get('severity', '?')}] "
                f"{f.get('rule_id', '?')} "
                f"(linia {f.get('line_start', '?')}): "
                f"{f.get('message', '')}"
            )

    lines.append("")
    lines.append(
        "OGRANICZENIE (informacja obowiazkowa do zacytowania w raporcie): "
        "SAST wykrywa ZNANE, statyczne wzorce podatnosci. Brak wykrytych "
        "podatnosci NIE oznacza braku podatnosci w kodzie - narzedzia "
        "oparte o taint-tracking (jak Semgrep) moga przeoczyc przypadki "
        "czesciowej/niewystarczajacej sanityzacji. Zalecane uzupelnienie "
        "o dynamiczne testy (np. sqlmap_scan) i/lub manualny przeglad kodu."
    )
    lines.append("### KONIEC WERDYKTU SAST ZWERYFIKOWANEGO AUTOMATYCZNIE")
    return "\n".join(lines)


def load_artifact_re_node(state: AuditState):
    """
    Ładuje trwałe wyniki Artifact/RE dla bieżącego thread_id.

    Node jest wyłącznie odczytowy: nie wykonuje artefaktu i nie uruchamia
    ponownie RE. Korzysta z RawResult zapisanych podczas ingestu.
    """
    store = EvidenceStore()

    raw_results = store.get_raw_results(
        thread_id=state["thread_id"],
    )

    re_results = [
        x for x in raw_results
        if x.tool_name in ("re_pipeline", "sast_pipeline")
    ]

    artifact_results = []

    for raw in re_results:
        try:
            parsed = json.loads(raw.stdout)
        except Exception:
            parsed = {
                "artifact_id": raw.metadata.get("artifact_id"),
                "raw_result_id": raw.id,
                "parse_error": True,
                "stdout": raw.stdout,
            }

        parsed["_raw_result_id"] = raw.id
        artifact_results.append(parsed)

    if not artifact_results:
        logger.info(
            "ARTIFACT_RE: brak wyników RE dla thread_id=%s",
            state["thread_id"],
        )
        return {
            "artifact_results": [],
        }

    deterministic_facts = "\n\n".join(
        json.dumps(
            item,
            ensure_ascii=False,
            indent=2,
        )
        for item in artifact_results
    )

    # RE jest trwałym wynikiem narzędzia i musi wejść do tego samego,
    # niezmiennego strumienia dowodowego co pozostałe wyniki narzędzi.
    # Dzięki temu report_writers i critic nie mogą "zgubić" artefaktu
    # tylko dlatego, że pochodzi z osobnego pipeline'u.
    hash_verdict = build_artifact_verdict_block(
        [x for x in artifact_results if "hash_lookup" in x]
    )
    sast_verdict = build_sast_verdict_block(
        [x for x in artifact_results if "findings_count" in x]
    )
    verdict_block = "\n\n".join(v for v in (hash_verdict, sast_verdict) if v)

    re_raw_block = (
        "ARTIFACT_RE_RESULTS (JEDYNE ŹRÓDŁO DOWODÓW DLA ANALIZY ARTEFAKTÓW):\n"
        + (verdict_block + "\n\n" if verdict_block else "")
        + deterministic_facts
    )

    previous_raw = (state.get("raw_results") or "").strip()
    raw_results = (
        f"{previous_raw}\\n\\n{re_raw_block}"
        if previous_raw
        else re_raw_block
    )

    logger.info(
        "ARTIFACT_RE: załadowano %d wynik(ów) RE dla thread_id=%s; "
        "dołączono do raw_results (len=%d)",
        len(artifact_results),
        state["thread_id"],
        len(raw_results),
    )

    return {
        "artifact_results": artifact_results,
        "deterministic_facts": deterministic_facts,
        "raw_results": raw_results,
        # RE jest rzeczywistym wynikiem narzędzia zapisanym w EvidenceStore.
        # Nie pozwalamy, aby guard report_writers uznał taki audyt za
        # pozbawiony danych tylko dlatego, że RE nie zwiększało wcześniej
        # tool_call_count.
        "tool_call_count": max(
            int(state.get("tool_call_count") or 0),
            len(artifact_results),
        ),
    }



def build_app():
    tool_llm = ChatOllama(model=TOOL_MODEL_NAME, base_url=OLLAMA_BASE_URL, temperature=0, num_ctx=8192,
            client_kwargs={"timeout": httpx.Timeout(600.0, connect=10.0)})

    def security_node(state: AuditState):
        logger.info(
            "SECURITY_NODE_INPUT: thread_id=%s raw_len=%d artifact_re=%s "
            "tool_call_count=%s escalation_count=%s selected_tools=%s",
            state["thread_id"],
            len(state.get("raw_results") or ""),
            "ARTIFACT_RE_RESULTS" in (state.get("raw_results") or ""),
            state.get("tool_call_count"),
            state.get("escalation_count"),
            state.get("selected_tools"),
        )

        logger.info(
            "SECURITY_NODE_BEFORE_PENTEST_TOOLS: thread_id=%s",
            state["thread_id"],
        )
        pentest_tools_list = make_pentest_tools(
            state["thread_id"],
            admin_password=state.get("admin_password"),
            user_email=state.get("user_email"),
        )
        logger.info(
            "SECURITY_NODE_AFTER_PENTEST_TOOLS: thread_id=%s pentest_tools=%s",
            state["thread_id"],
            [t.name for t in pentest_tools_list],
        )

        logger.info(
            "SECURITY_NODE_BEFORE_MAKE_TOOLS: thread_id=%s",
            state["thread_id"],
        )
        all_tools = make_tools() + pentest_tools_list
        audit_only_tools = make_tools()
        logger.info(
            "SECURITY_NODE_AFTER_MAKE_TOOLS: thread_id=%s all_tools=%s audit_tools=%s",
            state["thread_id"],
            [t.name for t in all_tools],
            [t.name for t in audit_only_tools],
        )
        pentest_tool_names = {t.name for t in pentest_tools_list}

        escalation_count = state.get("escalation_count") or 0
        last_tool_used = state.get("last_tool_used")
        previous_raw = state.get("raw_results") or ""

        if escalation_count > 0 and last_tool_used in ESCALATION_MAP:
            # Przebieg eskalacyjny: wymuszamy KONKRETNE, głębsze narzędzie
            # na tym samym celu, zamiast pozwalać modelowi wybierać dowolnie.
            forced_tool_name = ESCALATION_MAP[last_tool_used]
            tools_to_use = [t for t in all_tools if t.name == forced_tool_name]
            request_text = (
                f"{state['user_request']}\n\n"
                f"(Kontekst automatyczny: poprzednia próba narzędziem '{last_tool_used}' "
                f"nie znalazła żadnych otwartych portów/usług. Użyj teraz narzędzia "
                f"'{forced_tool_name}' na TYM SAMYM celu, żeby sprawdzić głębiej.)"
            )
            status_store.set_status(
                state["thread_id"], "security_agent",
                f"Pierwsza próba mało informacyjna - eskaluję do: {forced_tool_name}",
            )
        else:
            selected = state.get("selected_tools")
            if selected:
                # Uzytkownik jawnie wybral konkretne narzedzia (w tym ewentualnie
                # ofensywne) - uzywamy DOKLADNIE tego wyboru, bez fallbacku na
                # wszystkie narzedzia, jesli akurat zadna nazwa by sie nie zgodzila.
                tools_to_use = [t for t in all_tools if t.name in selected]
                if not tools_to_use:
                    tools_to_use = audit_only_tools
                else:
                    tool_names_str = ", ".join(t.name for t in tools_to_use)
                    state["user_request"] = (
                        f"{state['user_request']}\n\n"
                        f"WAŻNE: Użytkownik jawnie wybrał w interfejsie następujące "
                        f"narzędzia: {tool_names_str}. MUSISZ wywołać WSZYSTKIE "
                        f"z nich po kolei na podanym celu (chyba że narzędzie "
                        f"oczywiście nie pasuje do typu celu - np. narzędzie webowe "
                        f"na cel bez znanego portu HTTP). NIE kończ pracy po "
                        f"wywołaniu tylko jednego z nich."
                    )
            else:
                # Brak jawnego wyboru w UI = TYLKO narzedzia audytowe.
                # Narzedzia ofensywne (hydra/sqlmap/ffuf/nmap_vuln/nmap_stealth itd.)
                # nigdy nie uruchamiaja sie same - wymagaja jawnego zaznaczenia
                # przez czlowieka w interfejsie.
                tools_to_use = audit_only_tools

            logger.info(
                "SECURITY_NODE_TOOLS_SELECTED: thread_id=%s tools=%s selected=%s",
                state["thread_id"],
                [t.name for t in tools_to_use],
                selected,
            )

            request_text = state["user_request"]
            status_store.set_status(
                state["thread_id"], "security_agent",
                f"Wywołuję narzędzia diagnostyczne: {', '.join(t.name for t in tools_to_use)}",
            )

        is_pentest_mode = any(t.name in pentest_tool_names for t in tools_to_use)
        prompt = SECURITY_AGENT_PROMPT + (PENTEST_ESCALATION_PROMPT if is_pentest_mode else "")

        # ZABEZPIECZENIE: modele (zwlaszcza qwen3:14b jako agent ReAct)
        # obserwowane dzis wielokrotnie wywolujace TO SAMO narzedzie z TYMI
        # SAMYMI parametrami w petli (np. nmap_vuln_scan 5x, whatweb_scan 3x
        # w jednym przebiegu) - marnuje to czas/zasoby bez zadnej korzysci,
        # bo wynik identycznego wywolania jest identyczny. Limitujemy to
        # deterministycznie W KODZIE, nie prosba w prompcie (ktora - jak
        # widzielismy caly dzien - nie daje 100% gwarancji). Po przekroczeniu
        # limitu narzedzie zwraca komunikat zamiast faktycznie sie wykonac,
        # co model widzi jako ToolMessage i (zgodnie z SECURITY_AGENT_PROMPT)
        # powinien przejsc dalej zamiast probowac ponownie.
        MAX_IDENTICAL_CALLS = 1
        _call_counts: dict[tuple, int] = {}

        def _limit_duplicate_calls(tool_obj):
            original_func = tool_obj.func

            def _wrapped(*args, **kwargs):
                key = (tool_obj.name, tuple(sorted(kwargs.items())))
                _call_counts[key] = _call_counts.get(key, 0) + 1
                if _call_counts[key] > MAX_IDENTICAL_CALLS:
                    logger.warning(
                        f"DUPLICATE_CALL_BLOCKED: '{tool_obj.name}' z parametrami {kwargs} "
                        f"wywolane juz {_call_counts[key] - 1} razy - blokuje kolejne powtorzenie "
                        f"(thread_id={state['thread_id']})"
                    )
                    return (
                        f"BŁĄD: narzędzie '{tool_obj.name}' z tymi samymi parametrami zostało już "
                        f"wywołane {MAX_IDENTICAL_CALLS} razy w tym przebiegu i zawsze zwraca ten sam "
                        f"wynik. NIE wywołuj go ponownie z tymi samymi parametrami - użyj już "
                        f"otrzymanego wyniku albo przejdź do innego narzędzia/zakończ."
                    )
                return original_func(*args, **kwargs)

            tool_obj.func = _wrapped
            return tool_obj

        tools_to_use = [_limit_duplicate_calls(t) for t in tools_to_use]

        # ========================================================
        # DETERMINISTYCZNE WYKONANIE JAWNIE WYBRANYCH NARZĘDZI
        #
        # Jeżeli UI podało selected_tools ORAZ parametry narzędzia,
        # nie prosimy LLM o wykonanie tool-calla. Python wykonuje
        # dokładnie wskazane narzędzie z dokładnie przekazanymi
        # parametrami.
        #
        # Dzięki temu:
        #   selected_tools = ["nmap_stealth_scan"]
        #   tool_params = {"nmap_stealth_scan": {"target": "..."}}
        #
        # nie zależy od tego, czy model 8B poprawnie wygeneruje
        # natywny tool call.
        # ========================================================

        selected_params = state.get("tool_params") or {}

        if selected and selected_params:
            selected_set = set(selected)

            # JAWNY WYBÓR Z UI = DOKŁADNIE WYBRANE NARZĘDZIA,
            # W KOLEJNOŚCI PRZEKAZANEJ PRZEZ UI.
            # Bez dodatkowego wyboru przez LLM.
            direct_tools = [
                next(
                    (t for t in tools_to_use if t.name == tool_name),
                    None,
                )
                for tool_name in selected
            ]
            direct_tools = [t for t in direct_tools if t is not None]

            direct_outputs = []
            direct_tool_names = []

            for tool_obj in direct_tools:
                params = selected_params.get(tool_obj.name)

                if params is None:
                    continue

                if not isinstance(params, dict):
                    direct_outputs.append(
                        json.dumps(
                            {
                                "status": "error",
                                "message": (
                                    f"Parametry narzędzia '{tool_obj.name}' "
                                    "muszą być obiektem JSON."
                                ),
                            },
                            ensure_ascii=False,
                        )
                    )
                    direct_tool_names.append(tool_obj.name)
                    continue

                logger.info(
                    f"DIRECT_TOOL_CALL: '{tool_obj.name}' "
                    f"params={params} "
                    f"(thread_id={state['thread_id']})"
                )

                try:
                    # StructuredTool.invoke() wykonuje faktyczną funkcję
                    # narzędzia, bez udziału modelu.
                    result = tool_obj.invoke(params)

                    if isinstance(result, str):
                        output = result
                    else:
                        output = json.dumps(
                            result,
                            ensure_ascii=False,
                            default=str,
                        )

                    direct_outputs.append(output)
                    direct_tool_names.append(tool_obj.name)

                except Exception as exc:
                    logger.exception(
                        f"DIRECT_TOOL_ERROR: '{tool_obj.name}' "
                        f"(thread_id={state['thread_id']})"
                    )
                    direct_outputs.append(
                        json.dumps(
                            {
                                "status": "error",
                                "message": (
                                    f"Wyjątek podczas bezpośredniego "
                                    f"wywołania narzędzia '{tool_obj.name}': "
                                    f"{exc}"
                                ),
                            },
                            ensure_ascii=False,
                        )
                    )
                    direct_tool_names.append(tool_obj.name)

            # Jeżeli znaleźliśmy parametry dla co najmniej jednego
            # wybranego narzędzia, traktujemy ten przebieg jako
            # deterministyczne wykonanie i NIE uruchamiamy ReAct.
            if direct_tool_names:
                new_raw_part = "\n\n".join(direct_outputs)

                from collections import Counter

                call_counts = Counter(direct_tool_names)

                count_lines = [
                    "### ZWERYFIKOWANA LICZBA WYWOŁAŃ NARZĘDZI W TYM PRZEBIEGU "
                    "(NIEPODWAŻALNE, policzone w kodzie)",
                ]

                for tool_name, count in call_counts.items():
                    count_lines.append(
                        f"- {tool_name}: wywołane {count} raz(y)"
                    )

                count_lines.append(
                    "UŻYWAJ WYŁĄCZNIE powyższych liczb, jeśli w raporcie "
                    "wspominasz ile razy narzędzie zostało wykonane."
                )

                new_raw_part += "\n\n" + "\n".join(count_lines)

                last_tool_used_now = direct_tool_names[-1]

                raw_results = (
                    f"{previous_raw}\n\n{new_raw_part}"
                    if previous_raw
                    else new_raw_part
                )

                logger.info(
                    f"DIRECT_TOOL_RESULTS: "
                    f"tools={direct_tool_names}, "
                    f"thread_id={state['thread_id']}"
                )

                return {
                    "raw_results": raw_results,
                    "last_tool_used": last_tool_used_now,
                    "tool_call_count": max(state.get("tool_call_count") or 0, len(direct_tool_names)),
                    "escalation_count": escalation_count,
                }

        logger.info(
            "SECURITY_NODE_BEFORE_REACT_AGENT: thread_id=%s model=%s tools=%s prompt_len=%d",
            state["thread_id"],
            getattr(tool_llm, "model", None),
            [t.name for t in tools_to_use],
            len(prompt),
        )

        security_agent = create_react_agent(
            tool_llm,
            tools=tools_to_use,
            prompt=prompt,
            name="security_agent",
        )

        logger.info(
            "SECURITY_NODE_AFTER_REACT_AGENT: thread_id=%s",
            state["thread_id"],
        )

        def _invoke_agent():
            logger.info(
                "SECURITY_NODE_BEFORE_AGENT_INVOKE: thread_id=%s request_len=%d recursion_limit=%s",
                state["thread_id"],
                len(request_text),
                AGENT_RECURSION_LIMIT,
            )
            try:
                result = security_agent.invoke(
                    {"messages": [{"role": "user", "content": request_text}]},
                    config={"recursion_limit": AGENT_RECURSION_LIMIT},
                )
                logger.info(
                    "SECURITY_NODE_AFTER_AGENT_INVOKE: thread_id=%s messages=%d",
                    state["thread_id"],
                    len(result.get("messages", [])),
                )
                return result
            except GraphRecursionError:
                logger.warning(
                    f"security_agent przekroczył limit {AGENT_RECURSION_LIMIT} kroków "
                    f"(thread_id={state['thread_id']}) - kontynuuję z pustym wynikiem tej próby."
                )
                return {"messages": []}
            except Exception:
                logger.exception(
                    "SECURITY_NODE_AGENT_INVOKE_ERROR: thread_id=%s",
                    state["thread_id"],
                )
                raise

        result = _invoke_agent()
        tool_messages = [m for m in result["messages"] if m.__class__.__name__ == "ToolMessage"]

        # ZABEZPIECZENIE: modele 8B (llama3.1:8b) czasem NIE wywoluja
        # narzedzia przez prawdziwy mechanizm tool-calling, tylko PISZA
        # TEKST wygladajacy jak wywolanie (np. "Oto JSON: {"name": "...",
        # "parameters": {...}}") - to wygenerowalo w praniu KOMPLETNIE
        # zmyslony finalny raport o "wykrytej krytycznej podatnosci SQLi",
        # mimo ze zadne narzedzie sie nie wykonalo (tool_calls=0). Jesli
        # uzytkownik JAWNIE wybral konkretne narzedzia (selected), a mimo
        # to nie doszlo do zadnego prawdziwego wywolania - ponawiamy PRÓBĘ
        # RAZ z dobitniejszym przypomnieniem, zanim uznamy to za twarda
        # porazke.
        if not tool_messages and selected:
            logger.warning(
                f"security_agent NIE wywolal zadnego narzedzia mimo jawnego wyboru "
                f"(thread_id={state['thread_id']}) - ponawiam próbę z dobitniejszym promptem."
            )
            retry_request = (
                f"{request_text}\n\n"
                f"UWAGA: poprzednia próba nie wywołała żadnego narzędzia poprawnie. "
                f"MUSISZ użyć prawdziwego mechanizmu wywołania narzędzia (tool call), "
                f"NIE pisz JSON-a jako zwykły tekst odpowiedzi - to nie działa."
            )
            security_agent_retry = create_react_agent(
                tool_llm, tools=tools_to_use, prompt=prompt, name="security_agent",
            )
            try:
                result = security_agent_retry.invoke(
                    {"messages": [{"role": "user", "content": retry_request}]},
                    config={"recursion_limit": AGENT_RECURSION_LIMIT},
                )
                tool_messages = [m for m in result["messages"] if m.__class__.__name__ == "ToolMessage"]
            except GraphRecursionError:
                pass

        # WAŻNE: nie bierzemy ostatniej wiadomości AI (result["messages"][-1]),
        # bo to jest tekst PRZEPISANY przez model narzędziowy (llama3.1:8b) -
        # a nie dosłowna treść wyniku narzędzia. Model potrafi ją skrócić,
        # sparafrazować albo zgubić fragmenty. Zamiast tego zbieramy dosłowną
        # treść wszystkich ToolMessage z historii - to jedyne prawdziwie
        # surowe dane w tym przebiegu.
        tool_outputs = [m.content for m in tool_messages]

        if not tool_outputs and selected:
            # Nawet retry nie pomógł - TWARDA BLOKADA. Zamiast pozwolić
            # report writerom interpretować tekst modelu (ktory NIE jest
            # prawdziwym wynikiem narzedzia), wstrzykujemy niepodwazalny
            # fakt o calkowitej porazce wywolania. To uniemozliwia
            # jakikolwiek zmyslony raport o "wykrytych podatnosciach".
            logger.error(
                f"security_agent NIE wywolal zadnego narzedzia PO RETRY "
                f"(thread_id={state['thread_id']}) - blokuje dalsze przetwarzanie."
            )
            new_raw_part = (
                "### KRYTYCZNY BŁĄD WYKONANIA (NIEPODWAŻALNE, wygenerowane przez kod)\n"
                "Agent techniczny NIE wywołał żadnego z żądanych narzędzi mimo dwóch prób "
                "- wygenerował tekst przypominający wywołanie funkcji, ale nie użył "
                "prawdziwego mechanizmu tool-calling.\n"
                "BEZWZGLĘDNY ZAKAZ: w tym raporcie NIE WOLNO opisywać żadnych wyników "
                "skanu, podatności, alertów IDS ani jakichkolwiek ustaleń bezpieczeństwa "
                "- ŻADNE narzędzie się nie wykonało, więc nie istnieją żadne dane do "
                "zaraportowania. Napisz WYŁĄCZNIE: błąd techniczny, narzędzia nie zostały "
                "wykonane, poproś użytkownika o ponowienie próby."
            )
            last_tool_used_now = last_tool_used
            raw_results = f"{previous_raw}\n\n{new_raw_part}" if previous_raw else new_raw_part
            return {
                "raw_results": raw_results,
                "last_tool_used": last_tool_used_now,
                "escalation_count": escalation_count,
                "tool_call_count": state.get("tool_call_count") or 0,
            }

        if tool_outputs:
            new_raw_part = "\n\n".join(tool_outputs)
        else:
            new_raw_part = (
                "### BRAK ZWERYFIKOWANYCH WYNIKÓW NARZĘDZI\n"
                "Żadne narzędzie nie dostarczyło wyniku ToolMessage.\n"
                "Tekst wygenerowany przez agenta NIE jest wynikiem narzędzia "
                "i NIE może być traktowany jako fakt diagnostyczny.\n"
                "Nie wolno na jego podstawie raportować portów, usług, podatności, "
                "CVE, alertów ani innych ustaleń bezpieczeństwa."
            )

        # ZABEZPIECZENIE: modele czasem zmyslaja liczbe faktycznych wywolan
        # narzedzia w swoim raporcie (np. "wykonano 7 razy" gdy tool_calls
        # faktycznie wynosilo 2) - to jest halucynacja innego typu niz
        # dotychczas lapane (dotyczy METADANYCH wykonania, nie tresci
        # wyniku). Liczymy to deterministycznie w Pythonie i wstrzykujemy
        # jako niepodwazalny fakt, zamiast liczyc na to ze model poprawnie
        # zliczy wlasna historie wywolan.
        if tool_messages:
            from collections import Counter
            call_counts = Counter(getattr(m, "name", "nieznane") for m in tool_messages)
            count_lines = [
                "### ZWERYFIKOWANA LICZBA WYWOŁAŃ NARZĘDZI W TYM PRZEBIEGU (NIEPODWAŻALNE, policzone w kodzie)",
            ]
            for tool_name, count in call_counts.items():
                count_lines.append(f"- {tool_name}: wywołane {count} raz(y)")
            count_lines.append(
                "UŻYWAJ WYŁĄCZNIE powyższych liczb, jeśli w raporcie wspominasz ile razy "
                "narzędzie zostało wykonane. NIE zmyślaj innej liczby wywołań."
            )
            new_raw_part = new_raw_part + "\n\n" + "\n".join(count_lines)
            logger.info(f"TOOL_CALL_COUNTS: {dict(call_counts)}")

        # Nazwa ostatnio użytego narzędzia - potrzebna dla decyzji o eskalacji.
        # ToolMessage w LangChain ma atrybut .name ustawiony na nazwę narzędzia.
        last_tool_used_now = getattr(tool_messages[-1], "name", None) if tool_messages else last_tool_used

        # Deterministyczny parser firewalla - wstrzykuje gotową, policzoną i
        # sklasyfikowaną tabelę reguł do raw_results, żeby LLM nie musiał
        # ręcznie liczyć/transkrybować surowy `ufw status` (zawodne przy
        # większych zbiorach danych, patrz historia tego pliku).
        firewall_block = extract_and_format_firewall_block(new_raw_part)
        if firewall_block:
            new_raw_part = new_raw_part + "\n\n" + firewall_block
            logger.info(f"FIREWALL_PARSER: wstrzyknięto blok deterministyczny ({len(firewall_block)} znaków)")
        # Deterministyczny parser statusu wykonania narzedzia - wstrzykuje
        # niepodwazalny fakt sukces/blad na podstawie pola "status" w JSON,
        # zeby LLM nie wymyslal wlasnej (bledniej) interpretacji stdout
        # (patrz historia tego pliku - modele halucynowaly nieistniejace
        # kody bledow mimo ze narzedzie zwrocilo "status": "ok").
        tool_status_block = extract_and_format_tool_status_block(new_raw_part)
        if tool_status_block:
            new_raw_part = new_raw_part + "\n\n" + tool_status_block
            logger.info(f"TOOL_STATUS_PARSER: wstrzyknięto blok deterministyczny ({len(tool_status_block)} znaków)")
        # Deterministyczna checklista sekcji - wstrzykuje policzoną liste
        # sekcji obecnych w wielokluczowym wyniku (np. full_audit), zeby
        # model nie gubil calych sekcji przy wielu naraz (patrz historia
        # tego pliku - regresja z full_audit pomijajaca fail2ban/ssh/users/
        # updates/docker/services).
        section_checklist_block = extract_and_format_section_checklist(new_raw_part)
        if section_checklist_block:
            new_raw_part = new_raw_part + "\n\n" + section_checklist_block
            logger.info(f"SECTION_CHECKLIST: wstrzyknięto blok deterministyczny ({len(section_checklist_block)} znaków)")
        # Deterministyczne parsery faktow (updates/users) - patrz facts_parser.py
        # za uzasadnienie. Wyciagaja kluczowe liczby/listy z surowego JSON-a
        # i wstrzykuja krotki, niepodwazalny blok - zamiast pelnego JSON-a,
        # ktory model moze nie zobaczyc w calosci przy duzych promptach.
        updates_block = extract_and_format_updates_block(new_raw_part)
        if updates_block:
            new_raw_part = new_raw_part + "\n\n" + updates_block
            logger.info(f"FACTS_UPDATES: wstrzyknięto blok deterministyczny ({len(updates_block)} znaków)")
        users_block = extract_and_format_users_block(new_raw_part)
        if users_block:
            new_raw_part = new_raw_part + "\n\n" + users_block
            logger.info(f"FACTS_USERS: wstrzyknięto blok deterministyczny ({len(users_block)} znaków)")
        docker_block = extract_and_format_docker_block(new_raw_part)
        if docker_block:
            new_raw_part = new_raw_part + "\n\n" + docker_block
            logger.info(f"FACTS_DOCKER: wstrzyknięto blok deterministyczny ({len(docker_block)} znaków)")
        fail2ban_block = extract_and_format_fail2ban_block(new_raw_part)
        if fail2ban_block:
            new_raw_part = new_raw_part + "\n\n" + fail2ban_block
            logger.info(f"FACTS_FAIL2BAN: wstrzyknięto blok deterministyczny ({len(fail2ban_block)} znaków)")
        ssh_block = extract_and_format_ssh_block(new_raw_part)
        if ssh_block:
            new_raw_part = new_raw_part + "\n\n" + ssh_block
            logger.info(f"FACTS_SSH: wstrzyknięto blok deterministyczny ({len(ssh_block)} znaków)")
        services_block = extract_and_format_services_block(new_raw_part)
        if services_block:
            new_raw_part = new_raw_part + "\n\n" + services_block
            logger.info(f"FACTS_SERVICES: wstrzyknięto blok deterministyczny ({len(services_block)} znaków)")
        ports_block = extract_and_format_ports_block(new_raw_part)
        if ports_block:
            new_raw_part = new_raw_part + "\n\n" + ports_block
            logger.info(f"FACTS_PORTS: wstrzyknięto blok deterministyczny ({len(ports_block)} znaków)")
        nmap_block = extract_and_format_nmap_block(new_raw_part)
        if nmap_block:
            new_raw_part = new_raw_part + "\n\n" + nmap_block
            logger.info(f"FACTS_NMAP: wstrzyknięto blok deterministyczny ({len(nmap_block)} znaków)")
        alerts_block = extract_and_format_alerts_block(new_raw_part)
        if alerts_block:
            new_raw_part = new_raw_part + "\n\n" + alerts_block
            logger.info(f"FACTS_ALERTS: wstrzyknięto blok deterministyczny ({len(alerts_block)} znaków)")
        hydra_block = extract_and_format_hydra_block(new_raw_part)
        if hydra_block:
            new_raw_part = new_raw_part + "\n\n" + hydra_block
            logger.info(f"FACTS_HYDRA: wstrzyknięto blok deterministyczny ({len(hydra_block)} znaków)")
        sqlmap_block = extract_and_format_sqlmap_block(new_raw_part)
        if sqlmap_block:
            new_raw_part = new_raw_part + "\n\n" + sqlmap_block
            logger.info(f"FACTS_SQLMAP: wstrzyknięto blok deterministyczny ({len(sqlmap_block)} znaków)")
        gobuster_block = extract_and_format_gobuster_block(new_raw_part)
        if gobuster_block:
            new_raw_part = new_raw_part + "\n\n" + gobuster_block
            logger.info(f"FACTS_GOBUSTER: wstrzyknięto blok deterministyczny ({len(gobuster_block)} znaków)")
        ffuf_block = extract_and_format_ffuf_block(new_raw_part)
        if ffuf_block:
            new_raw_part = new_raw_part + "\n\n" + ffuf_block
            logger.info(f"FACTS_FFUF: wstrzyknięto blok deterministyczny ({len(ffuf_block)} znaków)")
        enum4linux_block = extract_and_format_enum4linux_block(new_raw_part)
        if enum4linux_block:
            new_raw_part = new_raw_part + "\n\n" + enum4linux_block
            logger.info(f"FACTS_ENUM4LINUX: wstrzyknięto blok deterministyczny ({len(enum4linux_block)} znaków)")
        nikto_block = extract_and_format_nikto_block(new_raw_part)
        if nikto_block:
            new_raw_part = new_raw_part + "\n\n" + nikto_block
            logger.info(f"FACTS_NIKTO: wstrzyknięto blok deterministyczny ({len(nikto_block)} znaków)")

        lynis_block = extract_and_format_lynis_block(new_raw_part)
        if lynis_block:
            new_raw_part = new_raw_part + "\n\n" + lynis_block
            logger.info(f"FACTS_LYNIS: wstrzyknięto blok deterministyczny ({len(lynis_block)} znaków)")

        nuclei_block = extract_and_format_nuclei_block(new_raw_part)
        if nuclei_block:
            new_raw_part = new_raw_part + "\n\n" + nuclei_block
            logger.info(f"FACTS_NUCLEI: wstrzyknięto blok deterministyczny ({len(nuclei_block)} znaków)")
        searchsploit_block = extract_and_format_searchsploit_block(new_raw_part)
        if searchsploit_block:
            new_raw_part = new_raw_part + "\n\n" + searchsploit_block
            logger.info(f"FACTS_SEARCHSPLOIT: wstrzyknięto blok deterministyczny ({len(searchsploit_block)} znaków)")
        testssl_block = extract_and_format_testssl_block(new_raw_part)
        if testssl_block:
            new_raw_part = new_raw_part + "\n\n" + testssl_block
            logger.info(f"FACTS_TESTSSL: wstrzyknięto blok deterministyczny ({len(testssl_block)} znaków)")
        whatweb_block = extract_and_format_whatweb_block(new_raw_part)
        if whatweb_block:
            new_raw_part = new_raw_part + "\n\n" + whatweb_block
            logger.info(f"FACTS_WHATWEB: wstrzyknięto blok deterministyczny ({len(whatweb_block)} znaków)")
        wafw00f_block = extract_and_format_wafw00f_block(new_raw_part)
        if wafw00f_block:
            new_raw_part = new_raw_part + "\n\n" + wafw00f_block
            logger.info(f"FACTS_WAFW00F: wstrzyknięto blok deterministyczny ({len(wafw00f_block)} znaków)")

        exposure_guard_block = extract_and_format_port_exposure_guard(new_raw_part)
        if exposure_guard_block:
            new_raw_part = new_raw_part + "\n\n" + exposure_guard_block
            logger.info(f"FACTS_EXPOSURE_GUARD: wstrzyknięto blok deterministyczny ({len(exposure_guard_block)} znaków)")

        connection_guard_block = extract_and_format_connection_guard(new_raw_part)
        if connection_guard_block:
            new_raw_part = new_raw_part + "\n\n" + connection_guard_block
            logger.info(f"FACTS_CONNECTION_GUARD: wstrzyknięto blok deterministyczny ({len(connection_guard_block)} znaków)")

        # Kompresja: USUWAMY obszerne, juz przetworzone surowe dane (stdout
        # dockera/services/firewalla, pelna liste alertow) - zostawiamy
        # tylko krotkie bloki faktow wygenerowane powyzej. Musi biec na
        # samym koncu, po wszystkich innych parserach.
        size_before_compact = len(new_raw_part)
        new_raw_part = compact_raw_results(new_raw_part)
        size_after_compact = len(new_raw_part)
        logger.info(
            f"COMPACT_RAW: {size_before_compact} -> {size_after_compact} znaków "
            f"(oszczedność: {size_before_compact - size_after_compact} znaków)"
        )

        raw_results = f"{previous_raw}\n\n{new_raw_part}" if previous_raw else new_raw_part

        logger.info(
            f"RAW_RESULTS (len={len(raw_results)}, tool_calls={len(tool_outputs)}, "
            f"last_tool={last_tool_used_now}, escalation_count={escalation_count}): {raw_results}"
        )
        logger.info(
            "SECURITY_NODE_OUTPUT: thread_id=%s raw_len=%d artifact_re=%s "
            "tool_call_count=%d last_tool=%s",
            state["thread_id"],
            len(raw_results),
            "ARTIFACT_RE_RESULTS" in raw_results,
            len(tool_messages),
            last_tool_used_now,
        )
        return {
            "raw_results": raw_results,
            "last_tool_used": last_tool_used_now,
            "tool_call_count": max(state.get("tool_call_count") or 0, len(tool_messages)),
            "escalation_count": escalation_count,
            # Snapshot sprzed compact_raw_results() - ten sam firewall_block
            # ktory dopiero co zostal wstrzykniety do new_raw_part. Jesli w
            # tej iteracji nie bylo nowych danych firewalla, zachowujemy
            # poprzedni snapshot zamiast go kasowac.
            "firewall_facts_snapshot": firewall_block or state.get("firewall_facts_snapshot") or "",
            "docker_facts_snapshot": docker_block or state.get("docker_facts_snapshot") or "",
            "services_facts_snapshot": services_block or state.get("services_facts_snapshot") or "",
            "lynis_facts_snapshot": lynis_block or state.get("lynis_facts_snapshot") or "",
            "nuclei_facts_snapshot": nuclei_block or state.get("nuclei_facts_snapshot") or "",
            "searchsploit_facts_snapshot": searchsploit_block or state.get("searchsploit_facts_snapshot") or "",
            "testssl_facts_snapshot": testssl_block or state.get("testssl_facts_snapshot") or "",
        }

    def escalate_prep_node(state: AuditState):
        """Mały węzeł-licznik: tylko podbija escalation_count przed powrotem
        do security_agent. Rozdzielenie tej odpowiedzialności od decide_after_security
        pozwala tamtej funkcji zostać CZYSTĄ funkcją routingu (LangGraph wymaga,
        żeby funkcje warunkowych krawędzi tylko zwracały nazwę węzła, nie
        mutowały stanu)."""
        return {"escalation_count": (state.get("escalation_count") or 0) + 1}

    def decide_after_security(state: AuditState) -> str:
        escalation_count = state.get("escalation_count") or 0
        last_tool_used = state.get("last_tool_used")

        if escalation_count < MAX_ESCALATIONS and last_tool_used in ESCALATION_MAP:
            if _looks_uninformative(state.get("raw_results") or ""):
                logger.info(
                    f"ESKALACJA: '{last_tool_used}' dał mało informacyjny wynik - "
                    f"przechodzę do '{ESCALATION_MAP[last_tool_used]}' (thread_id={state['thread_id']})"
                )
                return "escalate"

        if last_tool_used in DETECTION_CHECK_TOOLS and not state.get("detection_checked"):
            logger.info(
                f"WERYFIKACJA DETEKCJI: '{last_tool_used}' użyty - sprawdzam alarmy "
                f"Wazuh/Suricata (thread_id={state['thread_id']})"
            )
            return "check_detection"

        return "continue"

    def check_detection_node(state: AuditState):
        status_store.set_status(
            state["thread_id"], "check_detection",
            f"Weryfikuję czy system detekcji zauważył skan (czekam {DETECTION_CHECK_DELAY_SECONDS}s)...",
        )
        time.sleep(DETECTION_CHECK_DELAY_SECONDS)

        alerts_result = _call_admin_agent("check_recent_alerts")
        alerts_block = (
            "\n\n### WERYFIKACJA DETEKCJI (Wazuh/Suricata) - sprawdzone automatycznie po skanie\n"
            f"{json.dumps(alerts_result, ensure_ascii=False)}"
        )
        raw_results = (state.get("raw_results") or "") + alerts_block
        logger.info(f"DETECTION_CHECK: {alerts_block}")

        return {"raw_results": raw_results, "detection_checked": True}

    def report_writers_node(state: AuditState):
        # TWARDY GUARD: bez rzeczywistych danych z narzędzi nie generujemy raportu.
        raw_results = (state.get("raw_results") or "").strip()
        logger.info(
            "REPORT_WRITER_INPUT: thread_id=%s raw_len=%d artifact_re=%s",
            state["thread_id"],
            len(raw_results),
            "ARTIFACT_RE_RESULTS" in raw_results,
        )
        tool_call_count = int(state.get("tool_call_count") or 0)

        if not raw_results or tool_call_count <= 0:
            logger.warning(
                f"REPORT_BLOCKED_NO_TOOL_DATA: brak raw_results "
                f"(thread_id={state['thread_id']})"
            )
            return {
                "draft_reports": [{
                    "model": "deterministic_guard",
                    "report": (
                        "BRAK DANYCH Z NARZĘDZI. "
                        "Nie wykonano żadnego narzędzia, więc nie można "
                        "potwierdzić żadnych ustaleń bezpieczeństwa."
                    ),
                }]
            }

        drafts = []
        total = len(REPORT_MODEL_NAMES)
        for idx, model_name in enumerate(REPORT_MODEL_NAMES, start=1):
            model_name = model_name.strip()
            status_store.set_status(
                state["thread_id"], "report_writers",
                f"Piszę szkic raportu: {model_name} ({idx}/{total})",
            )
            llm = ChatOllama(model=model_name, base_url=OLLAMA_BASE_URL, temperature=0.3, num_ctx=32768,
            client_kwargs={"timeout": httpx.Timeout(600.0, connect=10.0)})
            prompt = (
                f"{REPORT_PROMPT}\n\n"
                "=== TWARDY KONTRAKT DOWODOWY ===\n"
                "RAW_RESULTS jest JEDYNYM źródłem faktów.\n"
                "Nie wolno wymyślać wyników narzędzi, portów, usług, "
                "podatności, CVE, wersji, użytkowników ani konfiguracji.\n"
                "Nie wolno traktować wiedzy modelu ani treści prośby użytkownika "
                "jako dowodu.\n"
                "Jeżeli faktu nie ma w RAW_RESULTS, oznacz go jako "
                "NIE ZWERYFIKOWANO i nie przedstawiaj go jako ustalenia.\n"
                "Każde ustalenie bezpieczeństwa musi wynikać bezpośrednio "
                "z RAW_RESULTS.\n"
                "=== KONIEC KONTRAKTU ===\n\n"
                f"Prośba użytkownika: {state['user_request']}\n\n"
                f"RAW_RESULTS (JEDYNE ŹRÓDŁO DOWODÓW):\n{raw_results}"
            )
            logger.info(f"PROMPT_SIZE[{model_name}]: {len(prompt)} znakow (prompt do report writera)")
            response = llm.invoke(prompt)
            meta = response.response_metadata
            logger.info(
                f"TOKEN_USAGE[{model_name}]: prompt_eval_count={meta.get('prompt_eval_count')}, "
                f"eval_count={meta.get('eval_count')}, num_ctx_configured=32768"
            )
            drafts.append({"model": model_name, "report": response.content})
        return {"draft_reports": drafts}


    def build_deterministic_critic_facts(state: AuditState) -> str:
        """
        JEDYNY blok faktograficzny przekazywany criticowi.

        Wszystkie wartości techniczne muszą pochodzić z parserów deterministycznych.
        Critic NIE interpretuje surowego stdout jako źródła faktów.
        """
        raw = (state.get("raw_results") or "").strip()

        facts = []

        # Istniejące deterministyczne ekstraktory.
        extractors = [
            ("PORTS", extract_and_format_ports_block),
            ("NMAP", extract_and_format_nmap_block),
            ("HYDRA", extract_and_format_hydra_block),
            ("SQLMAP", extract_and_format_sqlmap_block),
            ("GOBUSTER", extract_and_format_gobuster_block),
            ("FFUF", extract_and_format_ffuf_block),
            ("ENUM4LINUX", extract_and_format_enum4linux_block),
            ("NIKTO", extract_and_format_nikto_block),
            ("CONNECTION_GUARD", extract_and_format_connection_guard),
        ]

        for name, extractor in extractors:
            try:
                block = extractor(raw)
            except Exception as exc:
                logger.exception("CRITIC_FACTS extractor %s failed: %s", name, exc)
                block = None

            if block:
                facts.append(f"### FACTS_{name}\n{block}")

        # Istniejące parsery/importy - jeśli funkcja istnieje w tej wersji.
        optional_extractors = [
            ("SEARCHSPLOIT", "extract_and_format_searchsploit_block"),
            ("TESTSSL", "extract_and_format_testssl_block"),
            ("EXPOSURE_GUARD", "extract_and_format_port_exposure_guard"),
            ("FIREWALL", "extract_and_format_firewall_block"),
            ("SECTION_CHECKLIST", "extract_and_format_section_checklist"),
            ("DOCKER", "extract_and_format_docker_block"),
            ("SERVICES", "extract_and_format_services_block"),
            ("LYNIS", "extract_and_format_lynis_block"),
            ("NUCLEI", "extract_and_format_nuclei_block"),
            ("WHATWEB", "extract_and_format_whatweb_block"),
            ("WAFW00F", "extract_and_format_wafw00f_block"),
        ]

        module_globals = globals()

        for name, fn_name in optional_extractors:
            fn = module_globals.get(fn_name)
            if not fn:
                continue

            try:
                block = fn(raw)
            except Exception as exc:
                logger.exception("CRITIC_FACTS extractor %s failed: %s", name, exc)
                block = None

            # FALLBACK: compact_raw_results() zastepuje surowy stdout
            # placeholderem PO tym jak security_node juz raz poprawnie
            # sparsowal dany blok. Ponowne parsowanie tutaj (na skompaktowanym
            # raw) zwraca wiec pustke. Uzywamy snapshotu zapisanego przed
            # kompaktowaniem zamiast cichej utraty danych. Dotyczy wszystkich
            # blokow ktore _reduce_bulky_fields() moze podmienic na placeholder.
            SNAPSHOT_KEYS = {
                "FIREWALL": "firewall_facts_snapshot",
                "DOCKER": "docker_facts_snapshot",
                "SERVICES": "services_facts_snapshot",
                "LYNIS": "lynis_facts_snapshot",
                "NUCLEI": "nuclei_facts_snapshot",
                "SEARCHSPLOIT": "searchsploit_facts_snapshot",
                "TESTSSL": "testssl_facts_snapshot",
            }
            if not block and name in SNAPSHOT_KEYS:
                snapshot = state.get(SNAPSHOT_KEYS[name])
                if snapshot:
                    block = snapshot
                    logger.info(
                        "CRITIC_FACTS: %s odtworzony z %s "
                        "(raw juz skompaktowany, ponowne parsowanie zwrocilo pustke)",
                        name, SNAPSHOT_KEYS[name],
                    )

            if block:
                facts.append(f"### FACTS_{name}\n{block}")

        if not facts:
            return (
                "### DETERMINISTIC_FACTS\n"
                "Brak wyodrębnionych faktów deterministycznych.\n"
                "Nie wolno wyprowadzać faktów technicznych z wiedzy modelu."
            )

        return (
            "### DETERMINISTIC_FACTS\n"
            "Poniższe dane są jedynym autorytatywnym źródłem faktów "
            "technicznych dla raportu.\n\n"
            + "\n\n".join(facts)
        )

    def critic_node(state: AuditState):
        # TWARDY GUARD: critic nie może wygenerować ustaleń,
        # jeżeli nie istnieją rzeczywiste wyniki narzędzi.
        raw_results = (state.get("raw_results") or "").strip()
        logger.info(
            "CRITIC_INPUT: thread_id=%s raw_len=%d artifact_re=%s",
            state["thread_id"],
            len(raw_results),
            "ARTIFACT_RE_RESULTS" in raw_results,
        )
        tool_call_count = int(state.get("tool_call_count") or 0)

        if not raw_results or tool_call_count <= 0:
            logger.warning(
                f"CRITIC_BLOCKED_NO_TOOL_DATA: brak raw_results "
                f"(thread_id={state['thread_id']})"
            )
            return {
                "final_report": (
                    "BRAK DANYCH Z NARZĘDZI.\n\n"
                    "Nie wykonano żadnego narzędzia, więc nie można "
                    "potwierdzić żadnych ustaleń bezpieczeństwa."
                )
            }

        status_store.set_status(
            state["thread_id"], "critic",
            f"Recenzent opisuje deterministyczne fakty: {CRITIC_MODEL_NAME}",
        )

        critic_llm = ChatOllama(
            model=CRITIC_MODEL_NAME,
            base_url=OLLAMA_BASE_URL,
            temperature=0,
            num_ctx=16384,
        
            client_kwargs={"timeout": httpx.Timeout(600.0, connect=10.0)},)

        deterministic_facts = build_deterministic_critic_facts(state)

        drafts_text = "\n\n".join(
            f"--- Szkic od modelu: {d['model']} ---\n{d['report']}"
            for d in state.get("draft_reports", [])
        )

        prompt = f"""
Jesteś WYŁĄCZNIE redaktorem końcowego raportu bezpieczeństwa.

Twoja rola NIE polega na odkrywaniu ani ustalaniu faktów.

FUNKCJA:
- opisz poprawnie fakty przekazane w DETERMINISTIC_FACTS,
- uporządkuj je,
- połącz je w czytelny raport po polsku,
- możesz porównać szkice i wybrać lepsze sformułowania,
- możesz wskazać, że czegoś nie potwierdzono,
- możesz zasugerować kolejne narzędzia lub działania diagnostyczne,
- możesz zasugerować rozwiązania problemu.

ABSOLUTNY ZAKAZ HALUCYNACJI:
- NIE dodawaj żadnego portu,
- NIE dodawaj żadnej usługi,
- NIE dodawaj wersji,
- NIE dodawaj CVE,
- NIE dodawaj podatności,
- NIE dodawaj adresu IP,
- NIE dodawaj użytkownika,
- NIE dodawaj konfiguracji,
- NIE dodawaj liczby,
- NIE dodawaj wyniku narzędzia,
jeżeli nie występuje to w DETERMINISTIC_FACTS.

SZKICE NIE SĄ ŹRÓDŁEM PRAWDY.
Jeżeli szkic zawiera informację, której nie ma w DETERMINISTIC_FACTS:
USUŃ JĄ.

WIEDZA WŁASNA MODELU NIE JEST DOWODEM.
Nie wolno uzupełniać brakujących informacji wiedzą ogólną.

KRYTYCZNA ZASADA:
Jeżeli czegoś nie ma w DETERMINISTIC_FACTS, napisz:
"NIE ZWERYFIKOWANO"
zamiast zgadywać.

SUGESTIE:
Możesz proponować kolejne narzędzia i działania, ale sugestia NIE jest wynikiem
wykonanego narzędzia. Oznacz ją jako "SUGESTIA".

Przykład:
"SUGESTIA: wykonać nmap_vuln_scan w celu dalszej weryfikacji."

Nie pisz:
"nmap_vuln_scan wykazał ...",
jeżeli tego faktu nie ma w DETERMINISTIC_FACTS.

=== KONIEC KONTRAKTU ===

PROŚBA UŻYTKOWNIKA:
{state["user_request"]}

{deterministic_facts}

SZKICE — TYLKO DO REDAKCJI:
{drafts_text}

Napisz wyłącznie finalny raport po polsku.
"""

        logger.info(f"PROMPT_SIZE[critic/{CRITIC_MODEL_NAME}]: {len(prompt)} znakow (prompt do critica)")
        response = critic_llm.invoke(prompt)

        # HARD EVIDENCE SANITIZER:
        # critic nie może wprowadzać faktów technicznych spoza RAW_RESULTS.
        final_report = response.content

        # Usuń znany typ halucynacji: numer wersji Nmap potraktowany
        # jako wersja Apache.
        final_report = final_report.replace(
            "wersji 7.99",
            "wersji nieustalonej"
        )
        final_report = final_report.replace(
            "wersję 7.99",
            "wersję nieustaloną"
        )
        final_report = final_report.replace(
            "Apache 7.99",
            "Apache w wersji nieustalonej"
        )

        # RAW_RESULTS z tego audytu zawiera tylko Apache 2.4.25.
        # Jeżeli raport twierdzi inaczej, normalizujemy wersję.
        if "Apache httpd 2.4.25" in raw_results:
            final_report = final_report.replace(
                "Apache 7.99",
                "Apache 2.4.25"
            )

        # CVE wolno podać tylko wtedy, gdy konkretny numer CVE
        # występuje w RAW_RESULTS.
        import re
        raw_cves = set(re.findall(r"CVE-\\d{4}-\\d{4,7}", raw_results))
        report_cves = set(re.findall(r"CVE-\\d{4}-\\d{4,7}", final_report))

        for cve in report_cves - raw_cves:
            final_report = final_report.replace(
                cve,
                f"{cve} (NIE ZWERYFIKOWANO w danych skanu)"
            )

        # FIREWALL_COMPLETENESS_GUARD:
        # Critic ma udokumentowana tendencje do skracania dlugich list
        # (np. 45 regul firewalla) mimo wyraznej instrukcji w FACTS_FIREWALL
        # zeby przepisac WSZYSTKIE pozycje. Zamiast ufac posluszenstwu modelu,
        # weryfikujemy to w kodzie: liczymy realne wystapienia "RYZYKO:" w
        # finalnym raporcie i porownujemy z liczba referencyjna z parsera
        # deterministycznego. Jesli sie nie zgadza - doklejamy PELNA tabele
        # jako osobna, JAWNIE OZNACZONA sekcje (nie mieszamy bezszwowo z
        # tekstem LLM, zeby bylo widac co jest danymi automatycznymi a co
        # interpretacja modelu).
        try:
            firewall_block_for_check = extract_and_format_firewall_block(raw_results)
        except Exception as exc:
            logger.exception("FIREWALL_COMPLETENESS_GUARD: blad parsera: %s", exc)
            firewall_block_for_check = None

        if not firewall_block_for_check:
            firewall_block_for_check = state.get("firewall_facts_snapshot") or None
            if firewall_block_for_check:
                logger.info(
                    "FIREWALL_COMPLETENESS_GUARD: raw_results juz skompaktowany, "
                    "uzywam firewall_facts_snapshot"
                )

        if firewall_block_for_check:
            ref_match = re.search(
                r"Liczba referencyjna do weryfikacji: dokładnie (\d+) regu",
                firewall_block_for_check,
            )
            if ref_match:
                expected_rules = int(ref_match.group(1))
                actual_rules = final_report.count("RYZYKO:")
                if actual_rules != expected_rules:
                    logger.warning(
                        "FIREWALL_COMPLETENESS_GUARD: raport zawiera %d/%d regul "
                        "firewalla - doklejam pelna tabele deterministyczna",
                        actual_rules, expected_rules,
                    )
                    final_report += (
                        "\n\n---\n\n"
                        "## Pełna lista reguł firewalla (dane automatyczne, zweryfikowane)\n\n"
                        "Uwaga: powyższa sekcja raportu (wygenerowana przez model) "
                        f"wymieniła {actual_rules} z {expected_rules} reguł z surowego "
                        "`ufw status verbose`. Poniższa tabela jest wstawiona "
                        "automatycznie przez kod deterministyczny, NIE przez model "
                        "językowy, i zawiera KOMPLETNĄ listę:\n\n"
                        + firewall_block_for_check
                    )
                else:
                    logger.info(
                        "FIREWALL_COMPLETENESS_GUARD: OK (%d/%d regul w raporcie)",
                        actual_rules, expected_rules,
                    )

        # LYNIS_COMPLETENESS_GUARD:
        # Analogicznie do FIREWALL_COMPLETENESS_GUARD - Lynis potrafi miec
        # dziesiatki pozycji (ostrzezenia + sugestie), a Critic ma
        # udokumentowana tendencje do ich grupowania/skracania mimo
        # instrukcji "wypisz wszystkie". Liczymy realne wystapienia kodow
        # testow Lynis (np. [SSH-7408]) w finalnym raporcie i porownujemy
        # z suma zadeklarowana w FACTS_LYNIS.
        try:
            lynis_block_for_check = extract_and_format_lynis_block(raw_results)
        except Exception as exc:
            logger.exception("LYNIS_COMPLETENESS_GUARD: blad parsera: %s", exc)
            lynis_block_for_check = None

        if not lynis_block_for_check:
            lynis_block_for_check = state.get("lynis_facts_snapshot") or None
            if lynis_block_for_check:
                logger.info(
                    "LYNIS_COMPLETENESS_GUARD: raw_results juz skompaktowany, "
                    "uzywam lynis_facts_snapshot"
                )

        if lynis_block_for_check:
            warn_match = re.search(
                r"Liczba ostrzezen \(warnings\):\s*(\d+)",
                lynis_block_for_check,
            )
            sugg_match = re.search(
                r"Liczba sugestii \(suggestions\):\s*(\d+)",
                lynis_block_for_check,
            )
            if warn_match and sugg_match:
                expected_total = int(warn_match.group(1)) + int(sugg_match.group(1))
                actual_total = len(re.findall(r"\[[A-Z]+-\d{4}\]", final_report))
                if actual_total < expected_total:
                    logger.warning(
                        "LYNIS_COMPLETENESS_GUARD: raport zawiera %d/%d pozycji "
                        "Lynis (ostrzezenia+sugestie) - doklejam pelna tabele "
                        "deterministyczna",
                        actual_total, expected_total,
                    )
                    final_report += (
                        "\n\n---\n\n"
                        "## Pełny wynik audytu Lynis (dane automatyczne, zweryfikowane)\n\n"
                        "Uwaga: powyższa sekcja raportu (wygenerowana przez model) "
                        f"wymieniła {actual_total} z {expected_total} pozycji "
                        "(ostrzeżenia + sugestie) z surowego wyniku Lynis. "
                        "Poniższy blok jest wstawiony automatycznie przez kod "
                        "deterministyczny, NIE przez model językowy, i zawiera "
                        "KOMPLETNĄ listę:\n\n"
                        + lynis_block_for_check
                    )
                else:
                    logger.info(
                        "LYNIS_COMPLETENESS_GUARD: OK (%d/%d pozycji w raporcie)",
                        actual_total, expected_total,
                    )

        # NUCLEI_COMPLETENESS_GUARD
        try:
            nuclei_block_for_check = extract_and_format_nuclei_block(raw_results)
        except Exception as exc:
            logger.exception("NUCLEI_COMPLETENESS_GUARD: blad parsera: %s", exc)
            nuclei_block_for_check = None
        if not nuclei_block_for_check:
            nuclei_block_for_check = state.get("nuclei_facts_snapshot") or None
            if nuclei_block_for_check:
                logger.info("NUCLEI_COMPLETENESS_GUARD: raw juz skompaktowany, uzywam snapshotu")
        if nuclei_block_for_check:
            m = re.search(r"Liczba znalezisk:\s*(\d+)", nuclei_block_for_check)
            if m:
                expected = int(m.group(1))
                actual = len(re.findall(r"\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\]", final_report))
                if actual < expected:
                    logger.warning(
                        "NUCLEI_COMPLETENESS_GUARD: raport zawiera %d/%d znalezisk - doklejam pelna liste",
                        actual, expected,
                    )
                    final_report += (
                        "\n\n---\n\n"
                        "## Pelny wynik skanu Nuclei (dane automatyczne, zweryfikowane)\n\n"
                        f"Uwaga: powyzsza sekcja raportu wymienila {actual} z {expected} znalezisk. "
                        "Ponizszy blok jest wstawiony automatycznie przez kod deterministyczny:\n\n"
                        + nuclei_block_for_check
                    )
                else:
                    logger.info("NUCLEI_COMPLETENESS_GUARD: OK (%d/%d)", actual, expected)

        # SEARCHSPLOIT_COMPLETENESS_GUARD
        try:
            searchsploit_block_for_check = extract_and_format_searchsploit_block(raw_results)
        except Exception as exc:
            logger.exception("SEARCHSPLOIT_COMPLETENESS_GUARD: blad parsera: %s", exc)
            searchsploit_block_for_check = None
        if not searchsploit_block_for_check:
            searchsploit_block_for_check = state.get("searchsploit_facts_snapshot") or None
            if searchsploit_block_for_check:
                logger.info("SEARCHSPLOIT_COMPLETENESS_GUARD: raw juz skompaktowany, uzywam snapshotu")
        if searchsploit_block_for_check:
            m = re.search(r"Liczba znalezionych exploitow:\s*(\d+)", searchsploit_block_for_check)
            if m:
                expected = int(m.group(1))
                actual = len(re.findall(r"\[EDB-ID ", final_report))
                if actual < expected:
                    logger.warning(
                        "SEARCHSPLOIT_COMPLETENESS_GUARD: raport zawiera %d/%d exploitow - doklejam pelna liste",
                        actual, expected,
                    )
                    final_report += (
                        "\n\n---\n\n"
                        "## Pelna lista exploitow Searchsploit (dane automatyczne, zweryfikowane)\n\n"
                        f"Uwaga: powyzsza sekcja raportu wymienila {actual} z {expected} exploitow. "
                        "Ponizszy blok jest wstawiony automatycznie przez kod deterministyczny:\n\n"
                        + searchsploit_block_for_check
                    )
                else:
                    logger.info("SEARCHSPLOIT_COMPLETENESS_GUARD: OK (%d/%d)", actual, expected)

        # TESTSSL_COMPLETENESS_GUARD
        try:
            testssl_block_for_check = extract_and_format_testssl_block(raw_results)
        except Exception as exc:
            logger.exception("TESTSSL_COMPLETENESS_GUARD: blad parsera: %s", exc)
            testssl_block_for_check = None
        if not testssl_block_for_check:
            testssl_block_for_check = state.get("testssl_facts_snapshot") or None
            if testssl_block_for_check:
                logger.info("TESTSSL_COMPLETENESS_GUARD: raw juz skompaktowany, uzywam snapshotu")
        if testssl_block_for_check:
            m = re.search(r"pozycji WYMAGAJACYCH UWAGI[^:]*:\s*(\d+)", testssl_block_for_check)
            if m:
                expected = int(m.group(1))
                actual = len(re.findall(r"^\s*-\s*\[[A-Z_]+\]", final_report, re.MULTILINE))
                if actual < expected:
                    logger.warning(
                        "TESTSSL_COMPLETENESS_GUARD: raport zawiera %d/%d pozycji - doklejam pelna liste",
                        actual, expected,
                    )
                    final_report += (
                        "\n\n---\n\n"
                        "## Pelny wynik audytu TLS/SSL - testssl (dane automatyczne, zweryfikowane)\n\n"
                        f"Uwaga: powyzsza sekcja raportu wymienila {actual} z {expected} pozycji. "
                        "Ponizszy blok jest wstawiony automatycznie przez kod deterministyczny:\n\n"
                        + testssl_block_for_check
                    )
                else:
                    logger.info("TESTSSL_COMPLETENESS_GUARD: OK (%d/%d)", actual, expected)

        meta = response.response_metadata
        logger.info(
            f"TOKEN_USAGE[critic/{CRITIC_MODEL_NAME}]: prompt_eval_count={meta.get('prompt_eval_count')}, "
            f"eval_count={meta.get('eval_count')}, num_ctx_configured=16384"
        )
        # WAZNE: NIE ustawiamy tu stage="done" - to musi zrobic set_result()
        # w app.py, ATOMOWO razem z tresc raportu (result). W przeciwnym
        # razie powstaje luka czasowa: frontend widzi stage="done" (bo tu
        # bylo ustawiane od razu), przestaje odpytywac, ale result jeszcze
        # nie istnieje w status_store (bo set_result() w app.py wywoluje sie
        # dopiero PO _extract_suggested_tools(), ktore robi dodatkowe HTTP
        # zapytania do pentest-agenta) - stad "(brak tresci raportu)" mimo
        # ze pipeline faktycznie sie zakonczyl poprawnie.
        status_store.set_status(state["thread_id"], "critic", "Finalizuję raport...")
        return {"final_report": final_report}

    graph = StateGraph(AuditState)
    graph.add_node("artifact_re", load_artifact_re_node)
    graph.add_node("security_agent", security_node)
    graph.add_node("escalate_prep", escalate_prep_node)
    graph.add_node("check_detection", check_detection_node)
    graph.add_node("report_writers", report_writers_node)
    graph.add_node("critic", critic_node)

    graph.add_edge(START, "artifact_re")
    graph.add_edge("artifact_re", "security_agent")
    graph.add_conditional_edges(
        "security_agent",
        decide_after_security,
        {
            "escalate": "escalate_prep",
            "check_detection": "check_detection",
            "continue": "report_writers",
        },
    )
    graph.add_edge("escalate_prep", "security_agent")
    graph.add_edge("check_detection", "report_writers")
    graph.add_edge("report_writers", "critic")
    graph.add_edge("critic", END)

    checkpointer = MemorySaver()
    return graph.compile(checkpointer=checkpointer)


def get_model_config():
    return {
        "tool_model": TOOL_MODEL_NAME,
        "report_models": [m.strip() for m in REPORT_MODEL_NAMES],
        "critic_model": CRITIC_MODEL_NAME,
    }
