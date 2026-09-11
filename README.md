# Cybersec Agent

System wspomagający audyt bezpieczeństwa oraz testy penetracyjne (pentesting) sieci lokalnej, oparty o wieloagentowy potok (pipeline) wykorzystujący lokalnie hostowane modele językowe (LLM).

> **Status:** projekt rozwojowy / portfolio. Zbudowany i testowany na własnej infrastrukturze (Docker + lokalne modele Ollama). Lista znanych ograniczeń i planowanych prac — patrz sekcja [Znane ograniczenia i dalsze prace](#znane-ograniczenia-i-dalsze-prace).

---

## Cel i założenia projektu

Celem projektu było zaprojektowanie i wdrożenie systemu wspomagającego audyt bezpieczeństwa oraz testy penetracyjne sieci lokalnej, opartego o wieloagentowy potok przetwarzania (pipeline) wykorzystujący lokalnie hostowane modele językowe (LLM).

Głównym założeniem architektonicznym jest zasada **„deterministic-first”**: wszystkie fakty techniczne (liczby, nazwy, wersje oprogramowania, wyniki narzędzi diagnostycznych) są wyodrębniane z danych surowych przez deterministyczny kod w języku Python, natomiast modele językowe pełnią wyłącznie rolę redakcyjną — porządkują, opisują i formułują rekomendacje, nie interpretując samodzielnie danych liczbowych.

Podejście to eliminuje klasę błędów wynikającą z udokumentowanej tendencji modeli językowych do pomijania, zniekształcania lub zmyślania fragmentów danych przy przetwarzaniu długich, technicznych wyników narzędzi bezpieczeństwa (tzw. halucynacje). Zjawisko to zostało w projekcie potwierdzone empirycznie i wielokrotnie — patrz [Walka z halucynacjami LLM](#walka-z-halucynacjami-llm).

---

## Architektura systemu

![Diagram architektury](docs/architektura.png)

- **Interfejs użytkownika (chat-ui)** — panel czatu, wybór narzędzi i trybu (audyt / pentesting), panel findingów
- **Orchestrator (FastAPI + LangGraph)** — logika przepływu, ok. 20 deterministycznych parserów danych, budowa promptów, kaskadowy potok modeli
- **Pentest-agent** — wykonywanie narzędzi ofensywnych w izolowanym środowisku, z centralnym rejestrem narzędzi i walidacją celu (allowlist)
- **Admin-agent** — usługa systemowa na hoście, diagnostyka przez ograniczony (whitelistowany) dostęp do poleceń administracyjnych (`sudo`)
- **Warstwa Evidence/Findings** — model danych i magazyn trwały dla ustaleń bezpieczeństwa, z pełnym cyklem życia: wykrycie → walidacja → ocena ryzyka → retest
- **Internal Sensor** — pasywne wykrywanie zasobów (hostów) w sieci lokalnej
- **Potok wieloetapowy** — 1 model wykonujący narzędzia → N niezależnych modeli piszących szkice raportu → 1 model-recenzent (*critic*) porównujący szkice z danymi źródłowymi i tworzący raport końcowy

---

## Wykorzystane technologie i narzędzia

- **Backend:** Python 3.11, FastAPI, Pydantic
- **Orkiestracja LLM:** LangGraph, LangChain (langchain-ollama)
-- **Modele językowe (Ollama, lokalnie):** qwen3:14b (agent narzędziowy), qwen2.5-coder:14b i Bielik-11B-v3.0-instruct:Q5_K_M (szkicownicy raportu), qwen2.5:14b (dodatkowy szkicownik + model-recenzent/critic)
- **Infrastruktura:** Docker, Docker Compose
- **Frontend:** własny (HTML / CSS / JavaScript)
- **Narzędzia ofensywne:** sqlmap, gobuster, ffuf, nikto, enum4linux, nmap, hydra, wafw00f, whatweb, nuclei, searchsploit, testssl.sh
- **Diagnostyka hosta:** ufw, fail2ban, systemd, Lynis, Wazuh, Suricata
- **Reverse engineering / analiza artefaktów:** ssdeep (fuzzy hashing), YARA, binwalk, binutils (readelf/nm/objdump)
- **SAST:** Semgrep
- **Zewnętrzne źródła danych:** MalwareBazaar (abuse.ch)
- **Magazyn danych:** JSON Lines, model danych Pydantic (RawResult, Observation, Evidence, Finding, Validation, RiskAssessment, RetestResult, Asset, Artifact)
- **Diagramy:** Mermaid, draw.io

---

## Walka z halucynacjami LLM

W trakcie rozwoju projektu empirycznie potwierdzono i rozwiązano kilka niezależnych, powtarzalnych kategorii błędów generowania tekstu przez modele językowe przy przetwarzaniu długich, technicznych wyników narzędzi:

1. **Utrata danych przy transkrypcji reguł zapory sieciowej (firewall)** — model gubił/grupował pozycje mimo jawnej instrukcji w prompcie. *Rozwiązanie:* deterministyczny parser + automatyczna weryfikacja kompletności w warstwie recenzenta.
2. **Utrata danych przy transkrypcji wyniku audytu systemowego (Lynis)** — analogiczny problem przy dziesiątkach pozycji ostrzeżeń/sugestii. *Rozwiązanie:* analogiczny mechanizm jak dla firewalla.
3. **Błędne zliczanie liczby wykonanych wywołań narzędzi** — model deklarował inną liczbę niż faktyczna. *Rozwiązanie:* deterministyczny licznik wstrzykiwany jako niepodważalny fakt.
4. **Model generujący tekst wyglądający jak wywołanie narzędzia, bez faktycznego wykonania** — prowadzące do w pełni zmyślonego raportu o krytycznej podatności. *Rozwiązanie:* wykrywanie wzorca + twarda blokada opisu wyników bez faktycznego wykonania narzędzia.
5. **Pomijanie całych sekcji przy audycie wieloczęściowym** oraz nieoczekiwane przełączenie języka raportu na angielski. *Rozwiązanie:* deterministyczna lista kontrolna sekcji.
6. **Zmyślanie nieistniejących błędów wykonania** (kody HTTP, przekroczenie limitu czasu) mimo poprawnego pola statusu w danych źródłowych. *Rozwiązanie:* deterministyczny parser statusu wykonania.

Każdy z powyższych przypadków został zaobserwowany na rzeczywistych danych, udokumentowany w kodzie źródłowym i zaadresowany przez zasadę „deterministic-first” — nie przez dalsze poprawianie treści promptu.

---

## Znane ograniczenia i dalsze prace

Poniższa lista pochodzi ze szczegółowego przeglądu kodu źródłowego pod kątem gotowości do wdrożenia komercyjnego. Pełny opis każdego punktu (uzasadnienie, rekomendacja) dostępny w wewnętrznym rejestrze projektu.

| # | Obszar | Priorytet |
|---|---|---|
| 1 | Zakres działania (scope) skonfigurowany na sztywno pod środowisko testowe | Wysoki |
| 2 | Tylko 2 z ok. 15 narzędzi zasilają silnik Findings | Wysoki |
| 5 | Brak izolacji danych per klient/tenant | Wysoki |
| 6 | Brak szyfrowania danych at-rest | Wysoki |
| 7 | Brak polityki retencji danych | Wysoki |
| 13 | Migawki danych chroniące przed utratą przy kompresji — tylko dla 4/23 typów danych | Wysoki |
| 14 | Automatyczna weryfikacja kompletności raportu — tylko dla 2/23 typów danych | Wysoki |
| 17 | Stan pipeline'u trzymany wyłącznie w pamięci procesu (brak trwałego checkpointera) | Wysoki |
| 24 | Brak automatycznego odświeżania bazy sygnatur zagrożeń | Wysoki |
| 26 | Konfiguracja wdrożeniowa (TLS, sekrety, limity zasobów) — do weryfikacji | Wysoki |
| 3, 4, 8, 11, 12, 15, 22, 23 | Pomniejsze usprawnienia (mechanizm retest, indeksowanie magazynu danych, blokady współbieżności, przekazywanie sesji, zależność sprzętowa, krucha łatka wersji oprogramowania, konfiguracja narzędzi ograniczonych, wydajność parsowania) | Średni |
| 9, 16, 18, 19, 20, 21, 25 | Porządki kodu, spójność dokumentacji, drobne uproszczenia modelu ryzyka | Niski |

---

## Jak uruchomić

```bash
git clone <adres-repo>
cd cybersec-agent
cp .env.example .env   # uzupełnić tokeny (PENTEST_AGENT_TOKEN, ADMIN_AGENT_TOKEN)
docker compose up -d --build
```

Wymagania:
- Docker + Docker Compose
- Lokalny serwer Ollama z pobranymi modelami (patrz sekcja *Technologie*)
- Osobno skonfigurowana usługa `admin-agent` na hoście (systemd) — diagnostyka hosta wymaga uprawnień `sudo` do wybranych, whitelistowanych poleceń

Szczegółowa instrukcja konfiguracji usługi `admin-agent` (whitelist sudoers, token API, izolacja sieciowa) — patrz `docs/`.

---

## Autor

Michał Budyńczuk
