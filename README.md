# Cybersec Agent - system diagnostyki bezpieczeństwa (Supervisor + narzędzia + czat)

## Architektura

```
przeglądarka (localhost:8501)
        |
        v
  chat-ui (Streamlit)
        |
        v
  orchestrator (FastAPI + LangGraph, wzorzec Supervisor)
     - Supervisor (LLM: routing + finalna synteza raportu)
     - security_agent (LLM + narzędzia, TYLKO wywołuje, nie interpretuje)
        |
        v  HTTP + X-API-Token
  admin-agent (Twój istniejący FastAPI, systemd na hoście, port 8765)
```

LLM jest używany w dwóch miejscach: (1) supervisor decyduje które narzędzia wywołać,
(2) supervisor na końcu analizuje już zebrane, surowe dane i pisze raport.
Same wywołania narzędzi są deterministyczne (zwykłe HTTP), więc nie zależą od
"nastroju" modelu - to naprawia dokładnie problem, który mieliśmy w AnythingLLM.

## Krok 1: Zaktualizuj admin-agent

Zobacz `admin-agent-patch/README.md` - dopisz `check_wazuh`, `check_suricata`,
`scan_nmap` do swojego istniejącego admin-agent i zrestartuj usługę.

## Krok 2: Skopiuj ten katalog na serwer

```bash
# z Twojego komputera / albo pobierz pliki i wgraj przez scp:
scp -P 2847 -r cybersec-agent repas@192.168.0.126:/opt/ai_services/
```

## Krok 3: Ustaw token do admin-agent jako zmienną środowiskową

Na serwerze, w katalogu `cybersec-agent`:

```bash
cd /opt/ai_services/cybersec-agent
echo "ADMIN_AGENT_TOKEN=TWÓJ_PRAWDZIWY_TOKEN" > .env
```

(ten sam token co w `/etc/admin-agent/env`)

## Krok 4: Pobierz model w Ollamie (jeśli jeszcze nie masz)

```bash
docker exec -it ollama ollama pull llama3.1:8b
```

## Krok 5: Zbuduj i uruchom

```bash
cd /opt/ai_services/cybersec-agent
docker compose up -d --build
```

## Krok 6: Sprawdź logi przy pierwszym uruchomieniu

```bash
docker compose logs -f orchestrator
docker compose logs -f chat-ui
```

## Krok 7: Otwórz w przeglądarce

Jeśli jesteś na serwerze: `http://localhost:8501`
Jeśli zdalnie przez SSH tunnel:
```bash
ssh -p 2847 -L 8501:localhost:8501 repas@192.168.0.126
```
i otwórz `http://localhost:8501` na swoim komputerze.

## Testowanie

Wpisz w czacie np.:
- `sprawdź firewall i fail2ban`
- `czy wazuh i suricata działają?`
- `zrób pełny audyt bezpieczeństwa`
- `przeprowadź skan nmap na localhost`

Po każdej odpowiedzi warto zweryfikować logi orchestratora
(`docker compose logs -f orchestrator`), żeby widzieć realny przebieg
wywołań narzędzi - podobnie jak robiliśmy to wcześniej z `docker logs anythingllm`.

## Bezpieczeństwo - co już jest zabezpieczone

- `scan_nmap` ma białą listę dozwolonych celów (domyślnie tylko 127.0.0.1) -
  edytowalną w `functions/network.py` na hoście, NIE przez prompt w czacie.
- `scan_nmap` używa `-sT` (connect scan), nie wymaga uprawnień roota.
- Porty 8010 i 8501 są bindowane tylko do `127.0.0.1` w `docker-compose.yml` -
  żeby wystawić je szerzej (np. przez Tailscale), musisz świadomie odkomentować
  odpowiednią linię i rozważyć dodanie reguły `ufw` analogicznej do innych usług.
- Token do admin-agent trzymany w `.env` (dodaj `.env` do `.gitignore`, jeśli
  kiedykolwiek zrobisz z tego repo git).

## Co jeszcze warto rozważyć (nie zrobione automatycznie)

- Rotacja tokenu `admin-agent` (był wklejony w naszej wcześniejszej rozmowie).
- Limit `recursion_limit` / max iteracji w grafie, gdyby supervisor zapętlił się
  przy niejasnym poleceniu (na razie mamy domyślne wartości langgraph-supervisor).
- Health-check w `docker-compose.yml` (obecnie brak, można dodać podobnie jak
  masz w kontenerze `anythingllm`).
