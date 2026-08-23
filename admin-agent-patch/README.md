# Patch dla admin-agent: check_wazuh, check_suricata, scan_nmap

To NIE jest gotowy plik do podmiany - to fragmenty kodu do RĘCZNEGO dopisania
do Twoich istniejących plików, bo nie mam pełnej zawartości functions/security.py
i functions/network.py (widziałem tylko main.py). Otwórz swoje pliki na serwerze
i dopisz poniższe funkcje.

## 1. Zainstaluj nmap na hoście (tam gdzie działa admin-agent.service)

```bash
sudo apt update && sudo apt install nmap -y
```

## 2. Dopisz do functions/security.py

```python
def check_wazuh():
    """Sprawdza status usługi wazuh-agent."""
    try:
        result = subprocess.run(
            ["systemctl", "status", "wazuh-agent", "--no-pager"],
            capture_output=True, text=True, timeout=10
        )
        return {
            "status": "ok",
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr or None,
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}


def check_suricata():
    """Sprawdza status usługi suricata."""
    try:
        result = subprocess.run(
            ["systemctl", "status", "suricata", "--no-pager"],
            capture_output=True, text=True, timeout=10
        )
        return {
            "status": "ok",
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr or None,
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}
```

(Jeśli `subprocess` nie jest jeszcze zaimportowany w tym pliku, dodaj `import subprocess` na górze.)

## 3. Dopisz do functions/network.py

```python
# Bezpieczeństwo: nmap wolno skanować WYŁĄCZNIE cele z tej listy.
# To zapobiega użyciu tego API jako narzędzia do atakowania cudzej infrastruktury
# (np. gdyby ktoś przez agenta poprosił "zeskanuj 8.8.8.8" albo dowolny obcy adres).
ALLOWED_SCAN_TARGETS = {"127.0.0.1", "localhost"}
# Dodaj tu WŁASNE adresy (swojego serwera), jeśli chcesz skanować siebie z zewnątrz, np.:
# ALLOWED_SCAN_TARGETS.add("192.168.0.126")
# ALLOWED_SCAN_TARGETS.add("100.103.27.17")  # Tailscale


def scan_nmap(target: str = "127.0.0.1"):
    """Wykonuje TCP connect scan (-sT) + wykrywanie wersji usług (-sV) na dozwolonym celu.
    Celowo NIE używa -sS (SYN scan), więc nie wymaga uprawnień roota/sudo."""
    if target not in ALLOWED_SCAN_TARGETS:
        return {
            "status": "error",
            "message": (
                f"Cel '{target}' nie jest na białej liście dozwolonych celów skanowania. "
                f"Dozwolone: {sorted(ALLOWED_SCAN_TARGETS)}. "
                "Edytuj ALLOWED_SCAN_TARGETS w functions/network.py, aby dodać nowy cel."
            ),
        }
    try:
        result = subprocess.run(
            ["nmap", "-sT", "-sV", "--top-ports", "200", "-T4", target],
            capture_output=True, text=True, timeout=120
        )
        return {
            "status": "ok",
            "target": target,
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr or None,
        }
    except subprocess.TimeoutExpired:
        return {"status": "error", "message": "Skan przekroczył limit czasu (120s)."}
    except Exception as e:
        return {"status": "error", "message": str(e)}
```

(Analogicznie, upewnij się że `import subprocess` jest na górze pliku.)

## 4. Dopisz do main.py (obok innych route'ów)

```python
@app.get("/check_wazuh", dependencies=[Depends(verify_token)])
def route_check_wazuh():
    return security.check_wazuh()


@app.get("/check_suricata", dependencies=[Depends(verify_token)])
def route_check_suricata():
    return security.check_suricata()


@app.get("/scan_nmap", dependencies=[Depends(verify_token)])
def route_scan_nmap(target: str = "127.0.0.1"):
    return network.scan_nmap(target)
```

## 5. (Opcjonalnie) dodaj te 3 endpointy też do full_audit()

```python
return {
    "firewall": network.check_firewall(),
    "fail2ban": security.check_fail2ban(),
    "ssh_config": security.check_ssh(),
    "users": security.list_users(),
    "updates": system.check_updates(),
    "docker": system.check_docker(),
    "services": network.list_services(),
    "wazuh": security.check_wazuh(),          # NOWE
    "suricata": security.check_suricata(),     # NOWE
}
```

## 6. Zrestartuj usługę

```bash
sudo systemctl restart admin-agent
sudo systemctl status admin-agent
```

## 7. Przetestuj

```bash
curl -s -H "X-API-Token: TWÓJ_TOKEN" http://127.0.0.1:8765/check_wazuh | python3 -m json.tool
curl -s -H "X-API-Token: TWÓJ_TOKEN" http://127.0.0.1:8765/check_suricata | python3 -m json.tool
curl -s -H "X-API-Token: TWÓJ_TOKEN" http://127.0.0.1:8765/scan_nmap | python3 -m json.tool
```
