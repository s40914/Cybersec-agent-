"""
Deterministyczny parser faktow dla wynikow narzedzi zwracajacych proste,
bezposrednie dane JSON (check_updates, list_users) - w odroznieniu od
firewall_parser.py (ktory parsuje tekstowy `ufw status`), tutaj wejsciem
jest juz gotowy JSON zwrocony przez admin-agent, wiec zadanie sprowadza sie
do WYCIAGNIECIA i SFORMATOWANIA konkretnych pol, a nie parsowania surowego
tekstu.

DLACZEGO TO ISTNIEJE:
Modele 8-14B w tym pipeline przy full_audit (8 sekcji naraz, prompt czesto
przekraczajacy dostepne okno kontekstu - patrz historia z 2026-08-07)
systematycznie ZMYSLAJA tresc sekcji, ktorych surowe dane nie zmiescily sie
w oknie modelu (np. "2 pakiety aktualizacji" zamiast prawdziwych 82, albo
wymyslona liste uzytkownikow "root, ubuntu, tailscale" zamiast prawdziwego
jedynego uzytkownika). Zamiast liczyc na to ze model poprawnie odczyta
(lub w ogole zobaczy) surowy JSON, wyciagamy kluczowe fakty w Pythonie -
ze 100% powtarzalna poprawnoscia - i wstrzykujemy gotowy, krotki blok
tekstowy do promptu. To rowniez SKRACA ilosc tekstu wysylanego do modelu
w porownaniu do pelnego, nieprzetworzonego JSON-a, co bezposrednio pomaga
zmiescic sie w ciasnym oknie kontekstu (patrz PROMPT_SIZE w logach -
full_audit potrafi generowac prompty >50000 znakow).
"""
import json
import re


def _walk_dicts(node):
    """Rekurencyjnie przechadza sie po strukturze JSON (dict/list) i zwraca
    KAZDY napotkany slownik - zarowno najbardziej zewnetrzny, jak i wszystkie
    zagniezdzone. To niezbedne dla full_audit, ktore zwraca JEDEN duzy obiekt
    {"firewall": {...}, "fail2ban": {...}, "ssh_config": {...}, ...} - bez
    tego parsery widzialyby tylko zewnetrzny obiekt (z kluczami-nazwami
    sekcji) i nigdy nie trafialyby na charakterystyczne pola typu
    'service_active' czy 'settings', ktore siedza jeden poziom nizej."""
    if isinstance(node, dict):
        yield node
        for value in node.values():
            yield from _walk_dicts(value)
    elif isinstance(node, list):
        for item in node:
            yield from _walk_dicts(item)


def _find_json_objects(raw: str):
    """Szuka w raw wszystkich fragmentow, ktore wygladaja na kompletne
    obiekty JSON (najczesciej to zawartosc ToolMessage z narzedzi, ktore
    zwracaja json.dumps(...) jako string). Zwraca liste WSZYSTKICH
    slownikow napotkanych w drzewie (wlacznie z zagniezdzonymi - patrz
    _walk_dicts), ignorujac fragmenty ktore nie sa poprawnym JSON-em."""
    results = []
    # Szukamy najbardziej zewnetrznych klamer { ... } - prosta heurystyka
    # dopasowania zagniezdzonych nawiasow, bez regex (regex zle radzi sobie
    # z zagniezdzeniem klamer w JSON).
    depth = 0
    start = None
    for i, ch in enumerate(raw):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            if depth > 0:
                depth -= 1
                if depth == 0 and start is not None:
                    candidate = raw[start:i + 1]
                    try:
                        obj = json.loads(candidate)
                        if isinstance(obj, dict):
                            results.extend(_walk_dicts(obj))
                    except (json.JSONDecodeError, ValueError):
                        pass
                    start = None
    return results


def extract_and_format_updates_block(raw: str) -> str:
    """Szuka obiektu JSON z polami charakterystycznymi dla check_updates
    (total_upgradable + security_updates_count) i zwraca gotowy,
    niepodwazalny blok faktow. Pusty string jesli nic nie znaleziono."""
    for obj in _find_json_objects(raw):
        if "total_upgradable" in obj and "security_updates_count" in obj:
            total = obj.get("total_upgradable", "brak danych")
            security_count = obj.get("security_updates_count", "brak danych")
            other_count = obj.get("other_updates_count", "brak danych")
            security_list = obj.get("security_updates", [])

            lines = [
                "### ZWERYFIKOWANE FAKTY: AKTUALIZACJE SYSTEMU (wyciagniete automatycznie z JSON, NIEPODWAZALNE)",
                f"- Liczba wszystkich dostepnych aktualizacji (total_upgradable): {total}",
                f"- Liczba aktualizacji bezpieczenstwa (security_updates_count): {security_count}",
                f"- Liczba pozostalych aktualizacji (other_updates_count): {other_count}",
            ]
            if security_list:
                lines.append("- Lista aktualizacji bezpieczenstwa:")
                for item in security_list:
                    lines.append(f"  - {item}")
            elif security_count == 0:
                lines.append("- Brak aktualizacji bezpieczenstwa na liscie (security_updates_count = 0).")

            lines.append(
                f"UZYWAJ WYLACZNIE powyzszej liczby ({total}) jako liczby aktualizacji w raporcie. "
                f"NIE zaokraglaj, NIE zmyslaj innej liczby, NIE pisz 'brak zaleglosci' jesli total > 0."
            )
            return "\n".join(lines)
    return ""


def extract_and_format_users_block(raw: str) -> str:
    """Szuka obiektu JSON z polami charakterystycznymi dla list_users
    (human_users + sudo_group_members) i zwraca gotowy, niepodwazalny
    blok faktow. Pusty string jesli nic nie znaleziono."""
    for obj in _find_json_objects(raw):
        if "human_users" in obj and "sudo_group_members" in obj:
            human_users = obj.get("human_users", [])
            sudo_members = obj.get("sudo_group_members", [])

            lines = [
                "### ZWERYFIKOWANE FAKTY: UZYTKOWNICY SYSTEMOWI (wyciagniete automatycznie z JSON, NIEPODWAZALNE)",
                f"- Liczba uzytkownikow (human_users): {len(human_users)}",
            ]
            if human_users:
                lines.append("- Lista uzytkownikow:")
                for u in human_users:
                    username = u.get("username", "brak danych")
                    uid = u.get("uid", "brak danych")
                    home = u.get("home", "brak danych")
                    shell = u.get("shell", "brak danych")
                    lines.append(f"  - {username} (uid={uid}, home={home}, shell={shell})")
            else:
                lines.append("- Brak uzytkownikow na liscie (human_users jest puste).")

            lines.append(f"- Czlonkowie grupy sudo (sudo_group_members): {', '.join(sudo_members) if sudo_members else 'brak'}")
            lines.append(
                f"UZYWAJ WYLACZNIE powyzszej listy {[u.get('username') for u in human_users]} jako listy uzytkownikow w raporcie. "
                f"NIE dodawaj uzytkownikow ktorych nie ma na tej liscie (np. 'root', 'ubuntu' jesli nie sa wymienieni powyzej)."
            )
            return "\n".join(lines)
    return ""


def extract_and_format_ports_block(raw: str) -> str:
    """Szuka obiektu JSON zawierajacego stdout w formacie `ss -tulpn`
    (naglowek Netid/State/.../Local Address:Port) i zwraca gotowy,
    ponumerowany, niepodwazalny blok faktow z KAZDYM nasluchujacym
    portem osobno. Istnieje z tego samego powodu co pozostale bloki w
    tym module (patrz extract_and_format_users_block) - modele 8-14B
    gubia pojedyncze pozycje przy recznym przepisywaniu dlugich list z
    surowego stdout, nawet gdy prompt wprost zabrania grupowania.
    Pusty string jesli nic nie znaleziono."""
    for obj in _find_json_objects(raw):
        stdout = obj.get("stdout")
        if not isinstance(stdout, str):
            continue
        if "Netid" not in stdout or "State" not in stdout:
            continue
        if "LISTEN" not in stdout and "UNCONN" not in stdout:
            continue

        entries = []
        seen = set()
        for line in stdout.splitlines():
            if "LISTEN" not in line and "UNCONN" not in line:
                continue
            parts = line.split()
            if len(parts) < 5:
                continue
            proto = parts[0]
            local_addr = parts[4]
            match = re.search(r":(\d+)$", local_addr)
            if not match:
                continue
            port = match.group(1)
            proc_match = re.search(r'users:\(\("([^"]+)"', line)
            proc_name = proc_match.group(1) if proc_match else "brak danych"
            key = (proto, local_addr, proc_name)
            if key in seen:
                continue
            seen.add(key)
            entries.append((int(port), proto, local_addr, proc_name))

        if not entries:
            return ""

        entries.sort(key=lambda e: (e[0], e[1]))
        lines = [
            "### ZWERYFIKOWANE FAKTY: NASLUCHUJACE PORTY (wyciagniete automatycznie z ss -tulpn, NIEPODWAZALNE)",
            f"- Liczba wpisow (kazda kombinacja protokol+adres+proces liczona osobno): {len(entries)}",
            "- Pelna lista - WYPISZ W RAPORCIE KAZDY z ponizszych wpisow jako OSOBNA linia, "
            "NIE laczyj kilku portow w jedno zdanie z przecinkami:",
        ]
        for idx, (port, proto, local_addr, proc_name) in enumerate(entries, start=1):
            lines.append(f"  {idx}. port {port}/{proto} na {local_addr} (proces: {proc_name})")
        unique_ports = sorted({e[0] for e in entries})
        lines.append(
            f"- Unikalne numery portow w tej liscie ({len(unique_ports)}): "
            + ", ".join(str(p) for p in unique_ports)
        )
        lines.append(
            "UZYWAJ WYLACZNIE powyzszej listy. Przed oddaniem raportu policz linie w swoim "
            "opisie portow i porownaj z liczba wpisow powyzej - jesli masz mniej, wroc i "
            "uzupelnij brakujace, nie zmyslaj nowych ani nie pomijaj istniejacych."
        )
        return "\n".join(lines)
    return ""


def extract_and_format_docker_block(raw: str) -> str:
    """Szuka obiektu JSON z wynikiem `docker ps` (charakterystyczny naglowek
    stdout: 'CONTAINER ID' + 'NAMES') i wyciaga liste kontenerow (obraz +
    nazwa) zamiast liczenia na to, ze model poprawnie przepisze cala
    tabele tekstowa."""
    for obj in _find_json_objects(raw):
        stdout = obj.get("stdout")
        if isinstance(stdout, str) and "CONTAINER ID" in stdout and "NAMES" in stdout:
            lines = stdout.strip().split("\n")
            if len(lines) < 2:
                return ""
            containers = []
            for line in lines[1:]:
                tokens = line.split()
                if len(tokens) < 2:
                    continue
                image = tokens[1]
                name = tokens[-1]
                containers.append((name, image))

            lines_out = [
                "### ZWERYFIKOWANE FAKTY: KONTENERY DOCKER (wyciagniete automatycznie z JSON, NIEPODWAZALNE)",
                f"- Liczba dzialajacych kontenerow: {len(containers)}",
                "- Lista kontenerow (nazwa - obraz):",
            ]
            for name, image in containers:
                lines_out.append(f"  - {name} ({image})")
            lines_out.append(
                f"UZYWAJ WYLACZNIE powyzszej listy {len(containers)} kontenerow. "
                f"NIE zmyslaj innych nazw kontenerow (np. 'nginx', 'postgresql' jesli nie sa wymienione powyzej)."
            )
            return "\n".join(lines_out)
    return ""


def extract_and_format_fail2ban_block(raw: str) -> str:
    """Szuka obiektu JSON z wynikiem check_fail2ban (charakterystyczne pole
    service_active + zagniezdzony jail_status.stdout) i wyciaga status
    usluzenia oraz liczby zbanowanych/proby logowania z jail sshd."""
    for obj in _find_json_objects(raw):
        if "service_active" in obj and "jail_status" in obj:
            service_active = obj.get("service_active", "brak danych")
            jail_stdout = ""
            jail_status = obj.get("jail_status")
            if isinstance(jail_status, dict):
                jail_stdout = jail_status.get("stdout") or ""

            currently_banned = re.search(r"Currently banned:\s*(\d+)", jail_stdout)
            total_banned = re.search(r"Total banned:\s*(\d+)", jail_stdout)
            currently_failed = re.search(r"Currently failed:\s*(\d+)", jail_stdout)
            total_failed = re.search(r"Total failed:\s*(\d+)", jail_stdout)

            lines = [
                "### ZWERYFIKOWANE FAKTY: FAIL2BAN (wyciagniete automatycznie z JSON, NIEPODWAZALNE)",
                f"- Status uslugi fail2ban (service_active): {service_active}",
            ]
            if currently_banned:
                lines.append(f"- Aktualnie zbanowane IP (jail sshd): {currently_banned.group(1)}")
            if total_banned:
                lines.append(f"- Laczna liczba zbanowanych IP od startu (jail sshd): {total_banned.group(1)}")
            if currently_failed:
                lines.append(f"- Aktualnie nieudane proby logowania (jail sshd): {currently_failed.group(1)}")
            if total_failed:
                lines.append(f"- Laczna liczba nieudanych prob logowania (jail sshd): {total_failed.group(1)}")
            lines.append(
                f"UZYWAJ WYLACZNIE powyzszego statusu ('{service_active}') jako statusu fail2ban w raporcie."
            )
            return "\n".join(lines)
    return ""


def extract_and_format_ssh_block(raw: str) -> str:
    """Szuka obiektu JSON z wynikiem check_ssh (charakterystyczne pole
    'settings' z kluczami typu PasswordAuthentication) i wyciaga
    kluczowe ustawienia, z wyraznym oznaczeniem realnego ryzyka."""
    for obj in _find_json_objects(raw):
        settings = obj.get("settings")
        if isinstance(settings, dict) and "PasswordAuthentication" in settings:
            port = settings.get("Port", "22 (domyslny)")
            password_auth = settings.get("PasswordAuthentication", "brak danych")
            root_login = settings.get("PermitRootLogin", "brak danych")
            pubkey_auth = settings.get("PubkeyAuthentication", "brak danych")

            lines = [
                "### ZWERYFIKOWANE FAKTY: KONFIGURACJA SSH (wyciagniete automatycznie z JSON, NIEPODWAZALNE)",
                f"- Port SSH: {port}",
                f"- PasswordAuthentication: {password_auth}",
                f"- PermitRootLogin: {root_login}",
                f"- PubkeyAuthentication: {pubkey_auth}",
            ]
            for key, value in settings.items():
                if key not in ("Port", "PasswordAuthentication", "PermitRootLogin", "PubkeyAuthentication"):
                    lines.append(f"- {key}: {value}")

            if str(password_auth).lower() == "yes":
                lines.append(
                    "UWAGA RYZYKO: PasswordAuthentication=yes oznacza, ze logowanie haslem jest WLACZONE "
                    "(nie tylko klucz publiczny) - to zwieksza podatnosc na ataki brute-force, zwlaszcza "
                    "jesli fail2ban jest nieaktywny lub port jest dostepny z internetu."
                )
            lines.append(
                f"UZYWAJ WYLACZNIE powyzszych, dokladnych wartosci ustawien SSH w raporcie - "
                f"NIE zakladaj domyslnych/bezpiecznych wartosci, ktorych nie ma na tej liscie."
            )
            return "\n".join(lines)
    return ""


def extract_and_format_services_block(raw: str) -> str:
    """Szuka obiektu JSON z wynikiem list_services (charakterystyczny
    naglowek stdout: 'UNIT' + 'LOAD' + 'ACTIVE') i wyciaga liczbe oraz
    liste uslug systemd, zamiast liczenia na to ze model poprawnie
    przepisze cala tabele tekstowa."""
    for obj in _find_json_objects(raw):
        stdout = obj.get("stdout")
        if isinstance(stdout, str) and "UNIT" in stdout and "LOAD" in stdout and "ACTIVE" in stdout:
            service_lines = [
                line for line in stdout.split("\n")
                if line.strip().endswith(("running", "exited", "dead", "failed"))
                or (".service" in line and "loaded" in line)
            ]
            services = []
            for line in service_lines:
                tokens = line.split()
                if tokens and tokens[0].endswith(".service"):
                    services.append(tokens[0])

            total_match = re.search(r"(\d+)\s+loaded units listed", stdout)
            total = total_match.group(1) if total_match else str(len(services))

            lines = [
                "### ZWERYFIKOWANE FAKTY: USLUGI SYSTEMD (wyciagniete automatycznie z JSON, NIEPODWAZALNE)",
                f"- Liczba zaladowanych uslug (wg systemctl): {total}",
                "- Lista uslug (nazwy):",
            ]
            for s in services:
                lines.append(f"  - {s}")
            lines.append(
                f"UZYWAJ WYLACZNIE powyzszej listy {len(services)} uslug. "
                f"NIE zmyslaj innych nazw uslug ani nie pomijaj tych faktycznie obecnych na liscie."
            )
            return "\n".join(lines)
    return ""


def extract_and_format_alerts_block(raw: str) -> str:
    """Szuka obiektu JSON z wynikiem check_recent_alerts (charakterystyczne
    pola alert_count + alerts jako lista). Zamiast wypisywac kazdy alert
    z osobna (przy setkach alertow to zbyt duzo tekstu), AGREGUJE je wg
    'description' i pokazuje unikalne typy z liczba wystapien - to
    wystarczy do oceny ryzyka, a jest wielokrotnie krotsze niz pelna lista.
    Krytyczne: to jedyny sposob, zeby model nie zmyslal nieistniejacych
    typow alertow (np. 'malicious domain'), gdy pelna lista nie miesci sie
    w oknie kontekstu."""
    for obj in _find_json_objects(raw):
        alerts = obj.get("alerts")
        if isinstance(alerts, list) and "alert_count" in obj:
            alert_count = obj.get("alert_count", len(alerts))
            window = obj.get("window_minutes", "brak danych")

            counts = {}
            max_level = 0
            for a in alerts:
                desc = a.get("description", "brak opisu")
                level = a.get("level", 0)
                counts[desc] = counts.get(desc, 0) + 1
                if isinstance(level, (int, float)) and level > max_level:
                    max_level = level

            lines = [
                "### WERYFIKACJA DETEKCJI (Wazuh/Suricata)",
                "### ZWERYFIKOWANE FAKTY: ALARMY WAZUH/SURICATA (wyciagniete automatycznie z JSON, NIEPODWAZALNE)",
                f"- Calkowita liczba alertow w oknie {window} minut (alert_count): {alert_count}",
                f"- Liczba faktycznie otrzymanych rekordow alertow: {len(alerts)}",
                f"- Najwyzszy poziom (level) wsrod alertow: {max_level}",
                f"- Liczba UNIKALNYCH typow alertow (wg opisu): {len(counts)}",
                "- Zestawienie: typ alertu -> liczba wystapien:",
            ]
            for desc, count in sorted(counts.items(), key=lambda x: -x[1]):
                lines.append(f"  - [{count}x] {desc}")
            lines.append(
                f"UZYWAJ WYLACZNIE powyzszej listy {len(counts)} unikalnych typow alertow. "
                f"NIE zmyslaj innych typow alertow (np. 'malicious domain', 'malware', "
                f"'intrusion') ktorych nie ma na tej liscie - jesli nie ma ich powyzej, NIE WYSTAPILY."
            )
            return "\n".join(lines)
    return ""


def _reduce_bulky_fields(node) -> bool:
    """Rekurencyjnie mutuje node (dict/list) IN PLACE, zastepujac
    nieprzetworzone, obszerne pola (ktore maja juz odpowiadajacy im
    krotki blok FACTS_* wygenerowany wczesniej) krotkim placeholderem.
    Zwraca True jesli cokolwiek zmieniono. WAZNE: to musi biec PO tym,
    jak firewall_parser/tool_status_parser/section_checklist/facts_parser
    juz przeczytaly oryginalne dane - w przeciwnym razie te parsery
    nie mialyby z czego wyciagac faktow."""
    changed = False
    if isinstance(node, dict):
        stdout = node.get("stdout")
        if isinstance(stdout, str):
            if "CONTAINER ID" in stdout and "NAMES" in stdout:
                node["stdout"] = (
                    "(pelna tresc zastapiona ponizszym blokiem "
                    "'ZWERYFIKOWANE FAKTY: KONTENERY DOCKER')"
                )
                changed = True
            elif "UNIT" in stdout and "LOAD" in stdout and "ACTIVE" in stdout:
                node["stdout"] = (
                    "(pelna tresc zastapiona ponizszym blokiem "
                    "'ZWERYFIKOWANE FAKTY: USLUGI SYSTEMD')"
                )
                changed = True
            elif "ALLOW IN" in stdout or "DENY IN" in stdout:
                node["stdout"] = (
                    "(pelna tresc zastapiona ponizszym blokiem "
                    "deterministycznym firewall_parser - patrz reguly ALLOW/DENY ponizej)"
                )
                changed = True
            elif "Lynis" in stdout and "Hardening index" in stdout:
                node["stdout"] = (
                    "(pelna tresc zastapiona ponizszym blokiem "
                    "'ZWERYFIKOWANE FAKTY: AUDYT LYNIS')"
                )
                changed = True

        tool_name = node.get("tool")
        if tool_name in ("nuclei_scan", "searchsploit_scan", "testssl_scan") and "stdout" in node:
            node["stdout"] = (
                f"(pelna tresc zastapiona odpowiednim blokiem 'ZWERYFIKOWANE FAKTY' dla {tool_name})"
            )
            changed = True

        if "alerts" in node and isinstance(node["alerts"], list) and "alert_count" in node:
            original_len = len(node["alerts"])
            node["alerts"] = (
                f"(lista {original_len} pojedynczych alertow zastapiona ponizszym "
                f"zagregowanym blokiem 'ZWERYFIKOWANE FAKTY: ALARMY WAZUH/SURICATA')"
            )
            changed = True

        for value in node.values():
            if _reduce_bulky_fields(value):
                changed = True

    elif isinstance(node, list):
        for item in node:
            if _reduce_bulky_fields(item):
                changed = True

    return changed


def compact_raw_results(raw: str) -> str:
    """Znajduje NAJBARDZIEJ ZEWNETRZNE obiekty JSON w raw (top-level, depth=0
    - to sa oryginalne wyniki narzedzi, NIE wstrzykniete wczesniej bloki
    tekstowe FACTS_*/SECTION_CHECKLIST, ktore nie sa poprawnym JSON-em),
    redukuje w nich obszerne pola majace juz odpowiadajacy krotki blok
    faktow (patrz _reduce_bulky_fields), i podmienia oryginalny fragment
    tekstu na skrocona wersje. WYWOLYWAC DOPIERO PO wszystkich innych
    parserach (firewall_parser, tool_status_parser, section_checklist,
    facts_parser) - one musza najpierw przeczytac oryginalne dane."""
    spans = []
    depth = 0
    start = None
    for i, ch in enumerate(raw):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            if depth > 0:
                depth -= 1
                if depth == 0 and start is not None:
                    spans.append((start, i + 1))
                    start = None

    result = raw
    for span_start, span_end in reversed(spans):
        candidate = raw[span_start:span_end]
        try:
            obj = json.loads(candidate)
        except (json.JSONDecodeError, ValueError):
            continue
        if not isinstance(obj, dict):
            continue
        obj_copy = json.loads(json.dumps(obj))
        if _reduce_bulky_fields(obj_copy):
            new_candidate = json.dumps(obj_copy, ensure_ascii=False)
            result = result[:span_start] + new_candidate + result[span_end:]

    return result


def extract_and_format_nmap_block(raw: str) -> str:
    """Szuka wynikow nmap (pentest-agent /run_tool) w raw_results i zwraca
    gotowy, niepodwazalny blok faktow z lista otwartych portow.
    Istnieje z tego samego powodu co extract_and_format_ports_block -
    modele 8-14B ignoruja krotki wynik nmapa gdy w raw_results sa obszerne
    dane z Suricaty/Wazuh. Ten blok wymusza ze wynik nmap jest PIERWSZA
    i NAJWAZNIEJSZA informacja w raporcie, niezaleznie od ilosci danych
    z systemow detekcji."""
    for obj in _find_json_objects(raw):
        tool = obj.get("tool", "")
        stdout = obj.get("stdout", "")
        if not isinstance(stdout, str):
            continue
        if not any(t in tool for t in ("nmap_stealth_scan", "nmap_scan_ip", "nmap_vuln_scan")):
            continue
        if "Nmap scan report" not in stdout:
            continue

        open_ports = []
        for line in stdout.splitlines():
            match = re.match(r"^(\d+)/(tcp|udp)\s+open\s+(\S+)", line.strip())
            if match:
                port, proto, service = match.group(1), match.group(2), match.group(3)
                open_ports.append((int(port), proto, service))

        command = obj.get("command", "brak danych")
        target = obj.get("params", {}).get("target", "brak danych")

        lines = [
            f"### ZWERYFIKOWANE FAKTY: WYNIK NMAP ({tool}) (NIEPODWAZALNE, wyciagniete automatycznie)",
            f"- Narzedzie: {tool}",
            f"- Target: {target}",
            f"- Komenda: {command}",
            f"- Status: {'SUKCES' if obj.get('returncode') == 0 else 'BLAD'} (returncode={obj.get('returncode')})",
            f"- Liczba otwartych portow znalezionych przez nmap: {len(open_ports)}",
        ]
        if open_ports:
            lines.append("- PELNA LISTA otwartych portow (WYPISZ KAZDY Z NICH W RAPORCIE jako OSOBNA linia):")
            for i, (port, proto, service) in enumerate(open_ports, 1):
                lines.append(f"  {i}. port {port}/{proto} (usluga: {service})")
        else:
            lines.append("- BRAK otwartych portow w top portach przeskanowanych przez nmap.")
        lines.append(
            "BEZWZGLEDNA KOLEJNOSC RAPORTU: najpierw omow POWYZSZE wyniki nmap (to jest GLOWNY wynik "
            "narzedzia diagnostycznego), a dopiero NA KONCU sekcje weryfikacji detekcji "
            "(Suricata/Wazuh). NIE zamieniaj tej kolejnosci niezaleznie od ilosci danych "
            "z systemow detekcji - wynik nmap jest zawsze wazniejszy niz alerty IDS."
        )
        lines.append("### KONIEC ZWERYFIKOWANYCH FAKTOW NMAP")
        return "\n".join(lines)
    return ""


def extract_and_format_port_exposure_guard(raw: str) -> str:
    """Deterministyczny "straznik" oceny ryzyka ekspozycji portow.

    DLACZEGO TO ISTNIEJE:
    Instrukcja tekstowa w REPORT_PROMPT/CRITIC_PROMPT ("nie pisz 'dostepny
    z internetu' bez danych firewalla") okazala sie NIEDETERMINISTYCZNA -
    w jednym przebiegu model jej przestrzegal, w kolejnym (z tymi samymi
    danymi wejsciowymi co do struktury) zignorowal ja i ponownie napisal
    "KRYTYCZNE, port otwarty na 0.0.0.0". To pokazuje granice prompt
    engineeringu przy modelach 8-14B: instrukcja slowna to prosba, nie
    fakt. Ta funkcja przenosi te regule z warstwy "prosba" do warstwy
    "twardy fakt wstrzykniety do promptu" - dokladnie jak pozostale
    parsery w tym module.

    Wykrywa, czy w TYM KONKRETNYM przebiegu (raw) sa obecne dane
    check_firewall (obecnosc linii z "ALLOW IN"/"DENY IN") ORAZ dane
    o nasluchujacych portach (obecnosc "Local Address:Port" - format
    wyjscia `ss` z scan_ports). Jesli sa porty, ale NIE MA firewalla -
    wstrzykuje jednoznaczny, niepodwazalny zakaz klasyfikowania ryzyka
    ekspozycji. Jesli oba sa obecne - firewall_parser.py juz dostarcza
    wlasciwa klasyfikacje per-regula, wiec ten strażnik tylko to
    potwierdza (nie duplikuje pracy)."""
    has_ports = "Local Address:Port" in raw or ("LISTEN" in raw and "Netid" in raw)
    if not has_ports:
        return ""

    has_firewall = "ALLOW IN" in raw or "DENY IN" in raw

    if has_firewall:
        return (
            "### ZWERYFIKOWANE FAKTY: DOSTĘPNOŚĆ DANYCH DO OCENY EKSPOZYCJI PORTÓW\n"
            "- Ten przebieg ZAWIERA dane check_firewall (reguły ALLOW/DENY są dostępne).\n"
            "- Możesz oceniać ekspozycję portów na podstawie reguł firewalla podanych "
            "w bloku firewall_parser powyżej - trzymaj się DOKŁADNIE tej klasyfikacji ryzyka, "
            "nie twórz własnej, sprzecznej z nią oceny."
        )

    return (
        "### ZWERYFIKOWANE FAKTY: DOSTĘPNOŚĆ DANYCH DO OCENY EKSPOZYCJI PORTÓW (NIEPODWAŻALNE)\n"
        "- Ten przebieg NIE ZAWIERA danych check_firewall (brak reguł ALLOW/DENY w surowych danych).\n"
        "- Lista nasłuchujących portów (z ss/scan_ports) pokazuje TYLKO, że proces przyjmuje "
        "połączenia na danym adresie/interfejsie TEGO HOSTA - to NIE dowodzi dostępności z internetu.\n"
        "- BEZWZGLĘDNY ZAKAZ: w tym raporcie NIE WOLNO Ci klasyfikować żadnego portu jako "
        "\"dostępny z internetu\", \"otwarty na świat\", \"KRYTYCZNE\" ani \"WYSOKIE ryzyko\" "
        "z powodu ekspozycji sieciowej - nie masz do tego danych.\n"
        "- JEDYNA dozwolona klasyfikacja dla każdego portu z listy: \"nasłuchuje lokalnie - "
        "rzeczywista ekspozycja nieznana, wymaga danych z check_firewall (niedostępnych w tym przebiegu)\".\n"
        "- Złamanie tej zasady jest błędem krytycznym - jeśli chcesz ocenić realne ryzyko, "
        "poinformuj użytkownika, że potrzebny jest dodatkowy przebieg z check_firewall lub full_audit."
    )


def extract_and_format_lynis_block(raw: str) -> str:
    """Parsuje wynik check_lynis (Lynis security audit) - wyciaga Hardening
    Index, liczbe testow, oraz WSZYSTKIE warnings/suggestions z ich kodami
    testow [XXX-1234], zamiast pozwalac modelowi przepisywac (i gubic/
    zmyslac) z bardzo dlugiego, surowego stdout (setki linii z kodami ANSI
    pozycjonowania kursora \\u001b[NC, ktore dodatkowo utrudniaja modelowi
    poprawny odczyt)."""
    for obj in _find_json_objects(raw):
        stdout = obj.get("stdout")
        if isinstance(stdout, str) and "Lynis" in stdout and "Hardening index" in stdout:
            hardening_match = re.search(r"Hardening index\s*:\s*(\d+)", stdout)
            hardening = hardening_match.group(1) if hardening_match else "brak danych"

            tests_match = re.search(r"Tests performed\s*:\s*(\d+)", stdout)
            tests = tests_match.group(1) if tests_match else "brak danych"

            warnings = re.findall(r"!\s+(.+?)\s+\[([\w-]+)\]", stdout)
            suggestions = re.findall(r"\*\s+(.+?)\s+\[([\w-]+)\]", stdout)

            lines = [
                "### ZWERYFIKOWANE FAKTY: AUDYT LYNIS (wyciagniete automatycznie, NIEPODWAZALNE)",
                f"- Hardening Index: {hardening}/100",
                f"- Liczba wykonanych testow: {tests}",
                f"- Liczba ostrzezen (warnings): {len(warnings)}",
                f"- Liczba sugestii (suggestions): {len(suggestions)}",
            ]
            if warnings:
                lines.append("- Lista OSTRZEZEN (warnings) z kodami testow:")
                for text, code in warnings:
                    lines.append(f"  - [{code}] {text.strip()}")
            if suggestions:
                lines.append(f"- Lista SUGESTII (suggestions), {len(suggestions)} pozycji:")
                for text, code in suggestions:
                    lines.append(f"  - [{code}] {text.strip()}")
            lines.append(
                f"UZYWAJ WYLACZNIE powyzszej listy {len(warnings)} ostrzezen i {len(suggestions)} "
                f"sugestii. NIE zmyslaj innych ostrzezen/kodow testow ktorych nie ma na tej liscie."
            )
            return "\n".join(lines)
    return ""


def extract_and_format_nuclei_block(raw: str) -> str:
    """Parsuje wynik nuclei_scan (linie tekstowe w formacie
    [template] [protokol] [severity] url [szczegoly]) - wyciaga
    ustrukturyzowana liste znalezisk zamiast pozwalac modelowi
    przepisywac surowy tekst."""
    for obj in _find_json_objects(raw):
        if obj.get("tool") != "nuclei_scan":
            continue
        stdout = obj.get("stdout") or ""
        findings = re.findall(
            r"\[([\w.-]+)\]\s*\[(\w+)\]\s*\[(\w+)\]\s*(\S+)(?:\s*\[(.*)\])?",
            stdout,
        )
        lines = [
            "### ZWERYFIKOWANE FAKTY: SKAN NUCLEI (wyciagniete automatycznie, NIEPODWAZALNE)",
            f"- Liczba znalezisk: {len(findings)}",
        ]
        if findings:
            lines.append("- Lista znalezisk (szablon, protokol, poziom, cel, szczegoly):")
            for template, proto, severity, url, details in findings:
                extra = f" - {details}" if details else ""
                lines.append(f"  - [{severity.upper()}] {template} ({proto}) na {url}{extra}")
        else:
            lines.append("- Brak znalezisk (skan nie wykrył żadnych pasujących szablonów).")
        lines.append(
            f"UZYWAJ WYLACZNIE powyzszej listy {len(findings)} znalezisk. "
            f"NIE zmyslaj innych szablonow/CVE ktorych nie ma na tej liscie."
        )
        return "\n".join(lines)
    return ""


def extract_and_format_searchsploit_block(raw: str) -> str:
    """Parsuje wynik searchsploit_scan (JSON z RESULTS_EXPLOIT) - wyciaga
    tytul, EDB-ID, CVE i sciezke kazdego exploita."""
    for obj in _find_json_objects(raw):
        if obj.get("tool") != "searchsploit_scan":
            continue
        stdout = obj.get("stdout") or ""
        try:
            data = json.loads(stdout)
        except (json.JSONDecodeError, ValueError):
            return ""
        results = data.get("RESULTS_EXPLOIT", [])

        lines = [
            "### ZWERYFIKOWANE FAKTY: SEARCHSPLOIT (wyciagniete automatycznie, NIEPODWAZALNE)",
            f"- Zapytanie: {data.get('SEARCH', 'brak danych')}",
            f"- Liczba znalezionych exploitow: {len(results)}",
        ]
        if results:
            lines.append("- Lista exploitow (tytul, EDB-ID, CVE, typ):")
            for r in results:
                title = r.get("Title", "brak tytulu")
                edb = r.get("EDB-ID", "?")
                codes = r.get("Codes", "") or "brak CVE"
                etype = r.get("Type", "?")
                lines.append(f"  - [EDB-ID {edb}] {title} (typ: {etype}, kody: {codes})")
        else:
            lines.append("- Brak exploitow w lokalnej bazie Exploit-DB dla tego zapytania.")
        lines.append(
            f"UZYWAJ WYLACZNIE powyzszej listy {len(results)} exploitow. "
            f"NIE zmyslaj innych EDB-ID/CVE ktorych nie ma na tej liscie."
        )
        return "\n".join(lines)
    return ""


def extract_and_format_testssl_block(raw: str) -> str:
    """Parsuje wynik testssl_scan (JSON - lista obiektow id/severity/finding)
    - wyciaga tylko istotne wpisy (pomija DEBUG/OK dla czytelnosci, chyba
    ze to jedyne dostepne dane)."""
    for obj in _find_json_objects(raw):
        if obj.get("tool") != "testssl_scan":
            continue
        stdout = obj.get("stdout") or ""
        try:
            data = json.loads(stdout)
        except (json.JSONDecodeError, ValueError):
            return ""
        if not isinstance(data, list):
            return ""

        notable = [d for d in data if d.get("severity") not in ("DEBUG", "OK", "INFO")]
        lines = [
            "### ZWERYFIKOWANE FAKTY: AUDYT TLS/SSL - TESTSSL (wyciagniete automatycznie, NIEPODWAZALNE)",
            f"- Liczba wszystkich sprawdzonych pozycji: {len(data)}",
            f"- Liczba pozycji WYMAGAJACYCH UWAGI (poza DEBUG/OK/INFO): {len(notable)}",
        ]
        if notable:
            lines.append("- Lista pozycji wymagajacych uwagi (id, poziom, wynik):")
            for d in notable:
                lines.append(f"  - [{d.get('severity')}] {d.get('id')}: {d.get('finding')}")
        else:
            lines.append(
                "- Brak istotnych ostrzezen. Jesli wszystkie protokoly pokazuja "
                "'not offered', oznacza to ze cel NIE UZYWA TLS/SSL na tym porcie "
                "(np. to zwykly HTTP) - to NIE jest blad testu."
            )
        lines.append(
            f"UZYWAJ WYLACZNIE powyzszej listy {len(notable)} pozycji. "
            f"NIE zmyslaj innych podatnosci/protokolow ktorych nie ma na tej liscie."
        )
        return "\n".join(lines)
    return ""


def extract_and_format_hydra_block(raw: str) -> str:
    """Szuka wyniku hydra_ssh w raw_results i zwraca gotowy, niepodwazalny
    blok faktow z lista znalezionych par login:haslo (jesli sa) albo
    jednoznacznym stwierdzeniem braku wynikow. Istnieje z tego samego
    powodu co pozostale bloki w tym module - dla tego narzedzia ryzyko
    halucynacji jest szczegolnie powazne: zmyslenie hasla ktorego hydra
    NIE znalazla to falszywy pozytyw bezpieczenstwa, a pominiecie
    faktycznie znalezionej pary to falszywy negatyw (ukrycie realnej
    podatnosci) - oba sa niedopuszczalne w raporcie SecOps."""
    for obj in _find_json_objects(raw):
        if obj.get("tool") != "hydra_ssh":
            continue
        stdout = obj.get("stdout", "")
        if not isinstance(stdout, str):
            continue

        target = obj.get("params", {}).get("target", "brak danych")
        port = obj.get("params", {}).get("port", "22")
        command = obj.get("command", "brak danych")
        status = obj.get("status", "brak danych")
        returncode = obj.get("returncode")
        stderr = obj.get("stderr", "") or ""

        connection_failed = bool(re.search(
            r"could not connect|Timeout connecting|Connection refused|No route to host|Network is unreachable",
            stderr + stdout,
            re.IGNORECASE,
        ))

        found = re.findall(
            r"\[(\d+)\]\[(\w+)\]\s+host:\s+(\S+)\s+login:\s+(\S+)\s+password:\s+(\S*)",
            stdout,
        )

        if connection_failed:
            lines = [
                "### ZWERYFIKOWANE FAKTY: WYNIK HYDRA_SSH (NIEPODWAZALNE, wyciagniete automatycznie)",
                f"- Target: {target}:{port}",
                f"- Komenda: {command}",
                f"- Status wykonania wg pentest-agenta: {status} (returncode={returncode})",
                "- BLAD POLACZENIA WYKRYTY W STDERR/STDOUT: hydra NIE POLACZYLA SIE z celem "
                "(timeout/connection refused/brak trasy) - NIE WYKONANO ZADNEJ PROBY logowania.",
                "KRYTYCZNY ZAKAZ: mimo ze pole techniczne \"status\" moze pokazywac \"ok\" "
                "(bo returncode 255 jest traktowany jako prawidlowe zakonczenie hydry rowniez "
                "przy braku polaczenia), w RZECZYWISTOSCI test higieny hasel SIE NIE ODBYL. "
                "BEZWZGLEDNIE ZABRONIONE jest pisanie w raporcie, ze \"nie wykazano podatnosci\", "
                "\"haslo nie zostalo zlamane\" lub cokolwiek sugerujacego wykonany test - napisz "
                "wprost: \"Test hydra_ssh NIE POWIODL SIE - serwer SSH byl nieosiagalny "
                "(timeout/brak polaczenia), zero prob logowania zostalo wykonanych. Wymagana "
                "weryfikacja dostepnosci uslugi SSH i ponowienie testu.\"",
                "### KONIEC ZWERYFIKOWANYCH FAKTOW HYDRA_SSH",
            ]
            return "\n".join(lines)

        lines = [
            "### ZWERYFIKOWANE FAKTY: WYNIK HYDRA_SSH (NIEPODWAZALNE, wyciagniete automatycznie)",
            f"- Target: {target}:{port}",
            f"- Komenda: {command}",
            f"- Status wykonania: {status} (returncode={returncode})",
            f"- Liczba ZNALEZIONYCH par login/haslo: {len(found)}",
        ]
        if found:
            lines.append("- PELNA LISTA znalezionych par (WYPISZ KAZDA W RAPORCIE jako OSOBNA linia):")
            for i, (p, proto, host, login, password) in enumerate(found, 1):
                lines.append(f"  {i}. login: {login} / haslo: {password} (port {p}/{proto}, host {host})")
            lines.append(
                "KRYTYCZNE RYZYKO: znaleziono DZIALAJACE dane logowania SSH - to powazna "
                "podatnosc (slabe/domyslne haslo), wymaga natychmiastowej zmiany hasla."
            )
        else:
            lines.append(
                "- BRAK znalezionych par login/haslo w przetestowanej liscie "
                "(narzedzie NIE znalazlo dzialajacych danych logowania z uzytej listy)."
            )
            lines.append(
                "BEZWZGLEDNY ZAKAZ: NIE WOLNO Ci podawac w raporcie zadnego loginu ani "
                "hasla jako 'znalezionego' lub 'dzialajacego' - hydra nie znalazla "
                "zadnej pasujacej pary. Napisz wprost, ze test higieny hasel NIE wykazal "
                "podatnosci na uzytej liscie (co NIE oznacza, ze haslo jest silne - "
                "oznacza tylko, ze nie pasuje do przetestowanych kombinacji)."
            )
        lines.append("### KONIEC ZWERYFIKOWANYCH FAKTOW HYDRA_SSH")
        return "\n".join(lines)
    return ""


_CONNECTION_FAILURE_PATTERN = re.compile(
    r"could not connect|Timeout connecting|Connection refused|"
    r"No route to host|Network is unreachable|Connection timed out|"
    r"Failed to connect|Couldn't connect to server|"
    r"Empty reply from server|Could not resolve host|"
    r"Unable to connect|unable to connect to|"
    r"Connection reset by peer|Connection aborted|"
    r"Host is down|Operation timed out|"
    r"errno.*connection|Name or service not known",
    re.IGNORECASE,
)

_CONNECTION_GUARD_SKIP_TOOLS = {
    "hydra_ssh",
    "nmap_scan_ip",
    "nmap_vuln_scan",
    "nmap_stealth_scan",
}


def extract_and_format_connection_guard(raw: str) -> str:
    """Generyczna siatka bezpieczenstwa dla WSZYSTKICH narzedzi pentestowych
    bez dedykowanego parsera tresci (patrz _CONNECTION_GUARD_SKIP_TOOLS za
    liste wyjatkow, ktore maja juz wlasna, bardziej szczegolowa obsluge).

    DLACZEGO TO ISTNIEJE:
    Zaobserwowane na hydra_ssh (patrz extract_and_format_hydra_block) -
    narzedzia pentestowe czesto zwracaja "status": "ok" i "returncode" z
    listy ok_returncodes NAWET GDY nie udalo sie polaczyc z celem (dla
    wielu narzedzi brak polaczenia to normalne, "poprawne" zakonczenie
    procesu, nie blad w sensie kodu wyjscia). Bez tej siatki model widzi
    tylko "status": "ok" i pusty/krotki stdout, i moze to zinterpretowac
    jako "przeskanowano, nic nie znaleziono" - co jest falszywym,
    mylacym wynikiem bezpieczenstwa (gorszym niz brak wyniku w ogole).
    Ta funkcja dziala dla KAZDEGO narzedzia z polem "tool" nie znajdujacym
    sie na liscie wyjatkow - wykrywa typowe komunikaty bledu polaczenia
    w stderr/stdout i wstrzykuje jednoznaczny zakaz raportowania "czysto"
    dla tego konkretnego wyniku."""
    failures = []
    seen_keys = set()
    for obj in _find_json_objects(raw):
        tool = obj.get("tool")
        if not tool or tool in _CONNECTION_GUARD_SKIP_TOOLS:
            continue
        stdout = obj.get("stdout", "") or ""
        stderr = obj.get("stderr", "") or ""
        if not isinstance(stdout, str) or not isinstance(stderr, str):
            continue
        if not _CONNECTION_FAILURE_PATTERN.search(stdout + stderr):
            continue

        target = obj.get("params", {}).get("target", "brak danych")
        command = obj.get("command", "brak danych")
        status = obj.get("status", "brak danych")
        returncode = obj.get("returncode")

        match = _CONNECTION_FAILURE_PATTERN.search(stdout + stderr)
        error_snippet = match.group(0) if match else "brak danych"

        key = (tool, target, command)
        if key in seen_keys:
            continue
        seen_keys.add(key)

        failures.append((tool, target, command, status, returncode, error_snippet))

    if not failures:
        return ""

    lines = [
        "### ZWERYFIKOWANE FAKTY: BLAD POLACZENIA WYKRYTY AUTOMATYCZNIE (NIEPODWAZALNE)",
        f"- Liczba narzedzi z wykrytym bledem polaczenia w tym przebiegu: {len(failures)}",
    ]
    for tool, target, command, status, returncode, error_snippet in failures:
        lines.append(
            f"  - Narzedzie: {tool} | Cel: {target} | Status wg agenta: {status} "
            f"(returncode={returncode}) | Wykryty blad: \"{error_snippet}\""
        )
    lines.append(
        "KRYTYCZNY ZAKAZ: dla KAZDEGO z powyzszych narzedzi, niezaleznie od tego, ze "
        "pole techniczne \"status\" moze pokazywac \"ok\", w RZECZYWISTOSCI narzedzie "
        "NIE POLACZYLO SIE z celem - skan/test SIE NIE WYKONAL. BEZWZGLEDNIE ZABRONIONE "
        "jest pisanie w raporcie dla tych narzedzi jakichkolwiek sformulowan sugerujacych "
        "wykonany test (np. \"nie znaleziono podatnosci\", \"brak wynikow\", \"czysto\", "
        "\"serwer wyglada bezpiecznie\"). Zamiast tego NAPISZ WPROST dla kazdego z nich: "
        "\"Test [nazwa narzedzia] NIE POWIODL SIE - cel byl nieosiagalny (blad polaczenia), "
        "zero danych zostalo zebranych. Wymagana weryfikacja dostepnosci celu i ponowienie testu.\""
    )
    lines.append("### KONIEC ZWERYFIKOWANYCH FAKTOW - BLAD POLACZENIA")
    return "\n".join(lines)
