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
            usernames_str = ", ".join(u.get("username", "?") for u in human_users) if human_users else "brak"
            lines.append(
                f"UZYWAJ WYLACZNIE powyzszej listy uzytkownikow ({usernames_str}) w raporcie. "
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
            match = re.match(r"^(\d+)/(tcp|udp)\s+open\s+(\S+)(?:\s+(.+))?$", line.strip())
            if match:
                port, proto, service = match.group(1), match.group(2), match.group(3)
                version = (match.group(4) or "").strip()
                open_ports.append((int(port), proto, service, version))

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
            for i, (port, proto, service, version) in enumerate(open_ports, 1):
                version_str = f", wersja: {version}" if version else ""
                lines.append(f"  {i}. port {port}/{proto} (usluga: {service}{version_str})")
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


_NUCLEI_LINE_RE = re.compile(
    r"^\[([\w.:-]+)\]\s*\[(\w+)\]\s*\[(\w+)\]\s*(\S+)(?:\s*(\[.*\]))?\s*$"
)


def extract_and_format_nuclei_block(raw: str) -> str:
    """Parsuje wynik nuclei_scan (linie tekstowe w formacie
    [template] [protokol] [severity] url [szczegoly]) - wyciaga
    ustrukturyzowana liste znalezisk zamiast pozwalac modelowi
    przepisywac surowy tekst.

    WAZNE (naprawiono 2026-09-13, test na Metasploitable2): parsowanie
    dziala LINIA PO LINII (nie jeden regex na caly stdout). Poprzednia
    wersja uzywala re.findall na calym tekscie ze znakiem backslash-s-gwiazdka przed opcjonalnym
    nawiasem szczegolow - znak backslash-s dopasowuje rowniez znak nowej linii, wiec
    gdy jakas linia nie miala wlasnego nawiasu szczegolow (typowe dla
    znaleziskach protokolu tcp/javascript bez dodatkowych danych),
    regex "przeciekal" i chwytal poczatek NASTEPNEJ linii jako szczegoly
    biezacego wpisu - a ta nastepna linia znikala calkowicie z listy.
    Na realnym skanie Metasploitable2 (29 znaleziska) to obcinalo wynik
    do 19 pozycji, gubiac m.in. ftp-anonymous-login i kilka wpisow
    pgsql-default-db. Parsowanie linia-po-linii fizycznie eliminuje
    mozliwosc przeciekania miedzy wpisami."""
    for obj in _find_json_objects(raw):
        if obj.get("tool") != "nuclei_scan":
            continue
        stdout = obj.get("stdout") or ""
        findings = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            m = _NUCLEI_LINE_RE.match(line)
            if m:
                findings.append(m.groups())
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
        if obj.get("tool") not in ("hydra_ssh", "hydra_ftp"):
            continue
        stdout = obj.get("stdout", "")
        if not isinstance(stdout, str):
            continue

        tool_name = obj.get("tool")
        protocol_label = "FTP" if tool_name == "hydra_ftp" else "SSH"
        header_tag = f"WYNIK {tool_name.upper()}"
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
                f"### ZWERYFIKOWANE FAKTY: {header_tag} (NIEPODWAZALNE, wyciagniete automatycznie)",
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
                f"### KONIEC ZWERYFIKOWANYCH FAKTOW {tool_name.upper()}",
            ]
            return "\n".join(lines)

        lines = [
            f"### ZWERYFIKOWANE FAKTY: {header_tag} (NIEPODWAZALNE, wyciagniete automatycznie)",
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
        lines.append(f"### KONIEC ZWERYFIKOWANYCH FAKTOW {tool_name.upper()}")
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


def extract_and_format_sqlmap_block(raw: str) -> str:
    """Szuka wynikow sqlmap_scan (pentest-agent /run_tool) w raw_results i
    zwraca gotowy, niepodwazalny blok faktow o SQL injection. Istnieje z
    tego samego powodu co extract_and_format_nmap_block - surowy output
    sqlmapa jest dlugi i latwo przeoczyc/zle zinterpretowac kluczowa
    informacje (czy parametr jest naprawde podatny, jaki DBMS), zwlaszcza
    dla modeli 8-14B. SQL injection to jedna z najpowazniejszych klas
    podatnosci, wiec ten blok NIE moze zalezec od tego, czy model dobrze
    przeczyta surowy tekst."""
    for obj in _find_json_objects(raw):
        tool = obj.get("tool", "")
        stdout = obj.get("stdout", "")
        if not isinstance(stdout, str):
            continue
        if tool != "sqlmap_scan":
            continue

        command = obj.get("command", "brak danych")
        target = obj.get("params", {}).get("target", "brak danych")

        vulnerable = "sqlmap identified the following injection point(s)" in stdout

        lines = [
            f"### ZWERYFIKOWANE FAKTY: WYNIK SQLMAP ({tool}) (NIEPODWAZALNE, wyciagniete automatycznie)",
            f"- Narzedzie: {tool}",
            f"- Target: {target}",
            f"- Komenda: {command}",
            f"- Status: {'SUKCES' if obj.get('returncode') == 0 else 'BLAD'} (returncode={obj.get('returncode')})",
        ]

        if not vulnerable:
            lines.append(
                "- WERDYKT: sqlmap NIE znalazl podatnosci SQL injection na tym URL "
                "przy uzytych ustawieniach (--level/--risk). To NIE oznacza ze "
                "aplikacja jest bezpieczna - wyzszy poziom testow moze wykryc "
                "wiecej, ale przy TYCH ustawieniach brak trafienia. NIE zglaszaj "
                "tego jako 'brak podatnosci SQLi' bez tego zastrzezenia."
            )
            lines.append("### KONIEC ZWERYFIKOWANYCH FAKTOW SQLMAP")
            return "\n".join(lines)

        lines.append(
            "- WERDYKT: sqlmap POTWIERDZIL podatnosc SQL injection (nie przypuszczenie - "
            "faktyczne wstrzykniecie i eksploatacja)."
        )

        param_names = []
        for pname, method in re.findall(r"Parameter:\s*(\S+)\s*\((\w+)\)", stdout):
            label = f"{pname} ({method})"
            if label not in param_names:
                param_names.append(label)
        if param_names:
            lines.append(f"- Podatny(e) parametr(y): {', '.join(param_names)}")

        techniques = re.findall(
            r"Type:\s*(.+?)\n\s*Title:\s*(.+?)\n\s*Payload:\s*(.+?)(?:\n|$)",
            stdout,
        )
        if techniques:
            lines.append("- Wykryte techniki wstrzykniecia (KAZDA to osobny, potwierdzony wektor):")
            for i, (ttype, title, payload) in enumerate(techniques[:10], 1):
                lines.append(f"  {i}. {ttype.strip()} - {title.strip()}")
                lines.append(f"     Payload: {payload.strip()}")

        dbms_match = re.search(r"back-end DBMS:\s*(.+)", stdout)
        if not dbms_match:
            dbms_match = re.search(r"the back-end DBMS is '?([^'\n]+)'?", stdout)
        if dbms_match:
            lines.append(f"- Wykryty DBMS: {dbms_match.group(1).strip()}")

        os_match = re.search(r"web server operating system:\s*(.+)", stdout)
        if os_match:
            lines.append(f"- System operacyjny serwera: {os_match.group(1).strip()}")

        tech_match = re.search(r"web application technology:\s*(.+)", stdout)
        if tech_match:
            lines.append(f"- Technologia aplikacji webowej: {tech_match.group(1).strip()}")

        lines.append(
            "BEZWZGLEDNIE: powyzsza podatnosc SQL injection jest POTWIERDZONYM, "
            "krytycznym/wysokim ryzykiem - MUSI zostac zgloszona jako Finding "
            "w raporcie z pelna lista technik i payloadow powyzej, niezaleznie "
            "od innych wynikow skanowania."
        )
        lines.append("### KONIEC ZWERYFIKOWANYCH FAKTOW SQLMAP")
        return "\n".join(lines)
    return ""


GOBUSTER_MAX_MATCHES = 20


def extract_and_format_gobuster_block(raw: str) -> str:
    """Szuka wynikow gobuster_dir (pentest-agent /run_tool) w raw_results i
    zwraca gotowy, niepodwazalny blok faktow o znalezionych katalogach/plikach.

    W przeciwienstwie do labu testowego (DVWA), na realnej stronie klienta
    liczba trafien moze byc duza - dlatego blok jest limitowany (patrz
    GOBUSTER_MAX_MATCHES) i priorytetyzuje trafienia 200/301/302
    (realnie dostepne zasoby) nad samym potwierdzeniem istnienia sciezki
    zwracajacej 401/403 (istnieje, ale zablokowane - mniej pilne, ale
    nadal warte odnotowania jako powierzchnia ataku)."""
    for obj in _find_json_objects(raw):
        tool = obj.get("tool", "")
        stdout = obj.get("stdout", "")
        if not isinstance(stdout, str):
            continue
        if tool != "gobuster_dir":
            continue

        command = obj.get("command", "brak danych")
        target = obj.get("params", {}).get("target", "brak danych")

        accessible = []   # (path, status, size)
        blocked = []      # (path, status, size)
        for line in stdout.splitlines():
            m = re.match(
                r"^(\S+)\s+\(Status:\s*(\d+)\)\s*\[Size:\s*(\d+)\](?:\s*\[--> (.+)\])?",
                line.strip(),
            )
            if not m:
                continue
            path, status, size, redirect = m.group(1), m.group(2), m.group(3), m.group(4)
            entry = (path, status, size, redirect or "")
            if status in ("401", "403"):
                blocked.append(entry)
            else:
                accessible.append(entry)

        total_found = len(accessible) + len(blocked)

        lines = [
            f"### ZWERYFIKOWANE FAKTY: WYNIK GOBUSTER ({tool}) (NIEPODWAZALNE, wyciagniete automatycznie)",
            f"- Narzedzie: {tool}",
            f"- Target: {target}",
            f"- Komenda: {command}",
            f"- Status: {'SUKCES' if obj.get('returncode') == 0 else 'BLAD'} (returncode={obj.get('returncode')})",
            f"- Lacznie znalezionych sciezek: {total_found}",
        ]

        if total_found == 0:
            lines.append(
                "- WERDYKT: gobuster NIE znalazl zadnych katalogow/plikow z uzytej "
                "wordlisty przy tych ustawieniach. To NIE oznacza braku ukrytych "
                "endpointow - moze wynikac z WAF/rate-limitingu blokujacego skan "
                "albo zbyt malej wordlisty. NIE zglaszaj tego jako 'brak ukrytych "
                "zasobow' bez tego zastrzezenia."
            )
            lines.append("### KONIEC ZWERYFIKOWANYCH FAKTOW GOBUSTER")
            return "\n".join(lines)

        if accessible:
            lines.append(
                f"- DOSTEPNE zasoby (status 200/301/302 - realnie osiagalne, WYPISZ KAZDY):"
            )
            for i, (path, status, size, redirect) in enumerate(accessible[:GOBUSTER_MAX_MATCHES], 1):
                redirect_str = f" -> przekierowanie na {redirect}" if redirect else ""
                lines.append(f"  {i}. {path} (status {status}, {size} bajtow){redirect_str}")
            if len(accessible) > GOBUSTER_MAX_MATCHES:
                lines.append(f"  ... i {len(accessible) - GOBUSTER_MAX_MATCHES} wiecej (ucieto dla zwiezlosci)")

        if blocked:
            lines.append(
                f"- ISTNIEJACE, ale ZABLOKOWANE zasoby (status 401/403 - istnieja, "
                f"potencjalna powierzchnia ataku, ale nie bezposrednio dostepne):"
            )
            for i, (path, status, size, redirect) in enumerate(blocked[:GOBUSTER_MAX_MATCHES], 1):
                lines.append(f"  {i}. {path} (status {status}, {size} bajtow)")
            if len(blocked) > GOBUSTER_MAX_MATCHES:
                lines.append(f"  ... i {len(blocked) - GOBUSTER_MAX_MATCHES} wiecej (ucieto dla zwiezlosci)")

        lines.append("### KONIEC ZWERYFIKOWANYCH FAKTOW GOBUSTER")
        return "\n".join(lines)
    return ""


def extract_and_format_ffuf_block(raw: str) -> str:
    """Szuka wynikow ffuf_fuzz (pentest-agent /run_tool) w raw_results i
    zwraca gotowy, niepodwazalny blok faktow o znalezionych katalogach/
    plikach. Format ffuf rozni sie od gobustera (nawiasy kwadratowe, kody
    ANSI do koloryzacji terminala, ktore trzeba wyciac przed parsowaniem),
    ale logika oceny (dostepne vs zablokowane, limit, ostrzezenie przy
    braku trafien) jest identyczna jak w extract_and_format_gobuster_block."""
    for obj in _find_json_objects(raw):
        tool = obj.get("tool", "")
        stdout = obj.get("stdout", "")
        if not isinstance(stdout, str):
            continue
        if tool != "ffuf_fuzz":
            continue

        command = obj.get("command", "brak danych")
        target = obj.get("params", {}).get("target", "brak danych")

        clean_stdout = re.sub(r"\x1b\[[0-9;]*[a-zA-Z]", "", stdout)

        accessible = []
        blocked = []
        for line in clean_stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            m = re.match(
                r"^(\S*)\s*\[Status:\s*(\d+),\s*Size:\s*(\d+),\s*Words:\s*(\d+),\s*Lines:\s*(\d+),\s*Duration:\s*(\d+)ms\]",
                line,
            )
            if not m:
                continue
            path, status, size = m.group(1), m.group(2), m.group(3)
            path_label = path if path else "(pusta wartosc FUZZ - katalog glowny)"
            entry = (path_label, status, size)
            if status == "403":
                blocked.append(entry)
            else:
                accessible.append(entry)

        total_found = len(accessible) + len(blocked)

        lines = [
            f"### ZWERYFIKOWANE FAKTY: WYNIK FFUF ({tool}) (NIEPODWAZALNE, wyciagniete automatycznie)",
            f"- Narzedzie: {tool}",
            f"- Target: {target}",
            f"- Komenda: {command}",
            f"- Status: {'SUKCES' if obj.get('returncode') == 0 else 'BLAD'} (returncode={obj.get('returncode')})",
            f"- Lacznie znalezionych sciezek: {total_found}",
        ]

        if total_found == 0:
            lines.append(
                "- WERDYKT: ffuf NIE znalazl zadnych katalogow/plikow z uzytej "
                "wordlisty przy tych ustawieniach. To NIE oznacza braku ukrytych "
                "endpointow - moze wynikac z WAF/rate-limitingu blokujacego skan "
                "albo zbyt malej wordlisty. NIE zglaszaj tego jako 'brak ukrytych "
                "zasobow' bez tego zastrzezenia."
            )
            lines.append("### KONIEC ZWERYFIKOWANYCH FAKTOW FFUF")
            return "\n".join(lines)

        if accessible:
            lines.append("- DOSTEPNE zasoby (status 200/301/302 - realnie osiagalne, WYPISZ KAZDY):")
            for i, (path, status, size) in enumerate(accessible[:GOBUSTER_MAX_MATCHES], 1):
                lines.append(f"  {i}. {path} (status {status}, {size} bajtow)")
            if len(accessible) > GOBUSTER_MAX_MATCHES:
                lines.append(f"  ... i {len(accessible) - GOBUSTER_MAX_MATCHES} wiecej (ucieto dla zwiezlosci)")

        if blocked:
            lines.append(
                "- ISTNIEJACE, ale ZABLOKOWANE zasoby (status 403 - istnieja, "
                "potencjalna powierzchnia ataku, ale nie bezposrednio dostepne):"
            )
            for i, (path, status, size) in enumerate(blocked[:GOBUSTER_MAX_MATCHES], 1):
                lines.append(f"  {i}. {path} (status {status}, {size} bajtow)")
            if len(blocked) > GOBUSTER_MAX_MATCHES:
                lines.append(f"  ... i {len(blocked) - GOBUSTER_MAX_MATCHES} wiecej (ucieto dla zwiezlosci)")

        lines.append("### KONIEC ZWERYFIKOWANYCH FAKTOW FFUF")
        return "\n".join(lines)
    return ""


def extract_and_format_enum4linux_block(raw: str) -> str:
    """Szuka wynikow enum4linux_scan (pentest-agent /run_tool) w raw_results
    i zwraca gotowy, niepodwazalny blok faktow o enumeracji SMB.

    Zweryfikowano end-to-end na obu sciezkach: negatywnej (DVWA, brak
    sesji SMB) oraz pozytywnej (Metasploitable2, realna enumeracja 35
    uzytkownikow i 5 udzialow sieciowych, sesja 2026-09-13). Trzy bledy
    znalezione i naprawione przy pierwszym pozytywnym tescie: falszywy
    wpis udzialu z komunikatu informacyjnego, limit 20 pozycji obcinajacy
    liste uzytkownikow, zly wzorzec regex dla Domain SID."""
    for obj in _find_json_objects(raw):
        tool = obj.get("tool", "")
        stdout = obj.get("stdout", "")
        if not isinstance(stdout, str):
            continue
        if tool != "enum4linux_scan":
            continue

        command = obj.get("command", "brak danych")
        target = obj.get("params", {}).get("target", "brak danych")
        clean_stdout = re.sub(r"\x1b\[[0-9;]*[a-zA-Z]", "", stdout)

        lines = [
            f"### ZWERYFIKOWANE FAKTY: WYNIK ENUM4LINUX ({tool}) (NIEPODWAZALNE, wyciagniete automatycznie)",
            f"- Narzedzie: {tool}",
            f"- Target: {target}",
            f"- Komenda: {command}",
            f"- Status: {'SUKCES' if obj.get('returncode') == 0 else 'BLAD/BRAK SESJI'} (returncode={obj.get('returncode')})",
        ]

        null_session_denied = "doesn't allow session using username" in clean_stdout
        no_workgroup = "Can't find workgroup/domain" in clean_stdout

        if null_session_denied and no_workgroup:
            lines.append(
                "- WERDYKT: cel NIE przyjmuje sesji SMB (null session) - serwer "
                "odrzucil polaczenie z pustym uzytkownikiem/haslem. To POZYTYWNA "
                "informacja bezpieczenstwa (null session jest wylaczona), nie "
                "brak wyniku. Mozliwe rowniez ze port SMB (139/445) jest "
                "zamkniety/nieosiagalny - w obu przypadkach dalsza enumeracja "
                "SMB nie powiodla sie."
            )
            lines.append("### KONIEC ZWERYFIKOWANYCH FAKTOW ENUM4LINUX")
            return "\n".join(lines)

        share_section_match = re.search(
            r"Sharename\s+Type\s+Comment\s*\n\s*-+\s+-+\s+-+\s*\n(.*?)(?:\n\s*\n|\nReconnecting|\n[A-Z][a-z]+ing with)",
            clean_stdout,
            re.DOTALL,
        )
        share_lines = []
        if share_section_match:
            # Kazda prawdziwa linia udzialu zaczyna sie (po wcieciu) od nazwy
            # bez spacji, potem typu Disk/IPC/Printers - odrzucamy linie
            # ktore nie pasuja do tego wzorca (np. komunikaty informacyjne
            # ktore czasem trafiaja sie tuz po tabeli bez pustej linii miedzy).
            for sline in share_section_match.group(1).splitlines():
                sline = sline.strip()
                if not sline:
                    continue
                if re.match(r"^\S+\s+(Disk|IPC|Printer)\b", sline):
                    share_lines.append(sline)
        if share_lines:
            lines.append(f"- ZNALEZIONE UDZIALY SIECIOWE (SMB shares, {len(share_lines)}, WYPISZ KAZDY):")
            for i, s in enumerate(share_lines, 1):
                lines.append(f"  {i}. {s}")

        users = re.findall(r"user:\[([^\]]+)\]", clean_stdout)
        if users:
            unique_users = list(dict.fromkeys(users))
            lines.append(f"- Liczba znalezionych unikalnych uzytkownikow: {len(unique_users)}")
            lines.append(f"- ZNALEZIENI UZYTKOWNICY (enumeracja RID, WYPISZ WSZYSTKICH {len(unique_users)}): {', '.join(unique_users)}")

        min_pw_len = re.search(r"Minimum password length:\s*(\S+)", clean_stdout)
        lockout = re.search(r"Account lockout threshold:\s*(\S+)", clean_stdout)
        if min_pw_len or lockout:
            lines.append("- POLITYKA HASEL:")
            if min_pw_len:
                lines.append(f"  - Minimalna dlugosc hasla: {min_pw_len.group(1)}")
            if lockout:
                lines.append(f"  - Prog blokady konta: {lockout.group(1)}")

        domain_sid = re.search(r"Found new SID:\s*\n(S-\d[-\d]+)", clean_stdout)
        if not domain_sid:
            domain_sid = re.search(r"Domain Sid:\s*(\S+)", clean_stdout)
        if domain_sid:
            lines.append(f"- Domain SID: {domain_sid.group(1)}")

        if not share_lines and not users and not (min_pw_len or lockout) and not domain_sid:
            lines.append(
                "- WERDYKT: enum4linux zakonczyl dzialanie, ale parser nie rozpoznal "
                "zadnej znanej sekcji z wynikami (shares/users/password policy). "
                "MOZLIWE ze sesja zostala nawiazana, ale nic nie wyekstrahowano - "
                "sprawdz pelny surowy wynik recznie, NIE zaklada automatycznie "
                "braku podatnosci."
            )

        lines.append("### KONIEC ZWERYFIKOWANYCH FAKTOW ENUM4LINUX")
        return "\n".join(lines)
    return ""


def extract_and_format_nikto_block(raw: str) -> str:
    """Szuka wynikow nikto_scan (pentest-agent /run_tool) w raw_results
    i zwraca gotowy blok faktow o wynikach skanu web.

    Oparty na standardowym formacie nikto 2.x. Zweryfikowany end-to-end
    na realnym skanie DVWA (nikto v2.6.1, 13 findingow) w sesji 2026-09-08 -
    dwie poprawki regexow wprowadzone po tym tescie (dopasowanie linii
    podsumowania bez nawiasow, filtrowanie linii metadanych Platform:/
    CGI Directories jako falszywych findingow). Rownie pewny jak
    sqlmap/gobuster/ffuf/enum4linux."""
    for obj in _find_json_objects(raw):
        tool = obj.get("tool", "")
        stdout = obj.get("stdout", "")
        if not isinstance(stdout, str):
            continue
        if tool != "nikto_scan":
            continue

        command = obj.get("command", "brak danych")
        target = obj.get("params", {}).get("target", "brak danych")
        clean_stdout = re.sub(r"\x1b\[[0-9;]*[a-zA-Z]", "", stdout)

        lines = [
            f"### ZWERYFIKOWANE FAKTY: WYNIK NIKTO ({tool}) (NIEPODWAZALNE, wyciagniete automatycznie)",
            f"- Narzedzie: {tool}",
            f"- Target: {target}",
            f"- Komenda: {command}",
            f"- Status: {'SUKCES' if obj.get('returncode') == 0 else 'BLAD'} (returncode={obj.get('returncode')})",
        ]

        server_match = re.search(r"^\+ Server:\s*(.+)$", clean_stdout, re.MULTILINE)
        if server_match:
            lines.append(f"- Naglowek Server: {server_match.group(1).strip()}")

        skip_prefixes = (
            "+ Target IP:", "+ Target Hostname:", "+ Target Port:",
            "+ Start Time:", "+ End Time:", "+ Server:",
            "+ Multiple IPs found", "+ Platform:",
            "+ No CGI Directories found",
        )
        finding_lines = []
        for line in clean_stdout.splitlines():
            line = line.strip()
            if not line.startswith("+ "):
                continue
            if line.startswith(skip_prefixes):
                continue
            if re.match(r"^\+\s*\d+\s+requests?:", line):
                continue
            if re.match(r"^\+\s*\d+\s+host\(s\)\s+tested", line):
                continue
            finding_lines.append(line[2:].strip())

        summary_match = re.search(
            r"(\d+)\s+requests?:\s*(\d+)\s+errors?\s+and\s+(\d+)\s+items?\s+reported",
            clean_stdout,
        )

        if finding_lines:
            lines.append(f"- ZNALEZIONE PROBLEMY ({len(finding_lines)}, WYPISZ KAZDY):")
            for i, f in enumerate(finding_lines, 1):
                lines.append(f"  {i}. {f}")
        else:
            lines.append(
                "- WERDYKT: nikto nie zwrocil zadnych linii findingow (+) poza "
                "metadanymi. Sprawdz returncode i surowy output recznie - moze "
                "to oznaczac brak podatnosci, ale rowniez blad polaczenia z "
                "targetem."
            )

        if summary_match:
            req, err, items = summary_match.groups()
            lines.append(
                f"- Podsumowanie nikto: {req} zapytan, {err} blad(ow), {items} "
                f"zgloszonych elementow"
            )

        lines.append("### KONIEC ZWERYFIKOWANYCH FAKTOW NIKTO")
        return "\n".join(lines)
    return ""


def extract_and_format_whatweb_block(raw: str) -> str:
    """Szuka wynikow whatweb_scan w raw_results i zwraca gotowy,
    niepodwazalny blok faktow o wykrytych technologiach/wtyczkach.

    Format whatweb: jedna linia na kazdy przetestowany URL (whatweb
    podaza za przekierowaniami), z kolorowanymi kodami ANSI, kodem
    statusu HTTP w nawiasach kwadratowych, i lista wtyczek oddzielonych
    przecinkiem w formacie Plugin[wartosc] lub samo Plugin bez wartosci."""
    for obj in _find_json_objects(raw):
        tool = obj.get("tool", "")
        stdout = obj.get("stdout", "")
        if not isinstance(stdout, str):
            continue
        if tool != "whatweb_scan":
            continue

        command = obj.get("command", "brak danych")
        target = obj.get("params", {}).get("target", "brak danych")
        clean_stdout = re.sub(r"\x1b\[[0-9;]*[a-zA-Z]", "", stdout)

        lines = [
            f"### ZWERYFIKOWANE FAKTY: WYNIK WHATWEB ({tool}) (NIEPODWAZALNE, wyciagniete automatycznie)",
            f"- Narzedzie: {tool}",
            f"- Target: {target}",
            f"- Komenda: {command}",
            f"- Status: {'SUKCES' if obj.get('returncode') == 0 else 'BLAD'} (returncode={obj.get('returncode')})",
        ]

        url_matches = re.findall(
            r"^(https?://\S+)\s+\[(\d+)[^\]]*\]\s+(.+)$",
            clean_stdout,
            re.MULTILINE,
        )

        if not url_matches:
            lines.append(
                "- WERDYKT: whatweb nie zwrocil zadnych rozpoznanych URL-i/technologii "
                "(mozliwe ze cel jest nieosiagalny albo nie odpowiada na HTTP)."
            )
            lines.append("### KONIEC ZWERYFIKOWANYCH FAKTOW WHATWEB")
            return "\n".join(lines)

        lines.append(f"- Liczba przetestowanych URL-i (wliczajac przekierowania): {len(url_matches)}")
        lines.append("- WYKRYTE TECHNOLOGIE/WTYCZKI (WYPISZ KAZDY URL Z JEGO PELNA LISTA):")

        for i, (url, status, plugins_raw) in enumerate(url_matches, 1):
            plugins = [p.strip() for p in plugins_raw.split(",") if p.strip()]
            plugins_str = ", ".join(plugins) if plugins else "brak wykrytych wtyczek"
            lines.append(f"  {i}. {url} [HTTP {status}]: {plugins_str}")

        lines.append(
            f"UZYWAJ WYLACZNIE powyzszej listy {len(url_matches)} URL-i i ich wtyczek. "
            f"NIE zmyslaj innych technologii/wersji ktorych nie ma na tej liscie."
        )
        lines.append("### KONIEC ZWERYFIKOWANYCH FAKTOW WHATWEB")
        return "\n".join(lines)
    return ""


def extract_and_format_wafw00f_block(raw: str) -> str:
    """Szuka wynikow wafw00f_scan w raw_results i zwraca gotowy,
    niepodwazalny blok faktow o wykrytym (lub nie) WAF-ie.

    Format: stdout to gotowy JSON (wafw00f -f json), lista obiektow
    z polami detected/firewall/manufacturer/trigger_url/url - prostszy
    niz wiekszosc innych narzedzi, nie wymaga regexow tekstowych."""
    for obj in _find_json_objects(raw):
        tool = obj.get("tool", "")
        stdout = obj.get("stdout", "")
        if not isinstance(stdout, str):
            continue
        if tool != "wafw00f_scan":
            continue

        command = obj.get("command", "brak danych")
        target = obj.get("params", {}).get("target", "brak danych")

        lines = [
            f"### ZWERYFIKOWANE FAKTY: WYNIK WAFW00F ({tool}) (NIEPODWAZALNE, wyciagniete automatycznie)",
            f"- Narzedzie: {tool}",
            f"- Target: {target}",
            f"- Komenda: {command}",
            f"- Status: {'SUKCES' if obj.get('returncode') == 0 else 'BLAD'} (returncode={obj.get('returncode')})",
        ]

        try:
            results = json.loads(stdout)
        except (json.JSONDecodeError, ValueError):
            lines.append(
                "- BLAD: nie udalo sie sparsowac wyniku wafw00f jako JSON. "
                "NIE zmyslaj wykrytego WAF-u - zglos to jako brak wyniku."
            )
            lines.append("### KONIEC ZWERYFIKOWANYCH FAKTOW WAFW00F")
            return "\n".join(lines)

        if not isinstance(results, list) or not results:
            lines.append(
                "- WERDYKT: wafw00f nie zwrocil zadnych wynikow dla tego celu."
            )
            lines.append("### KONIEC ZWERYFIKOWANYCH FAKTOW WAFW00F")
            return "\n".join(lines)

        any_detected = any(r.get("detected") for r in results)
        lines.append(f"- Liczba sprawdzonych URL-i: {len(results)}")

        if any_detected:
            lines.append("- WERDYKT: WYKRYTO zapore aplikacji webowej (WAF). Szczegoly:")
            for r in results:
                if r.get("detected"):
                    fw = r.get("firewall", "nieznany")
                    manu = r.get("manufacturer", "nieznany")
                    lines.append(f"  - {r.get('url', target)}: {fw} (producent: {manu})")
            lines.append(
                "UWAGA: obecnosc WAF-a moze wplywac na wyniki innych skanerow "
                "(np. blokowac/maskowac prawdziwe podatnosci) - uwzglednij to "
                "w interpretacji pozostalych wynikow."
            )
        else:
            lines.append(
                "- WERDYKT: NIE wykryto zapory aplikacji webowej (WAF) na tym celu "
                "przy uzytych ustawieniach. To NIE jest dowod ze WAF na pewno nie istnieje "
                "- niektore WAF-y sa trudne do wykrycia."
            )

        lines.append("### KONIEC ZWERYFIKOWANYCH FAKTOW WAFW00F")
        return "\n".join(lines)
    return ""


def extract_and_format_nmap_vuln_block(raw: str) -> str:
    """Parsuje wynik nmap_vuln_scan (--script vuln) - wyciaga liste
    potwierdzonych podatnosci (VULNERABLE) z nazwy skryptu NSE, tytulu,
    stanu i identyfikatorow CVE/BID jesli sa dostepne.

    Format nmap NSE dla znaleziska podatnosci:
      | nazwa-skryptu:
      |   VULNERABLE:
      |   Tytul podatnosci
      |     State: VULNERABLE (lub VULNERABLE (Exploitable) / LIKELY VULNERABLE)
      |     IDs:  BID:xxx  CVE:CVE-xxxx-xxxx   [opcjonalne]

    WAZNE: skrypty NSE zwracaja tez linie w stylu 'NOT VULNERABLE' dla
    testow ktore nie wykryly problemu (np. smtp-vuln-cve2010-4344) -
    parser musi je jawnie pomijac, nie tylko szukac slowa VULNERABLE
    gdziekolwiek w tekscie (bezposrednia przyczyna bledu w nuclei_scan
    z 2026-09-13 - regex bez odpowiedniego kontekstu linii).

    Osobno: blok 'vulners:' (agregacja CVE z bazy Vulners per uslyga,
    czesto setki identyfikatorow) jest tylko ZLICZANY, nie wypisywany
    w calosci - zbyt duzy do czytelnego raportu (patrz test na
    Metasploitable2: 915 wzmianek CVE w jednym skanie)."""
    for obj in _find_json_objects(raw):
        if obj.get("tool") != "nmap_vuln_scan":
            continue
        stdout = obj.get("stdout") or ""
        target = obj.get("params", {}).get("target", "brak danych")
        command = obj.get("command", "brak danych")

        lines_raw = stdout.splitlines()
        findings = []
        vulners_cve_count = 0

        i = 0
        while i < len(lines_raw):
            line = lines_raw[i].rstrip()
            stripped = line.lstrip("|").strip()

            # Naglowek skryptu NSE: "| nazwa-skryptu:" (moze miec spacje po dwukropku)
            if line.startswith("| ") and stripped.endswith(":"):
                script_name = stripped.rstrip(":").strip()

                if script_name == "vulners":
                    vulners_cve_count += stdout[
                        stdout.find(lines_raw[i]) : stdout.find(lines_raw[i]) + 2000
                    ].count("CVE-")

                # Sprawdz czy nastepna niepusta linia to "VULNERABLE:"
                if i + 1 < len(lines_raw) and lines_raw[i + 1].strip().rstrip(":") == "|   VULNERABLE".rstrip(":"):
                    pass

                if i + 1 < len(lines_raw) and "VULNERABLE:" in lines_raw[i + 1] and "NOT VULNERABLE" not in lines_raw[i + 1]:
                    title = lines_raw[i + 2].lstrip("|").strip() if i + 2 < len(lines_raw) else ""
                    state = ""
                    cve_ids = ""
                    for j in range(i + 3, min(i + 8, len(lines_raw))):
                        probe = lines_raw[j].lstrip("|").strip()
                        if probe.startswith("State:"):
                            state = probe.replace("State:", "").strip()
                        elif probe.startswith("IDs:"):
                            cve_ids = probe.replace("IDs:", "").strip()
                            break
                        elif probe == "" or probe.startswith("Disclosure"):
                            break
                    # Znajdz najblizszy port/usluge WSTECZ od tego miejsca
                    # (nmap grupuje wyniki skryptow NSE pod naglowkiem portu,
                    # np. "25/tcp   open  smtp   Postfix smtpd").
                    port_context = "nieznany port"
                    for j in range(i, max(0, i - 500), -1):
                        probe_line = lines_raw[j]
                        if "/tcp" in probe_line and "open" in probe_line:
                            port_context = probe_line.strip()
                            break
                    findings.append((script_name, title, state, cve_ids, port_context))
                elif "NOT VULNERABLE" in (lines_raw[i + 1] if i + 1 < len(lines_raw) else ""):
                    pass
            i += 1

        lines = [
            "### ZWERYFIKOWANE FAKTY: NMAP VULN SCAN (wyciagniete automatycznie, NIEPODWAZALNE)",
            f"- Target: {target}",
            f"- Komenda: {command}",
            f"- Status: {'SUKCES' if obj.get('returncode') == 0 else 'BLAD'} (returncode={obj.get('returncode')})",
            f"- Liczba POTWIERDZONYCH podatnosci (VULNERABLE): {len(findings)}",
        ]

        if findings:
            lines.append("- LISTA POTWIERDZONYCH PODATNOSCI (WYPISZ KAZDA):")
            for i, (script, title, state, cve_ids, port_ctx) in enumerate(findings, 1):
                cve_part = f" [{cve_ids}]" if cve_ids else ""
                lines.append(f"  {i}. {script}: {title} - {state}{cve_part} (port: {port_ctx})")
        else:
            lines.append("- Brak potwierdzonych podatnosci (VULNERABLE) w tym skanie.")

        if vulners_cve_count > 0:
            lines.append(
                f"- Dodatkowo: baza Vulners zglosila laczne odniesienia do CVE dla "
                f"wykrytych wersji oprogramowania (orientacyjna, zagregowana liczba "
                f"wzmianek w calym wyniku: {stdout.count('CVE-')}) - PEŁNA lista NIE jest "
                f"tu wypisana (zbyt duza, setki pozycji), wspomnij to jako ogolna "
                f"obserwacje 'wykryto oprogramowanie z duza liczba znanych CVE w bazach "
                f"podatnosci', NIE wypisuj pojedynczych identyfikatorow ktorych nie ma "
                f"na liscie powyzej."
            )

        lines.append(
            f"UZYWAJ WYLACZNIE powyzszej listy {len(findings)} potwierdzonych podatnosci "
            f"jako 'VULNERABLE' w raporcie. NIE zmyslaj innych CVE/podatnosci ktorych "
            f"nie ma na tej liscie. NIE myl 'VULNERABLE' z 'NOT VULNERABLE' (to przeciwny wynik)."
        )
        return "\n".join(lines)
    return ""
