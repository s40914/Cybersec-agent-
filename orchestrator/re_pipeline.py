from __future__ import annotations

import csv
import hashlib
import json
import logging
import os
import re
import subprocess
from pathlib import Path
from uuid import uuid4
from typing import Any

from evidence_store import EvidenceStore
from security_models import Artifact, RawResult

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------
# Limity digestu dowodowego przekazywanego dalej do pipeline'u LLM.
# Pełne, nieprzycięte dane narzędzi (objdump, cały strings, cały nm)
# NIGDY nie trafiają do promptu LLM - zostają zapisane osobno na
# dysku (patrz _persist_full_raw) i pozostają dostępne do ręcznej
# analizy lub przyszłych, potężniejszych narzędzi RE.
# ------------------------------------------------------------------
MAX_MATCHES_PER_CATEGORY = 20      # ile unikalnych URL/IP/symboli max
MAX_STRING_SAMPLE_CHARS = 8000     # limit próbki interesujących stringów
MAX_DIGEST_TOTAL_CHARS = 20000     # twardy sufit całego digestu (safety net)


class REPipeline:
    """
    Deterministyczny etap RE dla Artifact.

    RE nie jest narzędziem dostępnym dla LLM.
    Pipeline sam wybiera bezpieczne, lokalnie dostępne operacje:
      - file
      - sha256
      - strings
      - readelf
      - nm
      - objdump

    Brak zewnętrznych frameworków RE nie blokuje pipeline.

    Wynik jest dwuwarstwowy:
      - PEŁNY wynik (łącznie z surowym objdump/strings/nm) trafia do
        pliku na dysku (data/re_artifacts/<artifact_id>_raw.json) -
        nic nie ginie, dostępne do ręcznej analizy.
      - DIGEST (ograniczony, ale zawierający KONKRETNE wyekstrahowane
        fakty - adresy, symbole, próbki stringów, nie same flagi
        true/false) trafia do EvidenceStore jako RawResult.stdout i
        stamtąd dalej do security_agent / report_writers / critic.
    """

    ALLOWED_TOOLS = {
        "file": ["file"],
        "strings": ["strings"],
        "readelf": ["readelf"],
        "nm": ["nm"],
        "objdump": ["objdump"],
        "yara": ["yara"],
        "binwalk": ["binwalk"],
    }

    YARA_RULES_PATH = "data/yara_rules/basic.yar"
    MALWARE_HASHES_PATH = "data/malware_hashes/known_hashes.csv"

    # Cache znanych hashy w pamięci procesu - unika ponownego czytania
    # calego known_hashes.csv (rosnie po kazdym imporcie z MalwareBazaar)
    # przy kazdym pojedynczym artefakcie przechodzacym przez pipeline.
    # Invalidowany po mtime pliku, wiec update_malware_db.py dziala bez zmian.
    _hashes_cache: list[dict[str, str]] | None = None
    _hashes_cache_mtime: float | None = None

    def __init__(self, store: EvidenceStore | None = None):
        self.store = store or EvidenceStore()

    @staticmethod
    def _run(cmd: list[str], timeout: int = 30) -> dict[str, Any]:
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            return {
                "returncode": proc.returncode,
                "stdout": proc.stdout,
                "stderr": proc.stderr,
                "status": "ok" if proc.returncode == 0 else "error",
            }
        except FileNotFoundError:
            return {
                "returncode": None,
                "stdout": "",
                "stderr": f"Tool not found: {cmd[0]}",
                "status": "not_available",
            }
        except subprocess.TimeoutExpired:
            return {
                "returncode": None,
                "stdout": "",
                "stderr": f"Timeout: {' '.join(cmd)}",
                "status": "timeout",
            }

    @classmethod
    def _load_known_hashes(cls) -> list[dict[str, str]]:
        """
        Wczytuje known_hashes.csv do pamieci, z cache'owaniem na poziomie
        klasy. Cache jest invalidowany, gdy zmieni sie mtime pliku (np. po
        uruchomieniu update_malware_db.py) - wiec zawsze odzwierciedla
        aktualna zawartosc bazy bez potrzeby restartu procesu.
        """
        path = Path(cls.MALWARE_HASHES_PATH)
        if not path.is_file():
            return []

        try:
            mtime = path.stat().st_mtime
        except OSError:
            return cls._hashes_cache or []

        if cls._hashes_cache is not None and cls._hashes_cache_mtime == mtime:
            return cls._hashes_cache

        try:
            with path.open("r", encoding="utf-8") as f:
                rows = list(csv.DictReader(f))
        except Exception:
            logger.exception("Nie udalo sie wczytac bazy znanych hashy: %s", path)
            return cls._hashes_cache or []

        cls._hashes_cache = rows
        cls._hashes_cache_mtime = mtime
        logger.info("Zaladowano %d wpisow z %s", len(rows), path)
        return rows

    @classmethod
    def _lookup_hash(cls, sha256: str) -> dict[str, Any] | None:
        """
        Sprawdza SHA256 artefaktu przeciw lokalnej bazie znanych hashy
        zlosliwego oprogramowania. Zwraca dane dopasowania albo None.

        To jest pierwszy, najszybszy i najbardziej jednoznaczny etap
        klasyfikacji - identyczny hash oznacza identyczny plik binarny,
        wiec trafienie tutaj jest znacznie silniejszym sygnalem niz
        jakakolwiek heurystyka (YARA, wskazniki stringow, itp).
        """
        sha256_norm = sha256.strip().lower()
        for row in cls._load_known_hashes():
            if row.get("sha256", "").strip().lower() == sha256_norm:
                return {
                    "threat_name": row.get("threat_name", "unknown"),
                    "source": row.get("source", "unknown"),
                    "severity": row.get("severity", "high"),
                }
        return None

    @staticmethod
    def _compute_fuzzy_hash(path: Path) -> str | None:
        try:
            import ssdeep as ssdeep_lib
        except ImportError:
            logger.warning(
                "Biblioteka ssdeep niedostepna w tym srodowisku - "
                "fuzzy hashing pominiety. Sprawdz: pip show ssdeep "
                "oraz obecnosc libfuzzy-dev w systemie."
            )
            return None
        try:
            return ssdeep_lib.hash_from_file(str(path))
        except Exception:
            logger.exception("ssdeep.hash_from_file() nie powiodlo sie dla %s", path)
            return None

    @classmethod
    def _lookup_fuzzy_hash(cls, fuzzy_hash: str | None, threshold: int = 50) -> list[dict[str, Any]]:
        if not fuzzy_hash:
            return []

        try:
            import ssdeep as ssdeep_lib
        except ImportError:
            logger.warning("Biblioteka ssdeep niedostepna - pomijam porownanie fuzzy hash")
            return []

        matches = []
        for row in cls._load_known_hashes():
            row_fuzzy = (row.get("fuzzy_hash") or "").strip()
            if not row_fuzzy:
                continue
            try:
                score = ssdeep_lib.compare(fuzzy_hash, row_fuzzy)
            except Exception:
                continue
            if score >= threshold:
                matches.append({
                    "threat_name": row.get("threat_name", "unknown"),
                    "source": row.get("source", "unknown"),
                    "similarity": score,
                })
        return matches

    def inspect(self, artifact: Artifact) -> dict[str, Any]:
        path = Path(artifact.path)

        if not path.is_file():
            raise FileNotFoundError(f"Artifact nie jest plikiem: {path}")

        result: dict[str, Any] = {
            "artifact_id": artifact.id,
            "thread_id": artifact.thread_id,
            "target": artifact.target,
            "path": str(path),
            "sha256": artifact.sha256,
            "size_bytes": artifact.size_bytes,
            "file_type": artifact.file_type,
            "operations": {},
        }

        # ------------------------------------------------------------
        # FILE
        # ------------------------------------------------------------
        result["operations"]["file"] = self._run(
            ["file", "-b", str(path)]
        )

        # ------------------------------------------------------------
        # STRINGS
        # ------------------------------------------------------------
        strings = self._run(
            ["strings", "-a", "-n", "4", str(path)]
        )
        result["operations"]["strings"] = strings

        # ------------------------------------------------------------
        # YARA - sygnaturowe skanowanie regulami
        # ------------------------------------------------------------
        if Path(self.YARA_RULES_PATH).is_file():
            result["operations"]["yara"] = self._run(
                ["yara", "-m", self.YARA_RULES_PATH, str(path)]
            )
        else:
            result["operations"]["yara"] = {
                "status": "skipped",
                "reason": f"brak pliku regul: {self.YARA_RULES_PATH}",
            }

        # ------------------------------------------------------------
        # BINWALK - wykrywanie osadzonych plikow/archiwow
        # ------------------------------------------------------------
        result["operations"]["binwalk"] = self._run(
            ["binwalk", str(path)], timeout=60
        )

        # ------------------------------------------------------------
        # ELF-specific RE
        # ------------------------------------------------------------
        file_description = (
            result["operations"]["file"].get("stdout", "")
            + " "
            + artifact.file_type
        ).lower()

        is_elf = "elf" in file_description

        if is_elf:
            result["operations"]["readelf"] = self._run(
                ["readelf", "-h", "-S", "-s", str(path)]
            )

            result["operations"]["nm"] = self._run(
                ["nm", "-a", str(path)]
            )

            result["operations"]["objdump"] = self._run(
                ["objdump", "-x", "-d", str(path)]
            )
        else:
            result["operations"]["readelf"] = {
                "status": "skipped",
                "reason": "artifact nie wygląda na ELF",
            }
            result["operations"]["nm"] = {
                "status": "skipped",
                "reason": "artifact nie wygląda na ELF",
            }
            result["operations"]["objdump"] = {
                "status": "skipped",
                "reason": "artifact nie wygląda na ELF",
            }

        # ------------------------------------------------------------
        # HASH LOOKUP - sprawdzenie SHA256 przeciw znanym zagrozeniom
        # ------------------------------------------------------------
        result["hash_lookup"] = self._lookup_hash(artifact.sha256)
        fuzzy_hash = self._compute_fuzzy_hash(path)
        result["fuzzy_hash"] = fuzzy_hash
        result["fuzzy_matches"] = self._lookup_fuzzy_hash(fuzzy_hash)

        # ------------------------------------------------------------
        # DETERMINISTIC SUMMARY
        # ------------------------------------------------------------
        result["summary"] = self._build_summary(result)

        # ------------------------------------------------------------
        # PEŁNE dane -> osobny plik na dysku (nic nie ginie)
        # ------------------------------------------------------------
        full_raw_path = self._persist_full_raw(result, artifact.id)

        # ------------------------------------------------------------
        # DIGEST -> to co faktycznie trafia do LLM (ograniczone, ale
        # z konkretnymi, cytowalnymi faktami, nie samymi flagami)
        # ------------------------------------------------------------
        digest = self._extract_evidence(result)
        digest["full_raw_path"] = full_raw_path

        digest_json = json.dumps(
            digest,
            ensure_ascii=False,
            separators=(",", ":"),
        )

        # Trwały wynik RE zapisywany do EvidenceStore. Nie jest to
        # Finding i nie jest to interpretacja LLM - to deterministyczny
        # digest, ograniczony rozmiarowo, żeby nigdy nie zatkać
        # pipeline'u raportowego (patrz incydent z 2026-08-29:
        # 78MB nieprzyciętego objdump w raw_results).
        raw_result = RawResult(
            id=str(uuid4()),
            thread_id=artifact.thread_id or "",
            tool_name="re_pipeline",
            target=artifact.target,
            params={
                "artifact_id": artifact.id,
                "path": str(path),
                "sha256": artifact.sha256,
            },
            status="ok",
            returncode=0,
            stdout=digest_json,
            stderr="",
            metadata={
                "artifact_id": artifact.id,
                "artifact_sha256": artifact.sha256,
                "artifact_type": artifact.artifact_type,
                "full_raw_path": full_raw_path,
                "full_raw_size_bytes": len(
                    json.dumps(result, ensure_ascii=False)
                ),
                "digest_size_bytes": len(digest_json),
            },
        )
        self.store.save_raw_result(raw_result)

        # Endpoint /artifacts/ingest nadal zwraca pełny `result`
        # synchronicznie w odpowiedzi HTTP - to nie trafia do LLM,
        # więc pełny rozmiar tutaj jest bezpieczny.
        return result

    @staticmethod
    def _persist_full_raw(result: dict[str, Any], artifact_id: str) -> str:
        """
        Zapisuje PEŁNY, nieprzycięty wynik RE (łącznie z objdump/strings/nm)
        jako osobny plik JSON na dysku. Nic z surowych danych nie ginie -
        tylko nie trafia bezpośrednio do promptu LLM.

        Zwraca ścieżkę do zapisanego pliku.
        """
        out_dir = Path("data/re_artifacts")
        out_dir.mkdir(parents=True, exist_ok=True)

        out_path = out_dir / f"{artifact_id}_raw.json"
        with out_path.open("w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, separators=(",", ":"))

        return str(out_path)

    @staticmethod
    def _extract_evidence(result: dict[str, Any]) -> dict[str, Any]:
        """
        Buduje ograniczony, ale KONKRETNY digest dowodowy z surowych
        wyników RE.

        W przeciwieństwie do samego `summary` (flagi true/false), ten
        digest zawiera rzeczywiste, wyekstrahowane fragmenty dowodowe
        (adresy, ścieżki, podejrzane symbole, próbki stringów) - tak,
        żeby model mógł napisać prawdziwy raport z konkretnymi
        ustaleniami, a nie tylko "wykryto ślady".
        """
        strings_text = result["operations"].get("strings", {}).get("stdout", "")
        nm_text = result["operations"].get("nm", {}).get("stdout", "")
        readelf_text = result["operations"].get("readelf", {}).get("stdout", "")
        yara_text = result["operations"].get("yara", {}).get("stdout", "")
        binwalk_text = result["operations"].get("binwalk", {}).get("stdout", "")

        def _unique_matches(pattern: str, text: str, flags=re.I) -> list[str]:
            seen: list[str] = []
            for m in re.finditer(pattern, text, flags):
                val = m.group(0)
                if val not in seen:
                    seen.append(val)
                if len(seen) >= MAX_MATCHES_PER_CATEGORY:
                    break
            return seen

        urls = _unique_matches(r"https?://[^\s'\"<>]+", strings_text)
        ips = _unique_matches(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", strings_text)

        suspicious_symbol_pattern = (
            r"\b(?:system|popen|execve|exec[lv]p?e?|fork|socket|connect|"
            r"listen|bind|recv|send|ptrace|mprotect|dlopen|LoadLibrary|"
            r"CreateRemoteThread|VirtualAlloc)\b"
        )
        suspicious_symbols = _unique_matches(
            suspicious_symbol_pattern, nm_text + " " + strings_text
        )

        crypto_terms = _unique_matches(
            r"\b(?:aes|rsa|sha256|sha1|md5|openssl|chacha20|des)\b",
            strings_text,
        )

        interesting_lines: list[str] = []
        total_sample_len = 0
        for line in strings_text.splitlines():
            line = line.strip()
            if len(line) < 6:
                continue
            if not re.search(r"[A-Za-z]{4,}", line):
                continue
            interesting_lines.append(line)
            total_sample_len += len(line)
            if total_sample_len >= MAX_STRING_SAMPLE_CHARS:
                break

        readelf_excerpt = readelf_text[:4000]

        yara_matches = []
        for line in yara_text.splitlines():
            line = line.strip()
            if not line:
                continue
            m = re.match(r"^(\S+)\s*(\[.*?\])?\s+\S+$", line)
            if m:
                rule_name = m.group(1)
                meta_raw = m.group(2) or ""
                severity = "unknown"
                description = ""
                sev_m = re.search(r"severity=\"([^\"]*)\"", meta_raw)
                if sev_m:
                    severity = sev_m.group(1)
                desc_m = re.search(r"description=\"([^\"]*)\"", meta_raw)
                if desc_m:
                    description = desc_m.group(1)
                yara_matches.append({
                    "rule": rule_name,
                    "severity": severity,
                    "description": description,
                })
            else:
                yara_matches.append({"raw": line})

        # Binwalk (fork OSPG) generuje bardzo duzo falszywych trafien na
        # sygnaturach sprzetu embedded (ESP32, JBOOT, bix header itp.) -
        # to szum przy analizie zwyklych binarek Linuksowych/desktopowych.
        # Filtrujemy do wazkiej listy sygnatur faktycznie istotnych dla
        # analizy bezpieczenstwa (osadzone archiwa/pliki/kompresja).
        BINWALK_RELEVANT_PATTERNS = (
            "zip archive", "rar archive", "gzip compressed", "bzip2 compressed",
            "7-zip archive", "tar archive", "pe32 executable", "elf,",
            "lzma compressed", "xz compressed", "cab archive",
            "microsoft executable", "certificate", "private key",
            "sqlite", "pdf document",
        )
        binwalk_findings = []
        for line in binwalk_text.splitlines():
            line = line.strip()
            if not line or line.startswith("DECIMAL") or line.startswith("-"):
                continue
            parts = line.split(None, 2)
            if len(parts) != 3:
                continue
            description = parts[2]
            if parts[0] == "0":
                # Offset 0 to zawsze naglowek SAMEGO analizowanego pliku,
                # nie cos "osadzonego" w jego wnetrzu - pomijamy, zeby nie
                # raportowac np. "ELF" jako podejrzanego znaleziska tylko
                # dlatego, ze plik sam w sobie jest plikiem ELF.
                continue
            if not any(p in description.lower() for p in BINWALK_RELEVANT_PATTERNS):
                continue
            binwalk_findings.append({
                "offset_decimal": parts[0],
                "offset_hex": parts[1],
                "description": description,
            })
            if len(binwalk_findings) >= MAX_MATCHES_PER_CATEGORY:
                break

        digest = {
            "artifact_id": result.get("artifact_id"),
            "hash_lookup": result.get("hash_lookup"),
            "fuzzy_matches": result.get("fuzzy_matches", []),
            "thread_id": result.get("thread_id"),
            "target": result.get("target"),
            "sha256": result.get("sha256"),
            "size_bytes": result.get("size_bytes"),
            "file_type": result.get("file_type"),
            "summary": result.get("summary", {}),
            "evidence": {
                "urls_found": urls,
                "ip_addresses_found": ips,
                "suspicious_symbols_found": suspicious_symbols,
                "crypto_terms_found": crypto_terms,
                "interesting_strings_sample": interesting_lines[:200],
                "readelf_header_excerpt": readelf_excerpt,
                "yara_matches": yara_matches,
                "embedded_files_found": binwalk_findings,
            },
            "omitted": {
                "strings_total_count": result.get("summary", {}).get(
                    "strings_count", 0
                ),
                "objdump_included": False,
                "objdump_reason": (
                    "Pełny disassembly pominięty w danych dla LLM "
                    "(zbyt duży, brak wartości analitycznej dla modelu "
                    "językowego). Dostępny w pełnej formie pod ścieżką "
                    "wskazaną w polu full_raw_path."
                ),
            },
        }

        digest_json = json.dumps(digest, ensure_ascii=False, indent=2)

        if len(digest_json) > MAX_DIGEST_TOTAL_CHARS:
            digest["evidence"]["interesting_strings_sample"] = digest[
                "evidence"
            ]["interesting_strings_sample"][:50]
            digest_json = json.dumps(digest, ensure_ascii=False, indent=2)
            if len(digest_json) > MAX_DIGEST_TOTAL_CHARS:
                digest["evidence"]["interesting_strings_sample"] = digest[
                    "evidence"
                ]["interesting_strings_sample"][:10]
                digest["_truncation_warning"] = (
                    "DIGEST UCIĘTY - przekroczono limit bezpieczeństwa "
                    f"{MAX_DIGEST_TOTAL_CHARS} znaków."
                )

        return digest

    @staticmethod
    def _build_summary(result: dict[str, Any]) -> dict[str, Any]:
        strings_text = (
            result["operations"]
            .get("strings", {})
            .get("stdout", "")
        )
        readelf_text = (
            result["operations"]
            .get("readelf", {})
            .get("stdout", "")
        )
        nm_text = (
            result["operations"]
            .get("nm", {})
            .get("stdout", "")
        )
        indicators = {
            "has_urls": bool(
                re.search(r"https?://", strings_text, re.I)
            ),
            "has_ip_addresses": bool(
                re.search(
                    r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
                    strings_text,
                )
            ),
            "has_shell_commands": bool(
                re.search(
                    r"\b(?:/bin/sh|/bin/bash|system\(|popen\(|execve\()",
                    strings_text,
                    re.I,
                )
            ),
            "has_crypto_terms": bool(
                re.search(
                    r"\b(?:aes|rsa|sha256|sha1|md5|openssl|crypto)\b",
                    strings_text,
                    re.I,
                )
            ),
            "has_network_terms": bool(
                re.search(
                    r"\b(?:socket|connect|listen|http|https|mqtt|tcp|udp)\b",
                    strings_text,
                    re.I,
                )
            ),
            "has_debug_symbols": bool(
                re.search(
                    r"\b(?:debug|\.debug_|DWARF)\b",
                    readelf_text,
                    re.I,
                )
            ),
            "has_symbols": bool(nm_text.strip()),
        }

        yara_text = (
            result["operations"]
            .get("yara", {})
            .get("stdout", "")
        )
        indicators["yara_matches_count"] = len(
            [x for x in yara_text.splitlines() if x.strip()]
        )

        return {
            "is_elf": "ELF" in (
                result["operations"]["file"].get("stdout", "")
                + " "
                + str(result.get("file_type", ""))
            ),
            "indicators": indicators,
            "strings_count": len(
                [x for x in strings_text.splitlines() if x.strip()]
            ),
        }
