from __future__ import annotations

import json
import subprocess
from pathlib import Path
from uuid import uuid4
from typing import Any

from evidence_store import EvidenceStore
from security_models import Artifact, RawResult


# ------------------------------------------------------------------
# Rozszerzenia plikow traktowane jako potencjalny kod zrodlowy.
# Uzywane jako dodatkowy sygnal obok wyniku `file -b` (ktory dla
# plikow tekstowych zazwyczaj zawiera slowo "text").
# ------------------------------------------------------------------
SOURCE_CODE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".php", ".java", ".go",
    ".rb", ".c", ".cpp", ".cs", ".rs", ".sql",
}

MAX_FINDINGS_IN_DIGEST = 30


def is_source_code(file_type: str, filename: str) -> bool:
    """
    Deterministyczne rozpoznanie, czy artefakt wyglada na kod zrodlowy
    (a nie binarke) - decyduje, czy artefakt trafia do SASTPipeline
    zamiast do REPipeline.

    Uzywa dwoch niezaleznych sygnalow (typ z `file -b` + rozszerzenie
    pliku) - wystarczy jeden pozytywny, semgrep i tak sam odrzuci
    pliki ktorych nie rozumie, wiec nie musimy tu byc idealnie precyzyjni.
    """
    file_type_lower = (file_type or "").lower()
    if "text" in file_type_lower and "elf" not in file_type_lower:
        return True

    ext = Path(filename).suffix.lower()
    return ext in SOURCE_CODE_EXTENSIONS


class SASTPipeline:
    """
    Deterministyczny etap SAST (Static Application Security Testing)
    dla artefaktow bedacych kodem zrodlowym.

    SAST nie jest narzedziem dostepnym dla LLM. Uzywa Semgrep -
    branzowego standardu statycznej analizy kodu (AST-aware, nie
    zwykly regex na tekscie) z oficjalnymi, utrzymywanymi rulesetami
    (p/sql-injection, p/security-audit, p/owasp-top-ten) jako
    fundamentem, uzupelnionymi o wlasne, dodatkowe reguly
    (data/semgrep_rules/).

    Rulesety sa pobierane i cache'owane RAZ podczas budowy obrazu
    Dockera (patrz Dockerfile) - w runtime skanowanie dziala w pelni
    offline, bez polaczen sieciowych, spojnie z reszta RE.
    """

    OFFICIAL_RULESETS = [
        "p/sql-injection",
        "p/security-audit",
        "p/owasp-top-ten",
    ]
    CUSTOM_RULES_DIR = "data/semgrep_rules"

    def __init__(self, store: EvidenceStore | None = None):
        self.store = store or EvidenceStore()

    def _run_semgrep(self, path: Path) -> dict[str, Any]:
        configs = []
        for ruleset in self.OFFICIAL_RULESETS:
            configs.extend(["--config", ruleset])
        if Path(self.CUSTOM_RULES_DIR).is_dir():
            configs.extend(["--config", self.CUSTOM_RULES_DIR])

        cmd = [
            "semgrep",
            *configs,
            "--json",
            "--quiet",
            "--disable-version-check",
            "--metrics=off",
            "--timeout", "60",
            str(path),
        ]

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
        except FileNotFoundError:
            return {
                "returncode": None,
                "stdout": "",
                "stderr": "Tool not found: semgrep",
                "status": "not_available",
            }
        except subprocess.TimeoutExpired:
            return {
                "returncode": None,
                "stdout": "",
                "stderr": "Timeout: semgrep scan przekroczyl limit czasu",
                "status": "timeout",
            }

        # Semgrep zwraca returncode != 0 gdy znalazl trafienia - to NIE
        # jest blad wykonania, tylko sygnal ze sa findings. Prawdziwy
        # blad rozpoznajemy po braku poprawnego JSON-a w stdout.
        status = "ok"
        if not proc.stdout.strip():
            status = "error"

        return {
            "returncode": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "status": status,
        }

    def inspect(self, artifact: Artifact) -> dict[str, Any]:
        path = Path(artifact.path)

        if not path.is_file():
            raise FileNotFoundError(f"Artifact nie jest plikiem: {path}")

        semgrep_raw = self._run_semgrep(path)

        findings: list[dict[str, Any]] = []
        parse_error = None

        if semgrep_raw["status"] == "ok":
            try:
                parsed = json.loads(semgrep_raw["stdout"])
                for result in parsed.get("results", []):
                    findings.append({
                        "rule_id": result.get("check_id", "nieznana_regula"),
                        "message": result.get("extra", {}).get(
                            "message", ""
                        ),
                        "severity": result.get("extra", {}).get(
                            "severity", "unknown"
                        ),
                        "line_start": result.get("start", {}).get("line"),
                        "line_end": result.get("end", {}).get("line"),
                        "cwe": result.get("extra", {})
                            .get("metadata", {})
                            .get("cwe", ""),
                    })
            except (json.JSONDecodeError, ValueError) as e:
                parse_error = str(e)

        result: dict[str, Any] = {
            "artifact_id": artifact.id,
            "thread_id": artifact.thread_id,
            "target": artifact.target,
            "path": str(path),
            "sha256": artifact.sha256,
            "size_bytes": artifact.size_bytes,
            "file_type": artifact.file_type,
            "semgrep_status": semgrep_raw["status"],
            "parse_error": parse_error,
            "findings": findings,
            "findings_count": len(findings),
        }

        # Trwaly surowy wynik SAST zapisywany do EvidenceStore. Digest
        # jest ograniczony (max MAX_FINDINGS_IN_DIGEST wpisow) - pelny
        # wynik semgrep --json trafia osobno na dysk, tak samo jak
        # w REPipeline dla objdump/strings.
        full_raw_path = self._persist_full_raw(
            {**result, "semgrep_raw_stdout": semgrep_raw["stdout"]},
            artifact.id,
        )

        digest = {
            "artifact_id": result["artifact_id"],
            "thread_id": result["thread_id"],
            "target": result["target"],
            "sha256": result["sha256"],
            "size_bytes": result["size_bytes"],
            "file_type": result["file_type"],
            "semgrep_status": result["semgrep_status"],
            "findings_count": result["findings_count"],
            "findings": findings[:MAX_FINDINGS_IN_DIGEST],
            "findings_truncated": len(findings) > MAX_FINDINGS_IN_DIGEST,
            "full_raw_path": full_raw_path,
        }

        digest_json = json.dumps(
            digest, ensure_ascii=False, separators=(",", ":")
        )

        raw_result = RawResult(
            id=str(uuid4()),
            thread_id=artifact.thread_id or "",
            tool_name="sast_pipeline",
            target=artifact.target,
            params={
                "artifact_id": artifact.id,
                "path": str(path),
                "sha256": artifact.sha256,
            },
            status="ok" if semgrep_raw["status"] == "ok" else "error",
            returncode=semgrep_raw["returncode"] or 0,
            stdout=digest_json,
            stderr=semgrep_raw["stderr"][:2000],
            metadata={
                "artifact_id": artifact.id,
                "artifact_sha256": artifact.sha256,
                "artifact_type": artifact.artifact_type,
                "full_raw_path": full_raw_path,
                "findings_count": len(findings),
            },
        )
        self.store.save_raw_result(raw_result)

        return result

    @staticmethod
    def _persist_full_raw(result: dict[str, Any], artifact_id: str) -> str:
        """
        Zapisuje PELNY wynik semgrep (wlacznie z surowym JSON stdout)
        jako osobny plik na dysku - nic nie ginie, tylko nie trafia
        bezposrednio do promptu LLM.
        """
        out_dir = Path("data/sast_artifacts")
        out_dir.mkdir(parents=True, exist_ok=True)

        out_path = out_dir / f"{artifact_id}_sast_raw.json"
        with out_path.open("w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, separators=(",", ":"))

        return str(out_path)
