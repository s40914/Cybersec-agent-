from __future__ import annotations

import hashlib
import mimetypes
import subprocess
from pathlib import Path
from uuid import uuid4

from evidence_store import EvidenceStore
from security_models import Artifact, Evidence, EvidenceType


class ArtifactPipeline:
    """
    Deterministyczny pipeline ingestujący artefakt.

    Nie używa LLM.
    Nie wykonuje artefaktu.
    Nie modyfikuje pliku.
    """

    def __init__(
        self,
        store: EvidenceStore | None = None,
        max_size_bytes: int = 500 * 1024 * 1024,
    ):
        self.store = store or EvidenceStore()
        self.max_size_bytes = max_size_bytes

    def ingest(
        self,
        path: str,
        thread_id: str,
        target: str,
    ) -> Artifact:
        artifact_path = Path(path).resolve()

        if not artifact_path.is_file():
            raise FileNotFoundError(
                f"Artefakt nie istnieje lub nie jest plikiem: {artifact_path}"
            )

        size_bytes = artifact_path.stat().st_size

        if size_bytes > self.max_size_bytes:
            raise ValueError(
                f"Artefakt jest zbyt duży: {size_bytes} bytes "
                f"(limit {self.max_size_bytes} bytes)"
            )

        sha256 = hashlib.sha256()

        with artifact_path.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                sha256.update(chunk)

        sha256_hex = sha256.hexdigest()

        file_type = self._file_type(artifact_path)
        mime_type, _ = mimetypes.guess_type(artifact_path.name)

        artifact = Artifact(
            id=str(uuid4()),
            thread_id=thread_id,
            target=target,
            path=str(artifact_path),
            filename=artifact_path.name,
            sha256=sha256_hex,
            size_bytes=size_bytes,
            mime_type=mime_type,
            file_type=file_type,
            artifact_type="unknown",
            metadata={},
        )

        self.store.save_artifact(artifact)

        evidence = Evidence(
            id=str(uuid4()),
            target=target,
            evidence_type=EvidenceType.ARTIFACT_ANALYSIS,
            raw_result_id=None,
            observation_id=None,
            finding_id=None,
            title=f"Artefakt: {artifact.filename}",
            content=(
                f"SHA256: {artifact.sha256}\n"
                f"Rozmiar: {artifact.size_bytes} bytes\n"
                f"Typ: {artifact.file_type or 'unknown'}\n"
                f"MIME: {artifact.mime_type or 'unknown'}"
            ),
            metadata={
                "artifact_id": artifact.id,
                "thread_id": thread_id,
            },
        )

        self.store.save_evidence(evidence)

        return artifact

    @staticmethod
    def _file_type(path: Path) -> str:
        try:
            result = subprocess.run(
                ["file", "-b", str(path)],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return "unknown"

        value = result.stdout.strip()

        return value or "unknown"
