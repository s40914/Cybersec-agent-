from __future__ import annotations

from uuid import uuid4

from evidence_store import EvidenceStore
from security_models import Evidence, EvidenceType, Observation, RawResult


class EvidencePipeline:
    """
    Deterministyczna warstwa RawResult -> Observation + Evidence.

    Nie interpretuje podatności i nie używa LLM.
    """

    def __init__(self, store: EvidenceStore | None = None):
        self.store = store or EvidenceStore()

    def process_raw_result(self, raw: RawResult) -> tuple[Observation, Evidence]:
        observation = Observation(
            id=str(uuid4()),
            raw_result_id=raw.id,
            target=raw.target,
            source_tool=raw.tool_name,
            kind="tool_result",
            value={
                "status": raw.status,
                "returncode": raw.returncode,
            },
            description=f"Wynik wykonania narzędzia {raw.tool_name}.",
            confidence=1.0 if raw.status == "ok" else 0.5,
            metadata={
                "thread_id": raw.thread_id,
            },
        )

        evidence = Evidence(
            id=str(uuid4()),
            target=raw.target,
            evidence_type=EvidenceType.TOOL_OUTPUT,
            source_tool=raw.tool_name,
            raw_result_id=raw.id,
            observation_id=observation.id,
            title=f"Wynik narzędzia: {raw.tool_name}",
            content=raw.stdout or raw.stderr or raw.status,
            metadata={
                "returncode": raw.returncode,
                "status": raw.status,
            },
        )

        self.store.save_observation(observation)
        self.store.save_evidence(evidence)

        return observation, evidence
