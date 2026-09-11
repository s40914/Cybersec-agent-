from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import TypeVar

from security_models import (
    Artifact,
    Asset,
    Evidence,
    Finding,
    Observation,
    RawResult,
    RiskAssessment,
    RetestResult,
    Validation,
)


T = TypeVar("T")


class EvidenceStore:
    """
    Trwały, append-only magazyn wiedzy bezpieczeństwa.

    Na tym etapie używamy JSONL zamiast bazy SQL.
    Każdy zapis jest osobnym rekordem JSON.

    Store NIE interpretuje danych i NIE używa LLM.
    Jest wyłącznie warstwą trwałości dla kontraktów z security_models.py.
    """

    def __init__(self, path: str | Path = "data/evidence.jsonl"):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def _append(self, record_type: str, obj) -> None:
        record = {
            "type": record_type,
            "data": obj.model_dump(mode="json"),
        }

        line = json.dumps(
            record,
            ensure_ascii=False,
            separators=(",", ":"),
        )

        with self._lock:
            with self.path.open("a", encoding="utf-8") as f:
                f.write(line + "\n")

    def _load(self, record_type: str) -> list[dict]:
        if not self.path.exists():
            return []

        records = []

        with self._lock:
            with self.path.open("r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()

                    if not line:
                        continue

                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    if record.get("type") == record_type:
                        records.append(record["data"])

        return records

    # ------------------------------------------------------------------
    # Artifact
    # ------------------------------------------------------------------

    def save_artifact(self, artifact: Artifact) -> None:
        self._append("artifact", artifact)

    def get_artifact(self, artifact_id: str) -> Artifact | None:
        for data in reversed(self._load("artifact")):
            if data.get("id") == artifact_id:
                return Artifact.model_validate(data)

        return None

    def get_artifacts(
        self,
        thread_id: str | None = None,
        target: str | None = None,
    ) -> list[Artifact]:
        latest: dict[str, dict] = {}

        for data in self._load("artifact"):
            artifact_id = data.get("id")

            if not artifact_id:
                continue

            if thread_id is not None and data.get("thread_id") != thread_id:
                continue

            if target is not None and data.get("target") != target:
                continue

            latest[artifact_id] = data

        return [
            Artifact.model_validate(data)
            for data in latest.values()
        ]

    # ------------------------------------------------------------------
    # RawResult
    # ------------------------------------------------------------------

    def save_raw_result(self, result: RawResult) -> None:
        self._append("raw_result", result)

    def get_raw_result(self, result_id: str) -> RawResult | None:
        for data in self._load("raw_result"):
            if data.get("id") == result_id:
                return RawResult.model_validate(data)

        return None

    def get_raw_results(
        self,
        thread_id: str | None = None,
        target: str | None = None,
    ) -> list[RawResult]:
        results = []

        for data in self._load("raw_result"):
            if thread_id is not None and data.get("thread_id") != thread_id:
                continue

            if target is not None and data.get("target") != target:
                continue

            results.append(RawResult.model_validate(data))

        return results

    # ------------------------------------------------------------------
    # Asset
    def save_asset(self, asset: Asset) -> None:
        self._append("asset", asset)

    def get_asset(self, asset_id: str) -> Asset | None:
        for data in reversed(self._load("asset")):
            if data.get("id") == asset_id:
                return Asset.model_validate(data)
        return None

    def find_asset_by_ip(
        self,
        ip_address: str,
        target: str | None = None,
    ) -> Asset | None:
        for data in reversed(self._load("asset")):
            if data.get("ip_address") != ip_address:
                continue
            if target is not None and data.get("target") != target:
                continue
            return Asset.model_validate(data)
        return None

    def get_assets(
        self,
        target: str | None = None,
    ) -> list[Asset]:
        latest: dict[str, dict] = {}

        for data in self._load("asset"):
            asset_id = data.get("id")
            if not asset_id:
                continue

            if target is not None and data.get("target") != target:
                continue

            latest[asset_id] = data

        return [
            Asset.model_validate(data)
            for data in latest.values()
        ]

    def upsert_asset(self, asset: Asset) -> Asset:
        """
        Tworzy nowy Asset albo aktualizuje istniejący Asset
        o tym samym IP w ramach tego samego targetu.
        """

        existing = None

        if asset.ip_address:
            existing = self.find_asset_by_ip(
                asset.ip_address,
                target=asset.target,
            )

        if existing is None:
            self.save_asset(asset)
            return asset

        updated = existing.model_copy(
            update={
                "hostname": asset.hostname or existing.hostname,
                "mac_address": asset.mac_address or existing.mac_address,
                "asset_type": asset.asset_type or existing.asset_type,
                "last_seen_at": asset.last_seen_at,
                "metadata": {
                    **existing.metadata,
                    **asset.metadata,
                },
            }
        )

        self.save_asset(updated)
        return updated

    # Observation
    # ------------------------------------------------------------------

    def save_observation(self, observation: Observation) -> None:
        self._append("observation", observation)

    def get_observation(self, observation_id: str) -> Observation | None:
        for data in self._load("observation"):
            if data.get("id") == observation_id:
                return Observation.model_validate(data)

        return None

    # ------------------------------------------------------------------
    # Finding
    # ------------------------------------------------------------------

    def save_finding(self, finding: Finding) -> None:
        self._append("finding", finding)

    def get_finding(self, finding_id: str) -> Finding | None:
        for data in reversed(self._load("finding")):
            if data.get("id") == finding_id:
                return Finding.model_validate(data)

        return None

    def find_finding_by_fingerprint(
        self,
        fingerprint: str,
        target: str,
    ) -> Finding | None:
        for data in reversed(self._load("finding")):
            if (
                data.get("fingerprint") == fingerprint
                and data.get("target") == target
            ):
                return Finding.model_validate(data)

        return None

    def get_findings(self, target: str | None = None) -> list[Finding]:
        """Zwraca najnowszą wersję każdego Finding."""
        latest: dict[str, dict] = {}

        for data in self._load("finding"):
            finding_id = data.get("id")
            if not finding_id:
                continue
            if target is not None and data.get("target") != target:
                continue
            latest[finding_id] = data

        return [
            Finding.model_validate(data)
            for data in latest.values()
        ]

    # ------------------------------------------------------------------
    # Evidence
    # ------------------------------------------------------------------

    def save_evidence(self, evidence: Evidence) -> None:
        self._append("evidence", evidence)

    def get_evidence(self, evidence_id: str) -> Evidence | None:
        for data in self._load("evidence"):
            if data.get("id") == evidence_id:
                return Evidence.model_validate(data)

        return None

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def save_validation(self, validation: Validation) -> None:
        self._append("validation", validation)

    def get_validations(self, finding_id: str) -> list[Validation]:
        return [
            Validation.model_validate(data)
            for data in self._load("validation")
            if data.get("finding_id") == finding_id
        ]

    # ------------------------------------------------------------------
    # RiskAssessment
    # ------------------------------------------------------------------

    def save_risk_assessment(
        self,
        assessment: RiskAssessment,
    ) -> None:
        self._append("risk_assessment", assessment)

    def get_risk_assessments(
        self,
        finding_id: str,
    ) -> list[RiskAssessment]:
        return [
            RiskAssessment.model_validate(data)
            for data in self._load("risk_assessment")
            if data.get("finding_id") == finding_id
        ]

    # ------------------------------------------------------------------
    # RetestResult
    # ------------------------------------------------------------------

    def save_retest_result(
        self,
        result: RetestResult,
    ) -> None:
        self._append("retest_result", result)

    def get_retest_results(
        self,
        finding_id: str,
    ) -> list[RetestResult]:
        return [
            RetestResult.model_validate(data)
            for data in self._load("retest_result")
            if data.get("finding_id") == finding_id
        ]
