from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from uuid import uuid4

from evidence_store import EvidenceStore
from security_models import Evidence, Finding, RiskAssessment


RISK_SCORES = {
    "critical": 9.5,
    "high": 8.0,
    "medium": 5.5,
    "low": 3.0,
    "info": 1.0,
}


def risk_score_for_severity(severity: str) -> float:
    return RISK_SCORES.get(severity.lower(), 0.0)


class FindingBuilder:
    """
    Deterministyczne tworzenie Finding + RiskAssessment
    na podstawie jawnie zidentyfikowanego sygnału.

    Nie używa LLM.
    """

    def __init__(self, store: EvidenceStore | None = None):
        self.store = store or EvidenceStore()

    @staticmethod
    def fingerprint(target: str, category: str, title: str) -> str:
        value = f"{target}|{category}|{title}".encode("utf-8")
        return hashlib.sha256(value).hexdigest()

    def create_finding(
        self,
        *,
        target: str,
        category: str,
        title: str,
        description: str,
        severity: str,
        confidence: float,
        evidence: Evidence,
    ) -> tuple[Finding, RiskAssessment]:

        fingerprint = self.fingerprint(target, category, title)

        existing = self.store.find_finding_by_fingerprint(
            fingerprint,
            target,
        )

        if existing:
            finding = existing

            if evidence.id not in finding.evidence_ids:
                finding.evidence_ids.append(evidence.id)

            if (
                evidence.observation_id
                and evidence.observation_id not in finding.observation_ids
            ):
                finding.observation_ids.append(evidence.observation_id)

            finding.last_seen_at = datetime.now(timezone.utc)

            self.store.save_finding(finding)

            risks = self.store.get_risk_assessments(finding.id)

            if risks:
                return finding, risks[-1]

            # Stary Finding bez RiskAssessment — utwórz brakującą ocenę.

        else:
            finding = Finding(
                id=str(uuid4()),
                target=target,
                fingerprint=fingerprint,
                title=title,
                description=description,
                category=category,
                severity=severity,
                confidence=confidence,
                observation_ids=(
                    [evidence.observation_id]
                    if evidence.observation_id
                    else []
                ),
                evidence_ids=[evidence.id],
            )

            self.store.save_finding(finding)

        risk_score = risk_score_for_severity(finding.severity)

        risk = RiskAssessment(
            id=str(uuid4()),
            finding_id=finding.id,
            target=finding.target,
            severity=finding.severity,
            score=risk_score,
            confidence=finding.confidence,
            rationale=(
                f"Ocena oparta na jawnym sygnale: {finding.title}. "
                f"Źródło dowodu: {evidence.source_tool or 'unknown'}."
            ),
        )

        self.store.save_risk_assessment(risk)

        return finding, risk
