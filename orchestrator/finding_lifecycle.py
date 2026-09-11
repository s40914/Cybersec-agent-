from __future__ import annotations

from uuid import uuid4
from datetime import datetime, timezone

from evidence_store import EvidenceStore
from finding_builder import risk_score_for_severity
from security_models import (
    Finding,
    FindingStatus,
    RetestResult,
    RiskAssessment,
    Validation,
    ValidationStatus,
)


def utc_now():
    return datetime.now(timezone.utc)


class FindingLifecycle:
    """
    Deterministyczny lifecycle Finding:
      Finding -> Validation -> RetestResult

    Bez LLM.
    """

    def __init__(self, store: EvidenceStore | None = None):
        self.store = store or EvidenceStore()

    def validate(
        self,
        *,
        finding_id: str,
        validator: str,
        method: str,
        status: ValidationStatus,
        explanation: str,
        evidence_ids: list[str] | None = None,
    ) -> Validation:

        finding = self.store.get_finding(finding_id)

        if finding is None:
            raise ValueError(f"Finding nie istnieje: {finding_id}")

        validation = Validation(
            id=str(uuid4()),
            finding_id=finding.id,
            target=finding.target,
            status=status,
            validator=validator,
            method=method,
            explanation=explanation,
            evidence_ids=evidence_ids or [],
        )

        self.store.save_validation(validation)

        updated = finding.model_copy(
            update={
                "validation_status": status,
                "last_seen_at": utc_now(),
            }
        )

        self.store.save_finding(updated)

        return validation

    def reassess_risk(
        self,
        *,
        finding_id: str,
        rationale: str | None = None,
    ) -> RiskAssessment:

        finding = self.store.get_finding(finding_id)

        if finding is None:
            raise ValueError(f"Finding nie istnieje: {finding_id}")

        validations = self.store.get_validations(finding_id)
        latest_validation = validations[-1] if validations else None

        # Finding.validation_status jest aktualnym stanem lifecycle.
        # Retest może zmienić ten stan bez tworzenia nowego Validation.
        validation_status = finding.validation_status

        if rationale is None:
            if latest_validation:
                rationale = (
                    f"Ponowna ocena Finding po lifecycle. "
                    f"Validation status: {validation_status.value}. "
                    f"Validator: {latest_validation.validator}."
                )
            else:
                rationale = (
                    f"Ponowna ocena Finding bez Validation. "
                    f"Validation status: {validation_status.value}."
                )

        risk = RiskAssessment(
            id=str(uuid4()),
            finding_id=finding.id,
            target=finding.target,
            severity=finding.severity,
            score=risk_score_for_severity(finding.severity),
            confidence=finding.confidence,
            rationale=rationale,
        )

        self.store.save_risk_assessment(risk)

        return risk

    def retest(
        self,
        *,
        finding_id: str,
        status: str,
        explanation: str,
        tool_name: str | None = None,
        raw_result_id: str | None = None,
        evidence_ids: list[str] | None = None,
        new_validation_status: ValidationStatus | None = None,
    ) -> RetestResult:

        finding = self.store.get_finding(finding_id)

        if finding is None:
            raise ValueError(f"Finding nie istnieje: {finding_id}")

        previous = finding.validation_status

        if new_validation_status is None:
            new_validation_status = previous

        result = RetestResult(
            id=str(uuid4()),
            finding_id=finding.id,
            target=finding.target,
            status=status,
            tool_name=tool_name,
            raw_result_id=raw_result_id,
            previous_validation_status=previous,
            new_validation_status=new_validation_status,
            explanation=explanation,
            evidence_ids=evidence_ids or [],
        )

        self.store.save_retest_result(result)

        updated = finding.model_copy(
            update={
                "validation_status": new_validation_status,
                "last_seen_at": utc_now(),
            }
        )

        self.store.save_finding(updated)

        return result

    def retest_with_tool(
        self,
        *,
        finding_id: str,
        tool_name: str,
        params: dict,
        thread_id: str = "retest",
    ) -> RetestResult:

        finding = self.store.get_finding(finding_id)

        if finding is None:
            raise ValueError(f"Finding nie istnieje: {finding_id}")

        from pentest_tools import make_pentest_tools

        before_ids = {
            x.get("id")
            for x in self.store._load("raw_result")
        }

        tools = make_pentest_tools(thread_id=thread_id)

        tool = next(
            (t for t in tools if getattr(t, "name", "") == tool_name),
            None,
        )

        if tool is None:
            raise ValueError(f"Nie znaleziono narzędzia: {tool_name}")

        tool_result = tool.invoke(params)

        new_raw = None

        for data in reversed(self.store._load("raw_result")):
            if data.get("id") not in before_ids:
                if (
                    data.get("tool_name") == tool_name
                    and data.get("target") == finding.target
                ):
                    new_raw = data
                    break

        if new_raw is None:
            raise RuntimeError(
                "Narzędzie wykonane, ale nie znaleziono nowego RawResult"
            )

        raw_result_id = new_raw["id"]

        evidence_ids = [
            data["id"]
            for data in self.store._load("evidence")
            if data.get("raw_result_id") == raw_result_id
        ]

        stdout = str(new_raw.get("stdout", ""))
        status = str(new_raw.get("status", "unknown"))
        returncode = new_raw.get("returncode")

        confirmed = (
            status == "ok"
            and returncode == 0
            and (
                "DVWA" in stdout
                or "Damn Vulnerable Web Application" in stdout
            )
        )

        new_status = (
            ValidationStatus.CONFIRMED
            if confirmed
            else ValidationStatus.NOT_VALIDATED
        )

        explanation = (
            f"Retest narzędziem {tool_name}: Finding potwierdzony."
            if confirmed
            else
            f"Retest narzędziem {tool_name}: brak jednoznacznego "
            "potwierdzenia Finding."
        )

        result = RetestResult(
            id=str(uuid4()),
            finding_id=finding.id,
            target=finding.target,
            status="confirmed" if confirmed else "not_confirmed",
            tool_name=tool_name,
            raw_result_id=raw_result_id,
            previous_validation_status=finding.validation_status,
            new_validation_status=new_status,
            explanation=explanation,
            evidence_ids=evidence_ids,
        )

        self.store.save_retest_result(result)

        updated = finding.model_copy(
            update={
                "validation_status": new_status,
                "last_seen_at": utc_now(),
            }
        )

        self.store.save_finding(updated)

        return result
