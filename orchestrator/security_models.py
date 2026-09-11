from __future__ import annotations
from uuid import uuid4

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class EvidenceType(str, Enum):
    TOOL_OUTPUT = "tool_output"
    HTTP_RESPONSE = "http_response"
    SCREENSHOT = "screenshot"
    ARTIFACT_ANALYSIS = "artifact_analysis"
    MANUAL = "manual"
    RETEST = "retest"


class ValidationStatus(str, Enum):
    NOT_VALIDATED = "not_validated"
    PENDING = "pending"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"


class FindingStatus(str, Enum):
    OPEN = "open"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    FIXED = "fixed"


class RawResult(BaseModel):
    """
    Nieprzetworzony wynik pojedynczego wykonania narzędzia.

    To jest granica pomiędzy tool execution a warstwą wiedzy
    o bezpieczeństwie.
    """

    id: str
    thread_id: str

    tool_name: str
    target: str

    params: dict[str, Any] = Field(default_factory=dict)

    status: str
    returncode: int | None = None

    stdout: str = ""
    stderr: str = ""

    started_at: datetime | None = None
    finished_at: datetime | None = None

    metadata: dict[str, Any] = Field(default_factory=dict)

    created_at: datetime = Field(default_factory=utc_now)


class Artifact(BaseModel):
    """
    Artefakt przeznaczony do dalszej analizy.

    Artifact nie jest Findingiem. Reprezentuje konkretny plik/binarne
    dane wraz z jego tożsamością kryptograficzną i podstawowymi
    informacjami o pochodzeniu.
    """

    id: str = Field(default_factory=lambda: str(uuid4()))

    thread_id: str | None = None
    target: str

    path: str
    filename: str

    sha256: str
    size_bytes: int

    mime_type: str | None = None
    file_type: str | None = None

    artifact_type: str = "unknown"

    created_at: datetime = Field(default_factory=utc_now)

    metadata: dict[str, Any] = Field(default_factory=dict)


class Asset(BaseModel):
    """
    Zidentyfikowany zasób wykryty podczas discovery.

    Asset nie jest Findingiem ani Observation.
    Reprezentuje host, urządzenie lub inny zasób w zakresie audytu.
    """

    id: str = Field(default_factory=lambda: str(uuid4()))

    target: str
    ip_address: str | None = None
    hostname: str | None = None
    mac_address: str | None = None

    asset_type: str = "host"

    first_seen_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    last_seen_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    metadata: dict = Field(default_factory=dict)


class Observation(BaseModel):
    """
    Fakt zaobserwowany w RawResult.

    Observation nie jest jeszcze podatnością.
    """

    id: str
    raw_result_id: str

    target: str
    source_tool: str

    kind: str
    value: Any

    location: str | None = None
    description: str | None = None

    confidence: float = Field(default=1.0, ge=0.0, le=1.0)

    observed_at: datetime = Field(default_factory=utc_now)

    metadata: dict[str, Any] = Field(default_factory=dict)


class Evidence(BaseModel):
    """
    Dowód wspierający lub obalający Finding/Observation.

    Evidence jest niezależne od sposobu prezentacji raportu.
    """

    id: str

    target: str

    evidence_type: EvidenceType

    source_tool: str | None = None
    raw_result_id: str | None = None
    observation_id: str | None = None
    finding_id: str | None = None

    title: str
    content: str

    collected_at: datetime = Field(default_factory=utc_now)

    metadata: dict[str, Any] = Field(default_factory=dict)


class Finding(BaseModel):
    """
    Stabilna reprezentacja potencjalnego problemu bezpieczeństwa.

    Finding nie powinien być utożsamiany z pojedynczym wynikiem narzędzia.
    Jeden finding może mieć wiele observations i evidence.
    """

    id: str

    target: str

    fingerprint: str

    title: str
    description: str

    category: str | None = None

    severity: str = "unknown"

    status: FindingStatus = FindingStatus.OPEN
    validation_status: ValidationStatus = ValidationStatus.NOT_VALIDATED

    confidence: float = Field(default=0.0, ge=0.0, le=1.0)

    first_seen_at: datetime = Field(default_factory=utc_now)
    last_seen_at: datetime = Field(default_factory=utc_now)

    observation_ids: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)

    metadata: dict[str, Any] = Field(default_factory=dict)


class Validation(BaseModel):
    """
    Wynik niezależnej walidacji Finding.

    Walidacja może pochodzić z ręcznej weryfikacji albo osobnego
    narzędzia walidującego.
    """

    id: str

    finding_id: str
    target: str

    status: ValidationStatus

    validator: str
    method: str

    explanation: str

    evidence_ids: list[str] = Field(default_factory=list)

    validated_at: datetime = Field(default_factory=utc_now)

    metadata: dict[str, Any] = Field(default_factory=dict)


class RiskAssessment(BaseModel):
    """
    Ocena ryzyka wykonana na podstawie Finding + Evidence + Validation.

    Nie zawiera surowego stdout.
    """

    id: str

    finding_id: str
    target: str

    severity: str
    score: float = Field(ge=0.0, le=10.0)

    confidence: float = Field(default=0.0, ge=0.0, le=1.0)

    rationale: str

    assessed_at: datetime = Field(default_factory=utc_now)

    metadata: dict[str, Any] = Field(default_factory=dict)


class RetestResult(BaseModel):
    """
    Wynik ponownego sprawdzenia istniejącego Finding.

    Retest nie tworzy automatycznie nowego Finding.
    """

    id: str

    finding_id: str
    target: str

    status: str

    tool_name: str | None = None
    raw_result_id: str | None = None

    previous_validation_status: ValidationStatus
    new_validation_status: ValidationStatus

    explanation: str

    evidence_ids: list[str] = Field(default_factory=list)

    tested_at: datetime = Field(default_factory=utc_now)

    metadata: dict[str, Any] = Field(default_factory=dict)
