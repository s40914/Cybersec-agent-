import asyncio
import logging
import os
import re
import uuid

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from graph import build_app, get_model_config
from tools import make_tools
from pentest_tools import make_pentest_tools
import status_store
from evidence_store import EvidenceStore
from artifact_pipeline import ArtifactPipeline
from re_pipeline import REPipeline
from sast_pipeline import SASTPipeline, is_source_code
from internal_sensor import InternalSensor
from target_scope import target_scope
import update_malware_db

PENTEST_AGENT_URL = os.getenv("PENTEST_AGENT_URL", "http://pentest-agent:8766")
PENTEST_AGENT_TOKEN = os.getenv("PENTEST_AGENT_TOKEN", "")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("orchestrator")

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

graph_app = build_app()
evidence_store = EvidenceStore()
artifact_pipeline = ArtifactPipeline(evidence_store)
re_pipeline = REPipeline(evidence_store)
sast_pipeline = SASTPipeline(evidence_store)


class ChatRequest(BaseModel):
    message: str
    thread_id: str | None = None
    selected_tools: list[str] | None = None
    # Parametry jawnie wybranych narzędzi.
    # Klucz = nazwa narzędzia, wartość = słownik parametrów.
    # Dzięki temu wybrane narzędzie może być wykonane deterministycznie,
    # bez proszenia LLM o ponowne podjęcie decyzji.
    tool_params: dict[str, dict] | None = None
    # Haslo administratora dostarczone PRZEZ CZLOWIEKA w UI dla TEJ
    # KONKRETNEJ wiadomosci - wymagane do wykonania narzedzi restricted
    # (np. nmap_stealth_scan). Nigdy nie trafia do promptu LLM, nie jest
    # zapisywane ani logowane w orchestratorze - plynie bezposrednio do
    # pentest-agenta i tam jest weryfikowane wzgledem PENTEST_ADMIN_PASSWORD_HASH.
    admin_password: str | None = None


class ChatResponse(BaseModel):
    response: str
    thread_id: str




class ArtifactIngestRequest(BaseModel):
    path: str
    thread_id: str
    target: str


@app.post("/artifacts/ingest")
async def ingest_artifact(req: ArtifactIngestRequest):
    """
    Pipeline (automatyczny routing wg typu artefaktu):
        artefakt -> ingest/hash/type -> klasyfikacja binarka/kod
            -> RE (binutils+YARA+binwalk+hash-lookup) DLA BINAREK
            -> SAST (Semgrep) DLA KODU ZRÓDŁOWEGO
        -> wynik pipeline

    Ani RE, ani SAST nie są narzędziami dla LLM. To deterministyczne
    etapy pipeline'u, wybierane automatycznie na podstawie typu pliku.
    """
    try:
        artifact = artifact_pipeline.ingest(
            path=req.path,
            thread_id=req.thread_id,
            target=req.target,
        )

        if is_source_code(artifact.file_type, artifact.filename):
            sast_result = sast_pipeline.inspect(artifact)
            return {
                "status": "ok",
                "artifact": artifact.model_dump(mode="json"),
                "pipeline_used": "sast",
                "sast": sast_result,
            }

        re_result = re_pipeline.inspect(artifact)

        return {
            "status": "ok",
            "artifact": artifact.model_dump(mode="json"),
            "pipeline_used": "re",
            "re": re_result,
        }

    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    except Exception as e:
        logger.exception("Artifact/RE pipeline failed")
        raise HTTPException(
            status_code=500,
            detail=f"Artifact/RE pipeline failed: {e}",
        )


@app.get("/artifacts")
async def list_artifacts(thread_id: str | None = None):
    artifacts = evidence_store.get_artifacts(thread_id=thread_id)

    return {
        "artifacts": [
            artifact.model_dump(mode="json")
            for artifact in artifacts
        ]
    }


@app.get("/findings")
async def list_findings(target: str | None = None):
    """Lista aktualnych Findingów."""
    findings = evidence_store.get_findings(target=target)
    return {
        "findings": [
            finding.model_dump(mode="json")
            for finding in findings
        ]
    }


@app.get("/findings/{finding_id}")
async def get_finding(finding_id: str):
    """Szczegóły Finding + lifecycle."""
    finding = evidence_store.get_finding(finding_id)

    if finding is None:
        raise HTTPException(
            status_code=404,
            detail=f"Finding nie istnieje: {finding_id}",
        )

    return {
        "finding": finding.model_dump(mode="json"),
        "validations": [
            x.model_dump(mode="json")
            for x in evidence_store.get_validations(finding.id)
        ],
        "retests": [
            x.model_dump(mode="json")
            for x in evidence_store.get_retest_results(finding.id)
        ],
        "risks": [
            x.model_dump(mode="json")
            for x in evidence_store.get_risk_assessments(finding.id)
        ],
    }

@app.get("/assets")
async def list_assets(target: str | None = None):
    """Lista wykrytych Assetów."""
    assets = evidence_store.get_assets(target=target)

    return {
        "assets": [
            asset.model_dump(mode="json")
            for asset in assets
        ]
    }


@app.post("/assets/discover")
async def discover_assets(
    network: str = "192.168.0.0/24",
):
    """Uruchamia Internal Sensor v1 i zapisuje Asset inventory."""

    sensor = InternalSensor(
        evidence_store=evidence_store,
        network=network,
    )

    assets = sensor.discover()

    return {
        "network": network,
        "count": len(assets),
        "assets": [
            asset.model_dump(mode="json")
            for asset in assets
        ],
    }



@app.post("/malware_db/update")
async def update_malware_database():
    """Aktualizuje lokalna baze znanych hashy malware z MalwareBazaar (abuse.ch)."""
    try:
        raw = await asyncio.to_thread(update_malware_db.fetch_recent_csv)
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"Blad pobierania z MalwareBazaar: {exc}")
    entries = update_malware_db.parse_malwarebazaar_csv(raw)
    stats = update_malware_db.update_known_hashes(entries)
    return {
        "parsed_entries": len(entries),
        "total_entries": stats["total_entries"],
        "new_entries_added": stats["new_entries_added"],
    }

@app.get("/health")
async def health():
    return {"status": "ok"}



def _tool_schema(tool):
    """Zwraca schemat argumentów narzędzia dla UI."""
    try:
        args = getattr(tool, "args", None)

        if isinstance(args, dict):
            return {
                "type": "object",
                "properties": args,
                "required": [
                    name
                    for name, spec in args.items()
                    if isinstance(spec, dict)
                    and name in getattr(tool.args_schema, "model_fields", {})
                    and getattr(
                        tool.args_schema.model_fields[name],
                        "is_required",
                        lambda: False,
                    )()
                ],
            }

        schema_model = getattr(tool, "args_schema", None)

        if schema_model is not None and hasattr(
            schema_model, "model_json_schema"
        ):
            schema = schema_model.model_json_schema()
            return {
                "type": schema.get("type", "object"),
                "properties": schema.get("properties", {}),
                "required": schema.get("required", []),
            }

    except Exception:
        logger.exception(
            "Nie można pobrać schematu narzędzia %s",
            getattr(tool, "name", "<unknown>"),
        )

    return {
        "type": "object",
        "properties": {},
        "required": [],
    }

@app.get("/tools")
async def list_tools():
    """Lista narzędzi wraz ze schematami parametrów dla UI."""
    defensive = []

    for t in make_tools():
        defensive.append({
            "name": t.name,
            "description": t.description,
            "category": "cybersec",
            "args_schema": _tool_schema(t),
        })

    offensive = []

    for t in make_pentest_tools():
        offensive.append({
            "name": t.name,
            "description": t.description,
            "category": "pentesting",
            "args_schema": _tool_schema(t),
        })

    return {"tools": defensive + offensive}


@app.get("/models")
async def list_models():
    """Konfiguracja modeli używanych w pipeline (dla panelu w UI)."""
    return get_model_config()


@app.get("/status/{thread_id}")
async def get_status(thread_id: str):
    """Aktualny etap pipeline'u dla danego thread_id - do pollingu z frontendu."""
    return status_store.get_status(thread_id)


@app.get("/tool_output/{thread_id}")
async def get_tool_output(thread_id: str):
    """Proxy do pentest-agenta - live output (stdout/stderr na żywo)
    aktualnie wykonywanego narzędzia ofensywnego dla danej sesji."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"{PENTEST_AGENT_URL}/tool_output/{thread_id}",
                headers={"X-API-Token": PENTEST_AGENT_TOKEN},
            )
            return resp.json()
    except Exception:
        return {"status": "idle", "tool": None, "lines": []}


@app.post("/stop/{thread_id}")
async def stop_pipeline(thread_id: str):
    """Proxy do pentest-agenta - zabija aktualnie dzialajace narzedzie
    ofensywne dla danej sesji, jesli takie wlasnie sie wykonuje."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                f"{PENTEST_AGENT_URL}/stop/{thread_id}",
                headers={"X-API-Token": PENTEST_AGENT_TOKEN},
            )
            return resp.json()
    except Exception as e:
        return {"status": "error", "detail": f"Blad komunikacji z pentest-agent: {e}"}


FINDING_CONCERN_RE = re.compile(r'::finding\[\w+\]\{concern="([^"]+)"')


def _extract_suggested_tools(final_report: str) -> list[dict]:
    """Parsuje bloki ::finding[...]{concern="..."} z finalnego raportu i
    deterministycznie (bez LLM) dopasowuje do nich narzedzia pentestowe,
    pytajac pentest-agent o kazdy unikalny concern. Wynik: lista narzedzi
    z opisem i lista concern ktore je wywolaly (do wyswietlenia "dlaczego")."""
    concerns = list(dict.fromkeys(FINDING_CONCERN_RE.findall(final_report)))
    if not concerns:
        return []
    seen_tools: dict[str, dict] = {}
    try:
        with httpx.Client(timeout=10.0) as client:
            for concern in concerns:
                resp = client.get(
                    f"{PENTEST_AGENT_URL}/suggest_tools/{concern}",
                    headers={"X-API-Token": PENTEST_AGENT_TOKEN},
                )
                data = resp.json()
                for tool in data.get("tools", []):
                    name = tool["name"]
                    if name not in seen_tools:
                        seen_tools[name] = {
                            "name": name,
                            "description": tool["description"],
                            "concerns": [concern],
                        }
                    else:
                        seen_tools[name]["concerns"].append(concern)
    except Exception:
        logger.exception(f"Błąd pobierania sugestii pentestowych dla concerns={concerny}")
        return []
    return list(seen_tools.values())


def _validate_selected_tool_targets(
    selected_tools,
    tool_params,
) -> tuple[bool, str]:
    """
    Safety gate dla jawnie wybranych narzędzi.

    Jeżeli narzędzie posiada parametr target, jego wartość musi
    przejść przez target_scope.

    Brak targetu nie jest tutaj blokowany — część narzędzi może
    korzystać z parametrów innych niż target.
    """

    if not selected_tools:
        return True, "brak jawnie wybranych narzędzi"

    tool_params = tool_params or {}

    for tool_name in selected_tools:
        params = tool_params.get(tool_name) or {}

        target = params.get("target")

        if not target:
            continue

        decision = target_scope(str(target))

        if not decision["allowed"]:
            return (
                False,
                f"Target zablokowany dla narzędzia {tool_name}: "
                f"{decision['reason']}",
            )

    return True, "wszystkie targety przeszły scope gate"


def _run_pipeline_background(
    thread_id: str,
    message: str,
    selected_tools,
    tool_params,
    admin_password: str | None = None,
):
    try:
        allowed, reason = _validate_selected_tool_targets(
            selected_tools,
            tool_params,
        )

        if not allowed:
            logger.warning(
                "Scope gate BLOCKED thread=%s: %s",
                thread_id,
                reason,
            )
            status_store.set_status(
                thread_id,
                "error",
                reason,
            )
            return

        result = graph_app.invoke(
            {
                "thread_id": thread_id,
                "user_request": message,
                "selected_tools": selected_tools,
                "tool_params": tool_params,
                "admin_password": admin_password,
            },
            config={"configurable": {"thread_id": thread_id}},
        )
        content = result["final_report"]
        logger.info(f"Odpowiedź (thread_id={thread_id}): {content[:200]}")
        suggested_tools = _extract_suggested_tools(content)
        status_store.set_result(thread_id, content, suggested_tools)
    except Exception:
        logger.exception(f"Błąd pipeline'u (thread_id={thread_id})")
        status_store.set_status(thread_id, "error", "Błąd podczas przetwarzania")


@app.post("/chat")
async def chat(req: ChatRequest):
    thread_id = req.thread_id or str(uuid.uuid4())
    logger.info(f"Otrzymano wiadomość (thread_id={thread_id}): {req.message}")
    status_store.set_status(thread_id, "starting", "Uruchamiam pipeline...")
    asyncio.create_task(
        asyncio.to_thread(
            _run_pipeline_background,
            thread_id,
            req.message,
            req.selected_tools,
            req.tool_params,
            req.admin_password,
        )
    )
    return {"thread_id": thread_id, "status": "started"}
