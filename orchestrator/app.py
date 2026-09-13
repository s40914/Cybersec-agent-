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
from pentest_tools import make_pentest_tools, _fetch_registry
import status_store
from evidence_store import EvidenceStore
from artifact_pipeline import ArtifactPipeline
from re_pipeline import REPipeline
from sast_pipeline import SASTPipeline, is_source_code
from internal_sensor import InternalSensor
from target_scope import target_scope
import update_malware_db
import auth_db

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

auth_db.init_db()

graph_app = build_app()
evidence_store = EvidenceStore()


class RegisterRequest(BaseModel):
    first_name: str
    last_name: str
    email: str
    password: str


class LoginRequest(BaseModel):
    email: str
    password: str


@app.post("/register")
async def register(req: RegisterRequest):
    """Zaklada nowe konto uzytkownika. Wymagane przed pierwszym logowaniem -
    zgodnie z zasada 'kazde uzycie narzedzia musi byc powiazane z
    konkretna, zidentyfikowana osoba'."""
    if len(req.password) < 8:
        raise HTTPException(status_code=400, detail="Haslo musi miec co najmniej 8 znakow.")
    try:
        user = auth_db.create_user(req.first_name, req.last_name, req.email, req.password)
    except Exception as exc:
        if "UNIQUE constraint failed" in str(exc):
            raise HTTPException(status_code=409, detail="Konto z tym adresem e-mail juz istnieje.")
        logger.exception("REGISTER_ERROR: %s", exc)
        raise HTTPException(status_code=500, detail="Blad podczas zakladania konta.")
    logger.info(f"USER_REGISTERED: email={req.email}")
    return {"status": "ok", "user_id": user["id"]}


@app.post("/login")
async def login(req: LoginRequest):
    """Sprawdza haslo, tworzy sesje. Zwraca token do zapisania w przegladarce."""
    user = auth_db.verify_login(req.email, req.password)
    if user is None:
        logger.warning(f"LOGIN_FAILED: email={req.email}")
        raise HTTPException(status_code=401, detail="Nieprawidlowy e-mail lub haslo.")
    token = auth_db.create_session(user["id"])
    logger.info(f"LOGIN_OK: email={req.email}, user_id={user['id']}")
    return {
        "status": "ok",
        "token": token,
        "user": {
            "id": user["id"],
            "first_name": user["first_name"],
            "last_name": user["last_name"],
            "email": user["email"],
            "is_admin": bool(user["is_admin"]),
        },
    }


@app.get("/verify_session")
async def verify_session(token: str):
    """Sprawdza czy token sesji jest wciaz wazny. Uzywane przez chat-ui
    do decydowania czy pokazac ekran logowania czy aplikacje."""
    user = auth_db.get_user_by_session(token)
    if user is None:
        raise HTTPException(status_code=401, detail="Sesja nieprawidlowa lub wygasla.")
    return {
        "status": "ok",
        "user": {
            "id": user["id"],
            "first_name": user["first_name"],
            "last_name": user["last_name"],
            "email": user["email"],
            "is_admin": bool(user["is_admin"]),
        },
    }


@app.get("/audit_log")
async def get_audit_log(session_token: str, limit: int = 100, user_email: str | None = None):
    """Zwraca log audytowy - kto, kiedy, jakie narzedzie, na jaki cel.
    Dostepny WYLACZNIE dla uzytkownikow z rola administratora - zwykly
    uzytkownik nie powinien widziec historii dzialan innych osob."""
    requester = auth_db.get_user_by_session(session_token)
    if requester is None:
        raise HTTPException(status_code=401, detail="Wymagane logowanie.")
    if not requester.get("is_admin"):
        raise HTTPException(status_code=403, detail="Brak uprawnien - wymagana rola administratora.")
    logs = auth_db.get_audit_log(limit=limit, user_email=user_email)
    return {"status": "ok", "count": len(logs), "logs": logs}

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
    session_token: str | None = None


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

# Typy parametrow, ktorych NIE da sie bezpiecznie wypelnic automatycznie
# z jednego, wspolnego "Celu" podanego w prompcie - wymagaja jawnego
# wskazania przez czlowieka (konkretny parametr zapytania dla sqlmap,
# literalny FUZZ dla ffuf, fraza wyszukiwania dla searchsploit).
_MANUAL_TARGET_TYPES = {"url_with_query", "url_fuzz", "search_term"}


def _tool_requires_manual_target(tool_name: str, registry: dict) -> bool:
    params = registry.get(tool_name, {}).get("params", {})
    for spec in params.values():
        if spec.get("type") in _MANUAL_TARGET_TYPES:
            return True
    return False


@app.get("/tools")
async def list_tools():
    """Lista narzędzi wraz ze schematami parametrów dla UI."""
    try:
        registry = _fetch_registry()
    except Exception:
        registry = {}

    defensive = []

    for t in make_tools():
        defensive.append({
            "name": t.name,
            "description": t.description,
            "category": "cybersec",
            "args_schema": _tool_schema(t),
            "requires_manual_target": False,
        })

    offensive = []

    for t in make_pentest_tools():
        offensive.append({
            "name": t.name,
            "description": t.description,
            "category": "pentesting",
            "args_schema": _tool_schema(t),
            "requires_manual_target": _tool_requires_manual_target(t.name, registry),
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


def _normalize_target_for_tool(raw_target: str, param_type: str) -> str:
    """
    Przeksztalca JEDEN, wspolny cel podany przez uzytkownika (np. goly IP
    albo pelny URL) do formatu wymaganego przez konkretne narzedzie.

    Powstalo, bo administrator nie powinien musiec pamietac ktore
    narzedzie chce goly IP, ktore pelny URL ze schematem, a ktore URL
    z parametrem zapytania - to prowadzilo do pomylek (np. port wpisany
    w pole cookie innego narzedzia, patrz incydent z 2026-09-12).

    NIE dotyczy typow url_with_query / url_fuzz - te wymagaja jawnego,
    konkretnego wskazania parametru/FUZZ przez czlowieka, nie da sie
    tego bezpiecznie zgadnac z samego adresu.
    """
    raw_target = raw_target.strip()

    if param_type == "ip":
        # Wytnij schemat i sciezke, jesli ktos podal pelny URL.
        if "://" in raw_target:
            without_scheme = raw_target.split("://", 1)[1]
            return without_scheme.split("/", 1)[0].split(":", 1)[0]
        return raw_target.split("/", 1)[0].split(":", 1)[0]

    if param_type == "url":
        if "://" in raw_target:
            return raw_target
        return f"http://{raw_target}"

    # url_with_query, url_fuzz, search_term i inne - bez zmian,
    # wymagaja jawnego wskazania przez uzytkownika.
    return raw_target


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

    PRZY OKAZJI: normalizuje tool_params NA MIEJSCU (mutuje dict),
    zeby jeden, wspolny "Cel" podany przez uzytkownika zostal
    przeksztalcony do formatu wymaganego przez kazde narzedzie -
    patrz _normalize_target_for_tool.
    """

    if not selected_tools:
        return True, "brak jawnie wybranych narzędzi"

    tool_params = tool_params if tool_params is not None else {}

    try:
        registry = _fetch_registry()
    except Exception:
        registry = {}

    for tool_name in selected_tools:
        params = tool_params.get(tool_name) or {}

        target = params.get("target")

        if not target:
            continue

        param_type = (
            registry.get(tool_name, {})
            .get("params", {})
            .get("target", {})
            .get("type", "ip")
        )
        normalized = _normalize_target_for_tool(target, param_type)
        if normalized != target:
            params["target"] = normalized
            tool_params[tool_name] = params
            target = normalized

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
    user_email: str | None = None,
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
                "user_email": user_email,
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
    # Wymagamy wazna sesje przed uruchomieniem pipeline'u. Kazde uzycie
    # narzedzia musi byc powiazane z konkretna, zidentyfikowana osoba -
    # patrz auth_db.py.
    user = auth_db.get_user_by_session(req.session_token) if req.session_token else None
    if user is None:
        raise HTTPException(status_code=401, detail="Wymagane logowanie - sesja nieprawidlowa lub wygasla.")

    thread_id = req.thread_id or str(uuid.uuid4())
    logger.info(f"Otrzymano wiadomość (thread_id={thread_id}, user={user['email']}): {req.message}")
    status_store.set_status(thread_id, "starting", "Uruchamiam pipeline...")
    asyncio.create_task(
        asyncio.to_thread(
            _run_pipeline_background,
            thread_id,
            req.message,
            req.selected_tools,
            req.tool_params,
            req.admin_password,
            user["email"],
        )
    )
    return {"thread_id": thread_id, "status": "started"}
