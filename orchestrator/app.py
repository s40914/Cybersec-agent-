import asyncio
import logging
import os
import re
import uuid

import httpx
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from graph import build_app, get_model_config
from tools import make_tools
from pentest_tools import make_pentest_tools
import status_store

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


class ChatRequest(BaseModel):
    message: str
    thread_id: str | None = None
    selected_tools: list[str] | None = None


class ChatResponse(BaseModel):
    response: str
    thread_id: str


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/tools")
async def list_tools():
    """Lista dostępnych narzędzi diagnostycznych (dla dropdownu w UI).
    Pole "category" pozwala UI odróżnić narzędzia defensywne (audyt) od
    ofensywnych (pentesting) bez konieczności zgadywania po nazwie."""
    defensive = [{"name": t.name, "description": t.description, "category": "cybersec"} for t in make_tools()]
    offensive = [{"name": t.name, "description": t.description, "category": "pentesting"} for t in make_pentest_tools()]
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


def _run_pipeline_background(thread_id: str, message: str, selected_tools):
    try:
        result = graph_app.invoke(
            {
                "thread_id": thread_id,
                "user_request": message,
                "selected_tools": selected_tools,
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
        asyncio.to_thread(_run_pipeline_background, thread_id, req.message, req.selected_tools)
    )
    return {"thread_id": thread_id, "status": "started"}
