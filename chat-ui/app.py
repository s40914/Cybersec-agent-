import os

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

ORCHESTRATOR_URL = os.getenv("ORCHESTRATOR_URL", "http://orchestrator:8010")
CHAT_TIMEOUT = float(os.getenv("REQUEST_TIMEOUT", "900"))

app = FastAPI()


@app.get("/api/tools")
async def api_tools():
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.get(f"{ORCHESTRATOR_URL}/tools")
        return JSONResponse(content=resp.json(), status_code=resp.status_code)


@app.get("/api/models")
async def api_models():
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.get(f"{ORCHESTRATOR_URL}/models")
        return JSONResponse(content=resp.json(), status_code=resp.status_code)


@app.get("/api/findings")
async def api_findings():
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.get(f"{ORCHESTRATOR_URL}/findings")
        return JSONResponse(content=resp.json(), status_code=resp.status_code)


@app.get("/api/findings/{finding_id}")
async def api_finding(finding_id: str):
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.get(f"{ORCHESTRATOR_URL}/findings/{finding_id}")
        return JSONResponse(content=resp.json(), status_code=resp.status_code)


@app.get("/api/status/{thread_id}")
async def api_status(thread_id: str):
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.get(f"{ORCHESTRATOR_URL}/status/{thread_id}")
        return JSONResponse(content=resp.json(), status_code=resp.status_code)
@app.get("/api/tool_output/{thread_id}")
async def api_tool_output(thread_id: str):
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.get(f"{ORCHESTRATOR_URL}/tool_output/{thread_id}")
        return JSONResponse(content=resp.json(), status_code=resp.status_code)
@app.post("/api/stop/{thread_id}")
async def api_stop(thread_id: str):
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.post(f"{ORCHESTRATOR_URL}/stop/{thread_id}")
        return JSONResponse(content=resp.json(), status_code=resp.status_code)


@app.post("/api/chat")
async def api_chat(request: Request):
    body = await request.json()
    try:
        async with httpx.AsyncClient(timeout=CHAT_TIMEOUT) as client:
            resp = await client.post(f"{ORCHESTRATOR_URL}/chat", json=body)
            return JSONResponse(content=resp.json(), status_code=resp.status_code)
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="Orchestrator nie odpowiedział w wyznaczonym czasie.")
    except httpx.ConnectError:
        raise HTTPException(status_code=502, detail="Nie można połączyć się z orchestratorem.")


# Statyczny frontend - musi być zamontowany na końcu, żeby nie przechwytywał /api/*
app.mount("/", StaticFiles(directory="static", html=True), name="static")
