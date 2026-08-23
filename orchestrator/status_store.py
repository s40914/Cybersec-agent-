"""
Prosty, wątkowo-bezpieczny magazyn statusu pipeline'u w pamięci, keyowany
po thread_id. Frontend odpytuje GET /status/{thread_id} co ok. 1s, żeby
pokazać na żywo, który etap (security_agent / report_writers / critic)
aktualnie się wykonuje.
"""
import threading

_lock = threading.Lock()
_status: dict[str, dict] = {}


def set_status(thread_id: str, stage: str, detail: str = "") -> None:
    with _lock:
        _status[thread_id] = {"stage": stage, "detail": detail}


def get_status(thread_id: str) -> dict:
    with _lock:
        return _status.get(thread_id, {"stage": "idle", "detail": ""})


def clear_status(thread_id: str) -> None:
    with _lock:
        _status.pop(thread_id, None)


def set_result(thread_id: str, content: str, suggested_tools: list | None = None) -> None:
    with _lock:
        _status[thread_id] = {
            "stage": "done",
            "detail": "Raport gotowy",
            "result": content,
            "suggested_tools": suggested_tools or [],
        }
