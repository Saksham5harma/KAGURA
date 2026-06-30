from fastapi import APIRouter
from engines.vuln_engine import VulnEngine

router = APIRouter()
engine = VulnEngine()


@router.get("/scan")
def scan(target: str):

    events = []

    def event_bus(event, data):
        events.append({
            "event": event,
            "data": data
        })

    result = engine.run_full_scan(target, event_bus)

    return {
        "status": "success",
        "meta": result,
        "stream": events
    }
