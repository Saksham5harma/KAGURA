from fastapi import APIRouter, WebSocket, WebSocketDisconnect

router = APIRouter()

active_connections = []


@router.websocket("/ws/scan")
async def scan_ws(websocket: WebSocket):

    await websocket.accept()
    active_connections.append(websocket)

    try:
        while True:
            await websocket.receive_text()

    except WebSocketDisconnect:
        active_connections.remove(websocket)

def push_event(event_type, data):

    message = {
        "type": event_type,
        "data": data
    }

    for conn in active_connections:

        try:
            import asyncio
            asyncio.create_task(conn.send_json(message))

        except Exception:
            pass
