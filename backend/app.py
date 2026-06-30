from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.scans import router as scan_router

app = FastAPI(
    title="KAGURA Security Engine",
    version="2.0",
    description="Advanced Recon & Vulnerability Intelligence Platform"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scan_router, prefix="/api")

@app.get("/")
def root():
    return {
        "status": "online",
        "engine": "KAGURA",
        "message": "Scan engine running"
    }


@app.get("/health")
def health():
    return {
        "status": "ok"
    }
