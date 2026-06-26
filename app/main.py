"""
QueueStorm Investigator — FastAPI Application Entry Point (Scaffold)
GET  /health          : Liveness probe for judge harness
"""

import logging
from fastapi import FastAPI
from fastapi.responses import JSONResponse

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="QueueStorm Investigator",
    description="AI copilot for fintech support agents — SUST CSE Carnival 2026",
    version="1.0.0",
)

@app.get("/health", tags=["Health"])
async def health():
    """Liveness probe — must respond within 60s of service start."""
    return {"status": "ok"}
