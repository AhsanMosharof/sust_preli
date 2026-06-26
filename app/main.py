"""
QueueStorm Investigator — FastAPI Application Entry Point
POST /analyze-ticket  : AI-driven ticket analysis
GET  /health          : Liveness probe for judge harness
"""

import logging
import os
from contextlib import asynccontextmanager

from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger(__name__)


# ─── Lifespan: warm up LLM client at startup ─────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize the LLM client once at startup — not on first request."""
    try:
        from app.llm_client import get_model
        get_model()
        logger.info("✅ LLM client initialized successfully")
    except Exception as e:
        logger.warning(f"⚠️  LLM client init failed: {e}. Fallback responses will be used.")
    yield
    logger.info("Service shutting down.")


# ─── App ──────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="QueueStorm Investigator",
    description="AI copilot for fintech support agents — SUST CSE Carnival 2026",
    version="1.0.0",
    lifespan=lifespan,
)


# ─── Health endpoint ─────────────────────────────────────────────────────────
@app.get("/health", tags=["Health"])
async def health():
    """Liveness probe — must respond within 60s of service start."""
    return {"status": "ok"}


# ─── Main analysis endpoint ───────────────────────────────────────────────────
@app.post("/analyze-ticket", tags=["Analysis"])
async def analyze_ticket(request: Request):
    """
    Analyze a customer support ticket using hybrid Rule + AI reasoning.
    Returns a structured investigation report with evidence verdict,
    case classification, department routing, and a safe customer reply.
    """
    from app.schemas import TicketRequest, TicketResponse
    from app.analyzer import analyze

    try:
        body = await request.json()
    except Exception:
        return JSONResponse(
            {"error": "Invalid JSON in request body."},
            status_code=400,
        )

    try:
        ticket = TicketRequest(**body)
    except Exception as exc:
        # Extract clean message — never expose internal tracebacks
        msg = str(exc).split("\n")[0][:300]
        return JSONResponse(
            {"error": f"Invalid request: {msg}"},
            status_code=422,
        )

    result: TicketResponse = await analyze(ticket)
    return result.model_dump(mode="json")


# ─── Home Dashboard UI ────────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse, tags=["UI"])
async def read_index():
    """Serve the static single-page ticket investigation playground."""
    index_path = os.path.join(os.path.dirname(__file__), "static", "index.html")
    if os.path.exists(index_path):
        with open(index_path, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read(), status_code=200)
    return HTMLResponse(content="<h1>QueueStorm Investigator UI Not Found</h1>", status_code=404)


# ─── Global exception handlers ────────────────────────────────────────────────
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Return clean 422 — never leak Pydantic internals."""
    try:
        msg = exc.errors()[0]["msg"]
    except Exception:
        msg = "Request validation failed."
    return JSONResponse({"error": f"Invalid request: {msg}"}, status_code=422)


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Catch-all — no stack traces, no secret leakage in production."""
    logger.error(f"Unhandled exception on {request.url.path}: {type(exc).__name__}: {exc}")
    return JSONResponse(
        {"error": "Internal server error. Please try again."},
        status_code=500,
    )
