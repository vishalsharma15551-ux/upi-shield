"""
UPI Shield — FastAPI Application
Serves the frontend and exposes analysis API endpoints.
"""

import os
import logging
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel

from nlp_engine import ScamAnalyzer
from upi_parser import parse_upi_intent

logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(levelname)s  %(message)s")
logger = logging.getLogger(__name__)

# ── Global analyser instance ──────────────────────────────────────────
analyzer: Optional[ScamAnalyzer] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global analyzer
    logger.info("Starting UPI Shield …")
    # Set use_transformer based on env var (default True)
    use_tf = os.environ.get("UPI_SHIELD_NO_MODEL", "0") != "1"
    analyzer = ScamAnalyzer(use_transformer=use_tf)
    yield
    logger.info("Shutting down UPI Shield.")


app = FastAPI(
    title="UPI Shield",
    description="AI-Powered Digital Payment Scam & Coercion Detector",
    version="1.0.0",
    lifespan=lifespan,
)

# ── Request / Response models ─────────────────────────────────────────

class AnalyzeRequest(BaseModel):
    text: str
    source: str = "sms"  # sms | whatsapp | upi_note

class UPIParseRequest(BaseModel):
    upi_string: str

# ── API endpoints ─────────────────────────────────────────────────────

@app.post("/api/analyze")
async def analyze_message(req: AnalyzeRequest):
    """Analyse a message for scam indicators."""
    result = analyzer.analyze(req.text)
    result["source"] = req.source
    return result


@app.post("/api/parse-upi")
async def parse_upi(req: UPIParseRequest):
    """Parse and analyse a UPI intent string."""
    return parse_upi_intent(req.upi_string)


@app.get("/api/health")
async def health():
    """Health check + model status."""
    status = analyzer.get_status() if analyzer else {"status": "initializing"}
    status["service"] = "UPI Shield"
    return status


# ── Serve static frontend ────────────────────────────────────────────

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/", response_class=HTMLResponse)
async def serve_frontend():
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))


# ── Run with uvicorn ──────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
