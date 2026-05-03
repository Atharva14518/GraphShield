"""
GraphShield API Server
Provides REST endpoints so the dashboard can trigger real scans
without needing the CLI.
"""
from __future__ import annotations

import json
import os
import sys
import traceback
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

PROJECT_ROOT = Path(__file__).resolve().parent

# Ensure the local graphshield package wins over any editable/site-packages copy.
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

app = FastAPI(
    title="GraphShield API",
    description="Agentic vulnerability intelligence engine REST interface",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # Render frontend URL is dynamic; lock down in production if needed
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Request / Response Models ──────────────────────────────────────────────

class ScanRequest(BaseModel):
    target: str          # local path OR GitHub URL
    use_agent: bool = False
    groq_api_key: Optional[str] = None


class StatusResponse(BaseModel):
    db_ready: bool
    db_entries: int
    bloom_ready: bool
    bloom_items: int
    bloom_fp_rate: float
    groq_configured: bool


# ── Helpers ────────────────────────────────────────────────────────────────

def _get_scanner(groq_api_key: Optional[str] = None, use_agent: bool = False):
    from graphshield.core.scanner import GraphShieldScanner
    key = groq_api_key or os.getenv("GROQ_API_KEY", "")
    return GraphShieldScanner(groq_api_key=key, use_agent=use_agent and bool(key))


def _normalize_target(target: str) -> str:
    cleaned = target.strip()
    if cleaned.startswith("https://github.com") or cleaned.startswith("git@github.com"):
        return cleaned
    return str((PROJECT_ROOT / cleaned).resolve()) if not Path(cleaned).is_absolute() else cleaned


# ── Routes ─────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok", "service": "GraphShield API"}


@app.get("/api/status", response_model=StatusResponse)
def get_status():
    from graphshield.config import DB_PATH, BLOOM_PATH
    from graphshield.core.bloom_filter import BloomFilter

    db_ready = DB_PATH.exists()
    db_entries = 0
    if db_ready:
        try:
            import sqlite3
            conn = sqlite3.connect(str(DB_PATH))
            db_entries = conn.execute("SELECT COUNT(*) FROM cve_entries").fetchone()[0]
            conn.close()
        except Exception:
            db_ready = False

    bloom_ready = BLOOM_PATH.exists()
    bloom_items = 0
    bloom_fp = 0.0
    if bloom_ready:
        try:
            bf = BloomFilter.load(BLOOM_PATH)
            stats = bf.stats()
            bloom_items = stats["items_added"]
            bloom_fp = stats["estimated_fp_rate"]
        except Exception:
            bloom_ready = False

    return StatusResponse(
        db_ready=db_ready,
        db_entries=db_entries,
        bloom_ready=bloom_ready,
        bloom_items=bloom_items,
        bloom_fp_rate=bloom_fp,
        groq_configured=bool(os.getenv("GROQ_API_KEY", "")),
    )


@app.post("/api/scan")
def run_scan(req: ScanRequest):
    try:
        scanner = _get_scanner(req.groq_api_key, req.use_agent)
        report = scanner.scan(_normalize_target(req.target))
        return JSONResponse(content=json.loads(report.to_json()))
    except Exception as exc:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/api/scan")
def scan_get(
    target: str = Query(..., description="Local path or GitHub URL to scan"),
    use_agent: bool = Query(False),
):
    """GET convenience endpoint — useful for quick browser testing."""
    return run_scan(ScanRequest(target=target, use_agent=use_agent))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api_server:app", host="127.0.0.1", port=8000, reload=True, log_level="info")
