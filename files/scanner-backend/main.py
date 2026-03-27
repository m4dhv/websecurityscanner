"""
SiteShield — Website Security Scanner Backend
FastAPI + Python real scanning engine
"""

from fastapi import FastAPI, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import asyncio
import time
from datetime import datetime
from scanner import run_full_scan
from models import ScanResult
from db import save_scan, get_recent_scans, get_stats

app = FastAPI(
    title="SiteShield Scanner API",
    description="Real website security scanning engine",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # Lock down to your frontend domain in production
    allow_methods=["GET"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    return {"status": "online", "service": "SiteShield Scanner API"}


@app.get("/scan", response_model=ScanResult)
async def scan(url: str = Query(..., description="Full URL to scan, e.g. https://example.com")):
    """
    Run a full security scan on the given URL.
    Returns SSL info, security headers, vulnerabilities, and performance metrics.
    """
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        result = await asyncio.wait_for(run_full_scan(url), timeout=20.0)
        save_scan(result)
        return result
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Scan timed out after 20 seconds")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")


@app.get("/admin/stats")
def admin_stats():
    """Aggregate stats for the admin dashboard."""
    return get_stats()


@app.get("/admin/scans")
def admin_scans(limit: int = 20):
    """Recent scan history."""
    return get_recent_scans(limit)


@app.get("/health")
def health():
    return {"status": "ok", "timestamp": datetime.utcnow().isoformat()}
