#!/usr/bin/env python3
"""
Demo 04: VERIS Community API
FastAPI REST API over the sample VERIS incident dataset.
"""
import json
import os
from typing import Optional, List
from fastapi import FastAPI, Query, HTTPException
from fastapi.responses import JSONResponse

app = FastAPI(
    title="VERIS Incident Dataset API",
    description="REST API over a sample VERIS-coded incident dataset for SOC analysis training.",
    version="1.0.0",
)

DATA_PATH = os.path.join(os.path.dirname(__file__), "data", "incidents.json")

with open(DATA_PATH) as f:
    INCIDENTS = json.load(f)


def _extract_actor_types(inc: dict) -> List[str]:
    return list(inc.get("actor", {}).keys())


def _extract_action_types(inc: dict) -> List[str]:
    return list(inc.get("action", {}).keys())


@app.get("/", summary="API info")
def root():
    return {
        "title": "VERIS Incident Dataset API",
        "total_incidents": len(INCIDENTS),
        "endpoints": ["/incidents", "/incidents/{id}", "/stats", "/stats/actors", "/stats/actions", "/docs"],
    }


@app.get("/incidents", summary="List incidents")
def list_incidents(
    actor: Optional[str] = Query(None, description="Filter by actor type (external/internal/partner)"),
    action: Optional[str] = Query(None, description="Filter by action category (hacking/malware/social/error/misuse)"),
    industry: Optional[str] = Query(None, description="Filter by NAICS industry code prefix"),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
):
    results = INCIDENTS
    if actor:
        results = [i for i in results if actor in _extract_actor_types(i)]
    if action:
        results = [i for i in results if action in _extract_action_types(i)]
    if industry:
        results = [i for i in results if str(i.get("industry", "")).startswith(industry)]
    total = len(results)
    return {"total": total, "offset": offset, "limit": limit, "incidents": results[offset:offset + limit]}


@app.get("/incidents/{incident_id}", summary="Get single incident")
def get_incident(incident_id: str):
    for inc in INCIDENTS:
        if inc.get("incident_id") == incident_id:
            return inc
    raise HTTPException(status_code=404, detail=f"Incident {incident_id!r} not found")


@app.get("/stats", summary="Overall statistics")
def stats():
    actor_counts = {}
    action_counts = {}
    for inc in INCIDENTS:
        for a in _extract_actor_types(inc):
            actor_counts[a] = actor_counts.get(a, 0) + 1
        for a in _extract_action_types(inc):
            action_counts[a] = action_counts.get(a, 0) + 1
    return {
        "total_incidents": len(INCIDENTS),
        "by_actor": actor_counts,
        "by_action": action_counts,
    }


@app.get("/stats/actors", summary="Actor breakdown")
def stats_actors():
    counts = {}
    for inc in INCIDENTS:
        for a in _extract_actor_types(inc):
            counts[a] = counts.get(a, 0) + 1
    total = len(INCIDENTS)
    return {k: {"count": v, "pct": round(v / total * 100, 1)} for k, v in sorted(counts.items(), key=lambda x: -x[1])}


@app.get("/stats/actions", summary="Action breakdown")
def stats_actions():
    counts = {}
    for inc in INCIDENTS:
        for a in _extract_action_types(inc):
            counts[a] = counts.get(a, 0) + 1
    total = len(INCIDENTS)
    return {k: {"count": v, "pct": round(v / total * 100, 1)} for k, v in sorted(counts.items(), key=lambda x: -x[1])}
