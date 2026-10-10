"""FastAPI web server providing REST endpoints and local-first monitoring dashboard."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from edgesentinel.analysis.pipeline import EventPipeline
from edgesentinel.config import AppConfig, load_config
from edgesentinel.models import Alert, AlertStatus, Device, NetworkEvent, Severity
from edgesentinel.platform_info import get_platform_info
from edgesentinel.simulation.scenarios import get_scenario_events
from edgesentinel.storage.database import Database


class UpdateAlertRequest(BaseModel):
    status: AlertStatus


def create_app(config: Optional[AppConfig] = None) -> FastAPI:
    cfg = config or load_config()
    db = Database(cfg.storage.database_path)
    pipeline = EventPipeline(config=cfg, db=db)

    app = FastAPI(
        title="EdgeSentinel",
        description="Local-First Lightweight Network Security Monitoring & IDS",
        version="0.1.0"
    )

    # Restrict CORS to localhost
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://127.0.0.1:8080", "http://localhost:8080"],
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH"],
        allow_headers=["*"],
    )

    static_dir = Path(__file__).parent / "static"

    @app.get("/api/status")
    def get_status() -> Dict[str, Any]:
        plat = get_platform_info()
        stats = db.get_stats()
        metrics = pipeline.get_metrics()
        return {
            "platform": plat,
            "stats": stats,
            "metrics": metrics.model_dump(),
            "config": {
                "environment": cfg.environment,
                "capture_backend": cfg.capture.backend,
                "response_mode": cfg.response.mode,
            }
        }

    @app.get("/api/alerts")
    def get_alerts(
        limit: int = Query(50, ge=1, le=500),
        severity: Optional[str] = None,
        status: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        alerts = db.get_alerts(limit=limit, severity=severity, status=status)
        return [a.model_dump() for a in alerts]

    @app.get("/api/alerts/{alert_id}")
    def get_alert_detail(alert_id: str) -> Dict[str, Any]:
        alert = db.get_alert_by_id(alert_id)
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")
        return alert.model_dump()

    @app.patch("/api/alerts/{alert_id}")
    def update_alert(alert_id: str, req: UpdateAlertRequest) -> Dict[str, Any]:
        success = db.update_alert_status(alert_id, req.status)
        if not success:
            raise HTTPException(status_code=404, detail="Alert not found")
        return {"status": "success", "alert_id": alert_id, "new_status": req.status.value}

    @app.get("/api/devices")
    def get_devices() -> List[Dict[str, Any]]:
        devices = db.get_devices()
        return [d.model_dump() for d in devices]

    @app.get("/api/events")
    def get_events(limit: int = Query(50, ge=1, le=200)) -> List[Dict[str, Any]]:
        events = db.get_events(limit=limit)
        return [e.model_dump() for e in events]

    @app.post("/api/simulate/{scenario}")
    def trigger_simulation(scenario: str) -> Dict[str, Any]:
        try:
            events = get_scenario_events(scenario)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

        alerts = pipeline.ingest_events(events)
        return {
            "scenario": scenario,
            "events_generated": len(events),
            "alerts_triggered": len(alerts),
            "alerts": [a.model_dump() for a in alerts]
        }

    @app.get("/", response_class=HTMLResponse)
    def index():
        html_file = static_dir / "index.html"
        if html_file.exists():
            return FileResponse(html_file)
        return HTMLResponse("<h1>EdgeSentinel API active. Frontend file missing.</h1>")

    return app
