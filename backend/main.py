from fastapi import (
    FastAPI,
    Depends,
    HTTPException,
    Request,
    WebSocket,
    WebSocketDisconnect,
)
from backend.services.cisa_kev import sync_cisa_kev
from backend.services.mitre_attack import sync_mitre_data
from backend.database.db import SessionLocal
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import func, text
from typing import List, Optional
import json
import asyncio
from datetime import datetime, timezone, timedelta
from contextlib import asynccontextmanager
import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from backend.database import db, models, schemas
from backend.services.nvd import run_nvd_sync
from backend.services.asset_filter import rematch_all_cves, matched_software
from backend.services.osint import fetch_osint_alerts
from backend.services.abuseipdb import check_ip_reputation
from backend.services import geoip
from backend.services.ip_blocklists import sync_ip_blocklists
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.events import EVENT_JOB_EXECUTED, EVENT_JOB_ERROR
import threading
import traceback


# Real-time event manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: str):
        for connection in list(self.active_connections):
            try:
                await connection.send_text(message)
            except Exception:
                self.disconnect(connection)


manager = ConnectionManager()
app_scheduler = None  # set in lifespan; /api/system/shutdown waits for its running jobs
JOB_THREAD = "threatlens-job"  # name of one-off background job threads, joined on shutdown
app_loop = None  # set in lifespan; scheduler jobs run in threads and must hop onto it


def notify(message: str):
    """Broadcast from a scheduler thread onto the app's event loop."""
    if app_loop is not None:
        asyncio.run_coroutine_threadsafe(manager.broadcast(message), app_loop)

# Seed mock data logic
# Scheduler reliability helpers
def safe_run_job(job_func, job_name):
    import inspect
    db_gen = db.get_db()
    db_session = next(db_gen)
    try:
        print(f"[SCHEDULER] Starting job: {job_name}")
        sig = inspect.signature(job_func)
        if len(sig.parameters) == 0:
            job_func()
        else:
            job_func(db_session)
        # Log success
        log = models.SchedulerLog(job_name=job_name, status="Success")
        db_session.add(log)
        db_session.commit()
    except Exception as e:
        error_msg = f"{str(e)}\n{traceback.format_exc()}"
        print(f"[SCHEDULER ERROR] Job {job_name} failed: {error_msg}")
        log = models.SchedulerLog(job_name=job_name, status="Failed", error_message=error_msg)
        db_session.add(log)
        db_session.commit()
    finally:
        db_gen.close()

def rematch_in_background():
    """Re-match all CVEs after an asset change off the request path, then tell open pages."""
    def job(session):
        rematch_all_cves(session)
        notify(json.dumps({"type": "CVES_UPDATED", "data": {"rematched": True}}))
    threading.Thread(name=JOB_THREAD, target=safe_run_job, args=(job, "Asset Rematch")).start()

def scheduler_event_listener(event):
    if event.exception:
        print(f"[SCHEDULER EVENT] Job {event.job_id} raised an exception: {event.exception}")
    else:
        print(f"[SCHEDULER EVENT] Job {event.job_id} completed successfully.")

def _relax_flagged_abuse_score(conn):
    """Older databases have flagged_connections.abuse_score NOT NULL; SQLite can't relax that in place,
    so rebuild the table from the current model and copy the rows across (same transaction)."""
    cols = {row[1]: row for row in conn.execute(text("PRAGMA table_info(flagged_connections)"))}
    if not cols or not cols["abuse_score"][3]:
        return
    for index in conn.execute(text("PRAGMA index_list(flagged_connections)")).fetchall():
        if index[3] == "c":  # created by CREATE INDEX, would clash with the new table's index names
            conn.execute(text(f'DROP INDEX "{index[1]}"'))
    conn.execute(text("ALTER TABLE flagged_connections RENAME TO flagged_connections_old"))
    models.FlaggedConnection.__table__.create(conn)
    shared = ", ".join(c for c in cols if c in models.FlaggedConnection.__table__.columns)
    conn.execute(text(f"INSERT INTO flagged_connections ({shared}) SELECT {shared} FROM flagged_connections_old"))
    conn.execute(text("DROP TABLE flagged_connections_old"))


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize database tables
    models.Base.metadata.create_all(bind=db.engine)
    # create_all doesn't add columns to existing tables
    added_columns = {
        "osint_alerts": (("adversary", "VARCHAR"), ("targeted_countries", "JSON"), ("industries", "JSON")),
        "assets": (("latitude", "FLOAT"), ("longitude", "FLOAT"), ("location_label", "VARCHAR")),
        "flagged_connections": (("source", "VARCHAR"), ("reference", "VARCHAR")),
    }
    with db.engine.begin() as conn:
        _relax_flagged_abuse_score(conn)
        conn.execute(text("DROP TABLE IF EXISTS cve_to_groups"))  # no source links CVEs to groups; the model is gone
        # Briefs from the pre-GPT-4o template stated made-up incident counts and advice
        conn.execute(text("DELETE FROM morning_briefs WHERE content LIKE 'ThreatLens detected % active incidents.%"
                          "Monitor network for lateral movement indicators.'"))
        for table, columns in added_columns.items():
            have = {row[1] for row in conn.execute(text(f"PRAGMA table_info({table})"))}
            for col, col_type in columns:
                if col not in have:
                    conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {col} {col_type}"))
    # Seed data
    db_session = next(db.get_db())
    try:
        # Part 4: Startup Sequence
        print("[STARTUP] 1/4 Database initialized.")
        
        from backend.services.mitre_attack import sync_mitre_data
        sync_mitre_data(db_session)
        print("[STARTUP] 2/4 MITRE ATT&CK sync complete.")
        
        from backend.services.cisa_kev import sync_cisa_kev
        sync_cisa_kev(db_session)
        print("[STARTUP] 3/4 CISA KEV sync complete.")
        
    finally:
        db_session.close()
    
    global app_loop
    app_loop = asyncio.get_running_loop()

    # Start Scheduler
    global app_scheduler
    scheduler = app_scheduler = BackgroundScheduler()
    scheduler.add_listener(scheduler_event_listener, EVENT_JOB_EXECUTED | EVENT_JOB_ERROR)
    
    # Trigger jobs immediately, then on interval
    scheduler.add_job(
        lambda: safe_run_job(lambda: run_nvd_sync(notify), "NVD Sync"),
        'interval', minutes=15, next_run_time=datetime.now(),
        misfire_grace_time=300, id="nvd_sync"
    )
    scheduler.add_job(
        lambda: safe_run_job(lambda db: fetch_osint_alerts(db, notify), "OSINT Sync"),
        'interval', minutes=30, next_run_time=datetime.now(),
        misfire_grace_time=300, id="osint_sync"
    )
    scheduler.add_job(
        lambda: safe_run_job(sync_cisa_kev, "CISA KEV Sync"),
        'interval', hours=6, misfire_grace_time=300, id="cisa_sync"
    )
    scheduler.add_job(
        lambda: safe_run_job(sync_mitre_data, "MITRE Sync"),
        'interval', days=7, misfire_grace_time=300, id="mitre_sync"
    )
    scheduler.add_job(
        lambda: safe_run_job(sync_ip_blocklists, "IP Blocklist Sync"),
        'interval', hours=1, next_run_time=datetime.now(),
        misfire_grace_time=300, id="ip_blocklist_sync"
    )

    scheduler.start()

    yield
    if scheduler.running:  # already stopped if /api/system/shutdown ran
        scheduler.shutdown()


app = FastAPI(title="ThreatLens API", version="2.0.0", lifespan=lifespan)

ALLOWED_ORIGINS = ["http://127.0.0.1:5173", "http://localhost:5173", "null"]


@app.middleware("http")
async def reject_foreign_origins(request: Request, call_next):
    # CORS only hides responses; "simple" cross-site POSTs (text/plain, forms) still run, so refuse them.
    # Requests without Origin (local agents, curl) are not from a web page and pass.
    origin = request.headers.get("origin")
    if origin is not None and origin not in ALLOWED_ORIGINS:
        from fastapi.responses import JSONResponse
        return JSONResponse({"detail": "Origin not allowed"}, status_code=403)
    return await call_next(request)

app.add_middleware(
    CORSMiddleware,
    # the app's own pages only; packaged Electron loads file:// and sends Origin: null
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.websocket("/ws/events")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Keep connection open
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)


@app.get("/")
async def root():
    return {"status": "online", "version": "2.0.0"}


def _local_midnight_utc():
    """Start of the user's local day as naive UTC, the way SQLite stores our datetimes."""
    return (datetime.now().astimezone().replace(hour=0, minute=0, second=0, microsecond=0)
            .astimezone(timezone.utc).replace(tzinfo=None))


@app.get("/api/overview")
async def get_overview(db: Session = Depends(db.get_db)):
    """Get overview metrics for dashboard"""
    try:
        today = _local_midnight_utc()
        cves_today = db.query(models.CVE).filter(models.CVE.published_date >= today)
        total_cves = cves_today.count()
        active_incidents = (
            db.query(models.Incident)
            .filter(models.Incident.status == "Active")
            .count()
        )
        critical_count = (
            db.query(models.CVE).filter(models.CVE.risk_band == "CRITICAL").count()
        )
        assets_monitored = db.query(models.Asset).count()
        
        # Get severity breakdown
        from collections import Counter
        tiers = Counter((c.risk_band or "").title() for c in cves_today.all())
        severity_breakdown = [
            {"name": t, "value": tiers.get(t, 0)}
            for t in ["Critical", "High", "Medium", "Low"]
        ]
        
        # Get top 5 critical threats — use real risk_score from scoring engine
        top_threats = db.query(models.CVE).order_by(
            models.CVE.risk_score.desc().nullslast(),
            models.CVE.cvss_score.desc()
        ).limit(5).all()
        
        top_threats_data = []
        for threat in top_threats:
            desc = threat.description or ''
            top_threats_data.append({
                'id': threat.id,
                'cve_id': threat.cve_id,
                'description': desc[:100] + '...' if len(desc) > 100 else desc,
                'risk_score': round(threat.risk_score or 0, 1),
                'cvss_score': threat.cvss_score,
                'epss_score': threat.epss_score,
                'cisa_kev': bool(threat.cisa_kev),
                'risk_band': threat.risk_band,
            })
        
        # Get activity log (simplified)
        activity_log = []
        recent_cves = db.query(models.CVE).order_by(models.CVE.created_at.desc()).limit(5).all()
        for cve in recent_cves:
            activity_log.append({
                'id': f"cve-{cve.id}",
                'type': 'CVE',
                'message': f"New CVE {cve.cve_id} detected",
                'timestamp': _iso_utc(cve.created_at or datetime.now(timezone.utc)),
                'severity': (cve.risk_band or '').title()
            })
        
        recent_incidents = db.query(models.Incident).order_by(models.Incident.created_at.desc()).limit(5).all()
        asset_names = dict(db.query(models.Asset.id, models.Asset.name).all())
        for incident in recent_incidents:
            machine = asset_names.get(incident.machine_id) or f"asset #{incident.machine_id}"
            activity_log.append({
                'id': f"incident-{incident.id}",
                'type': 'Incident',
                'message': f"{incident.type or 'Security incident'} on {machine}",
                'timestamp': _iso_utc(incident.created_at or datetime.now(timezone.utc)),
                'severity': incident.severity
            })
        activity_log.sort(key=lambda a: a['timestamp'], reverse=True)  # all ISO UTC, so text order is time order
        
        # Get morning brief
        morning_brief = db.query(models.MorningBrief).order_by(models.MorningBrief.date.desc()).first()
        
        return {
            'metrics': {
                'totalCves': total_cves,
                'activeIncidents': active_incidents,
                'criticalThreats': critical_count,
                'assetsMonitored': assets_monitored
            },
            'severityBreakdown': severity_breakdown,
            'topThreats': top_threats_data,
            'activityLog': activity_log,
            'morningBrief': {
                'content': morning_brief.content if morning_brief else None,
                'date': _iso_utc(morning_brief.date) if morning_brief else None
            }
        }
    except Exception as e:
        logging.error(f"Error in overview endpoint: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")


@app.get("/api/health")
async def get_health(db: Session = Depends(db.get_db)):
    now = datetime.now(timezone.utc)
    # NVD: check most recent CVE ingested
    latest_cve = db.query(models.CVE).order_by(models.CVE.created_at.desc()).first()
    nvd_mins = (now - latest_cve.created_at.replace(tzinfo=timezone.utc)).total_seconds() / 60 if latest_cve and latest_cve.created_at else 9999
    # OSINT/OTX: check most recent OSINT alert
    latest_osint = db.query(models.OSINTAlert).order_by(models.OSINTAlert.created_at.desc()).first()
    otx_mins = (now - latest_osint.created_at.replace(tzinfo=timezone.utc)).total_seconds() / 60 if latest_osint and latest_osint.created_at else 9999
    # Agent: most recently seen asset
    latest_asset = db.query(models.Asset).order_by(models.Asset.last_seen.desc()).first()
    agent_secs = (now - latest_asset.last_seen.replace(tzinfo=timezone.utc)).total_seconds() if latest_asset and latest_asset.last_seen else 9999

    import os
    vt_key = os.getenv("VIRUSTOTAL_API_KEY", "")
    abuse_key = os.getenv("ABUSEIPDB_API_KEY", "")
    ai_key = os.getenv("GPT4O_API_KEY", "")

    # Status logic with thresholds
    nvd_status = "Live" if nvd_mins < 20 else ("Delayed" if nvd_mins < 60 else "Down")
    otx_status = "Live" if otx_mins < 40 else ("Delayed" if otx_mins < 120 else "Down")

    return {
        "nvd":      {"status": nvd_status, "detail": f"{int(nvd_mins)}m ago"},
        "otx":      {"status": otx_status, "detail": f"{int(otx_mins)}m ago"},
        "abuseipdb":{"status": "Active" if abuse_key        else "Down",   "detail": "API key present" if abuse_key else "No key"},
        "virustotal":{"status":"Active" if vt_key           else "Down",   "detail": "API key present" if vt_key else "No key"},
        "ai":       {"status": "Ready"  if ai_key           else "Down",   "detail": "GPT-4o key present" if ai_key else "No API key"},
        "agent":    {"status": "Online" if agent_secs < 60  else "Offline","detail": f"{int(agent_secs)}s ago"},
    }


async def ask_gpt4o(system: str, user: str, max_tokens: int = 600, json_mode: bool = False) -> str:
    """One GPT-4o call with GPT4O_API_KEY. Errors become HTTP errors, never fallback text."""
    from openai import AsyncOpenAI
    key = os.getenv("GPT4O_API_KEY")
    if not key:
        raise HTTPException(status_code=503, detail="AI unavailable: GPT4O_API_KEY is not set")
    try:
        response = await AsyncOpenAI(api_key=key).chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
            max_tokens=max_tokens,
            temperature=0.2,
            **({"response_format": {"type": "json_object"}} if json_mode else {}),
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        logging.error(f"[GPT-4o] {e}")
        raise HTTPException(status_code=502, detail=f"AI service error: {e}")


async def ask_gpt4o_json(system: str, user: str, max_tokens: int = 800) -> dict:
    try:
        return json.loads(await ask_gpt4o(system, user, max_tokens, json_mode=True))
    except json.JSONDecodeError:
        raise HTTPException(status_code=502, detail="AI service returned malformed JSON")


def _cve_context_line(c) -> str:
    kev = " [KEV]" if c.cisa_kev else ""
    ransomware = " [KEV ransomware]" if c.ransomware_use else ""
    affected = f" [affects {c.affected_asset_count} of your assets]" if c.asset_affected else ""
    epss = f" EPSS:{round((c.epss_score or 0)*100, 1)}%" if c.epss_score else ""
    return (f"  - {c.cve_id} Risk:{round(c.risk_score or 0)} ({c.risk_band}) CVSS:{c.cvss_score or 'N/A'}"
            f"{epss}{kev}{ransomware}{affected} | {(c.description or '')[:160]}")


NO_GUESSING = ("Use ONLY the facts in the data provided. Do not invent CVEs, threat actors, malware, techniques, "
               "counts, activity or patch status. If the data shows nothing notable, say so.")


@app.post("/api/morning-brief/generate")
async def generate_morning_brief(db: Session = Depends(db.get_db)):
    """Daily brief written by GPT-4o from stored CVEs, incidents and OSINT alerts."""
    existing = db.query(models.MorningBrief).filter(models.MorningBrief.date >= _local_midnight_utc()).first()
    top_cves = db.query(models.CVE).order_by(models.CVE.risk_score.desc().nullslast()).limit(10).all()
    active = db.query(models.Incident).filter(models.Incident.status == "Active").limit(10).all()
    osint = db.query(models.OSINTAlert).order_by(models.OSINTAlert.created_at.desc()).limit(10).all()
    data = "\n\n".join([
        "HIGHEST RISK-SCORE CVEs (score and band from the platform's scoring engine):\n"
        + ("\n".join(_cve_context_line(c) for c in top_cves) or "  none"),
        "ACTIVE INCIDENTS:\n" + ("\n".join(
            f"  - #{i.id} [{i.severity}] {i.type} {i.process_name or ''}: {(i.details or '')[:150]}" for i in active) or "  none"),
        "RECENT OSINT ALERTS:\n" + ("\n".join(
            f"  - [{o.severity}] {o.type} {o.indicator} ({o.source}): {(o.description or '')[:120]}" for o in osint) or "  none"),
    ])
    result = await ask_gpt4o_json(
        "You write the daily security brief for a SOC analyst. " + NO_GUESSING + " Return JSON: "
        '{"summary": "3-5 sentences", "patterns": "patterns visible across the data, or an empty string", '
        '"actions": [{"task": "...", "priority": "High|Medium|Low"}]} with at most 5 actions, '
        "each naming an item from the data.",
        data,
    )
    content = str(result.get("summary") or "").strip()
    if not content:
        raise HTTPException(status_code=502, detail="AI service returned an empty brief")
    patterns = str(result.get("patterns") or "").strip()
    actions = [a for a in result.get("actions") or [] if isinstance(a, dict) and a.get("task")][:5]
    top_threats = [{"name": c.cve_id, "risk": c.risk_band} for c in top_cves[:3]]
    if existing:
        existing.content, existing.patterns, existing.actions, existing.top_threats = content, patterns, actions, top_threats
        db.commit()
        await manager.broadcast(json.dumps({"type": "MORNING_BRIEF_GENERATED", "time": str(datetime.now(timezone.utc))}))
        return existing
    brief = models.MorningBrief(
        date=datetime.now(timezone.utc), content=content,
        top_threats=top_threats,
        active_incidents=[{"id": i.id, "type": i.type} for i in active[:5]],
        patterns=patterns,
        actions=actions,
    )
    db.add(brief)
    db.commit()
    db.refresh(brief)
    await manager.broadcast(json.dumps({"type": "MORNING_BRIEF_GENERATED", "time": str(datetime.now(timezone.utc))}))
    return brief


def _filtered_cves(db: Session, severity=None, epss_min=None, epss_pct_min=None, band=None, affected_only=False):
    """CVE query with the Global Threats filters (shared by the table and the graph)."""
    query = db.query(models.CVE)
    if affected_only:
        query = query.filter(models.CVE.asset_affected == True)
    if severity:
        query = query.filter(models.CVE.cvss_score >= severity)
    if epss_min:
        query = query.filter(models.CVE.epss_score >= epss_min)
    if epss_pct_min:
        query = query.filter(models.CVE.epss_percentile >= epss_pct_min)
    if band:
        query = query.filter(models.CVE.risk_band == band.upper())
    return query


@app.get("/api/cves", response_model=List[schemas.CVEResponse])
async def get_cves(
    skip: int = 0,
    limit: int = 50,
    severity: Optional[float] = None,
    epss_min: Optional[float] = None,
    epss_pct_min: Optional[float] = None,
    sort: Optional[str] = None,
    band: Optional[str] = None,
    affected_only: bool = False,
    db: Session = Depends(db.get_db),
):
    query = _filtered_cves(db, severity, epss_min, epss_pct_min, band, affected_only)
    sort_columns = {
        "risk_score": models.CVE.risk_score,
        "epss": models.CVE.epss_score,
        "cvss": models.CVE.cvss_score,
        "published": models.CVE.published_date,
    }
    if sort in sort_columns:
        query = query.order_by(sort_columns[sort].desc().nullslast())
    else:
        query = query.order_by(models.CVE.created_at.desc())
        
    return query.offset(skip).limit(limit).all()


@app.get("/api/cves/graph")
async def get_threat_graph(
    epss_pct_min: Optional[float] = None,
    band: Optional[str] = None,
    affected_only: bool = False,
    db: Session = Depends(db.get_db),
):
    # Top 20 CVEs by risk within the page's filters, linked to the weakness types (CWE) NVD publishes.
    cves = (
        _filtered_cves(db, epss_pct_min=epss_pct_min, band=band, affected_only=affected_only)
        .order_by(models.CVE.risk_score.desc().nullslast())
        .limit(20)
        .all()
    )
    nodes, links, cwe_nodes_added = [], [], set()
    for cve in cves:
        nodes.append({
            "id": cve.cve_id,
            "type": "cve",
            "val": round(cve.cvss_score or 5, 1),
            "cvss": cve.cvss_score,
            "risk": cve.risk_score,
            "kev": cve.cisa_kev,
        })
        cwes = {
            d["value"]
            for w in (cve.raw_json or {}).get("weaknesses", [])
            for d in w.get("description", [])
            if d.get("value", "").startswith("CWE-")
        }
        for cwe in sorted(cwes):
            if cwe not in cwe_nodes_added:
                nodes.append({"id": cwe, "type": "cwe", "val": 8})
                cwe_nodes_added.add(cwe)
            links.append({"source": cve.cve_id, "target": cwe, "source_label": "NVD"})

    return {"nodes": nodes, "links": links}

@app.get("/api/cves/{cve_id}", response_model=schemas.CVEResponse)
async def get_cve_detail(cve_id: str, db: Session = Depends(db.get_db)):
    cve = db.query(models.CVE).filter(models.CVE.cve_id == cve_id).first()
    if not cve:
        raise HTTPException(status_code=404, detail="CVE not found")
    return cve


@app.get("/api/assets")
async def get_assets(db: Session = Depends(db.get_db)):
    assets = db.query(models.Asset).all()
    result = []
    for asset in assets:
        incidents = db.query(models.Incident).filter(models.Incident.machine_id == asset.id).all()
        active_incidents = [i for i in incidents if i.status == "Active"]
        blocked = [i for i in incidents if i.auto_response_action and ("kill" in (i.auto_response_action or "").lower() or "block" in (i.auto_response_action or "").lower())]
        quarantined = [i for i in incidents if "quarantine" in (i.auto_response_action or "").lower()]

        # Risk score: highest cvss-derived score from active incidents
        def severity_to_score(sev):
            return {"Critical": 92, "High": 72, "Medium": 45, "Low": 20}.get(sev, 0)
        risk_score = max((severity_to_score(i.severity) for i in active_incidents), default=0)

        latest_incident = incidents[0] if incidents else None

        result.append({
            "id": asset.id,
            "name": asset.name,
            "os": asset.os,
            "software_list": asset.software_list,
            "ip_address": asset.ip_address,
            "last_seen": asset.last_seen.isoformat() if asset.last_seen else None,
            "status": asset.status,
            "latitude": asset.latitude,
            "longitude": asset.longitude,
            "location_label": asset.location_label,
            "risk_score": risk_score,
            "active_incident_count": len(active_incidents),
            "threats_blocked": len(blocked),
            "files_quarantined": len(quarantined),
            "latest_incident_summary": (latest_incident.type + (": " + latest_incident.process_name if latest_incident.process_name else "")) if latest_incident else None,
        })
    return result


@app.post("/api/assets", response_model=schemas.AssetResponse)
async def register_asset(
    asset: schemas.AssetCreate, db: Session = Depends(db.get_db)
):
    db_asset = models.Asset(**asset.model_dump())
    db.add(db_asset)
    db.commit()
    db.refresh(db_asset)
    rematch_in_background()
    await manager.broadcast(json.dumps({"type": "ASSET_ADDED", "data": {"name": db_asset.name, "id": db_asset.id}}))
    return db_asset


@app.delete("/api/assets/{asset_id}")
async def delete_asset(asset_id: int, db: Session = Depends(db.get_db)):
    asset = db.query(models.Asset).filter(models.Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    
    # Also delete associated incidents
    db.query(models.Incident).filter(models.Incident.machine_id == asset_id).delete()
    
    db.delete(asset)
    db.commit()
    rematch_in_background()

    await manager.broadcast(json.dumps({"type": "ASSET_DELETED", "data": {"id": asset_id}}))
    return {"status": "success", "message": "Asset deleted"}


@app.patch("/api/assets/{asset_id}/location")
async def set_asset_location(asset_id: int, location: schemas.AssetLocation, db: Session = Depends(db.get_db)):
    """Pin an asset where the user clicked on the Attack Map; nulls clear it."""
    asset = db.query(models.Asset).filter(models.Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    if (location.latitude is None) != (location.longitude is None):
        raise HTTPException(status_code=422, detail="latitude and longitude must be set together")
    asset.latitude, asset.longitude = location.latitude, location.longitude
    asset.location_label = location.location_label if location.latitude is not None else None
    db.commit()
    return {"id": asset.id, "latitude": asset.latitude, "longitude": asset.longitude,
            "location_label": asset.location_label}


@app.get("/api/assets/{asset_id}/incidents", response_model=List[schemas.IncidentResponse])
async def get_asset_incidents(asset_id: int, db: Session = Depends(db.get_db)):
    return db.query(models.Incident).filter(models.Incident.machine_id == asset_id).order_by(models.Incident.created_at.desc()).all()


@app.get("/api/incidents", response_model=List[schemas.IncidentResponse])
async def get_incidents(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    db: Session = Depends(db.get_db),
):
    query = db.query(models.Incident)
    if status:
        query = query.filter(models.Incident.status == status)
    if severity:
        query = query.filter(models.Incident.severity == severity)
    return query.order_by(models.Incident.created_at.desc()).all()


@app.get("/api/incidents/{id}", response_model=schemas.IncidentResponse)
async def get_incident_detail(id: int, db: Session = Depends(db.get_db)):
    incident = (
        db.query(models.Incident).filter(models.Incident.id == id).first()
    )
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@app.post("/api/incidents", response_model=schemas.IncidentResponse)
async def create_incident(
    incident: schemas.IncidentCreate, db: Session = Depends(db.get_db)
):
    db_incident = models.Incident(**incident.model_dump())
    db.add(db_incident)
    db.commit()
    db.refresh(db_incident)
    await manager.broadcast(json.dumps({
        "type": "NEW_INCIDENT",
        "data": {
            "id": db_incident.id,
            "type": db_incident.type,
            "severity": db_incident.severity,
            "machine_id": db_incident.machine_id,
            "status": db_incident.status,
            "created_at": str(db_incident.created_at)
        }
    }))
    return db_incident


@app.patch("/api/incidents/{id}", response_model=schemas.IncidentResponse)
async def update_incident(
    id: int, update: schemas.IncidentUpdate, db: Session = Depends(db.get_db)
):
    incident = db.query(models.Incident).filter(models.Incident.id == id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    for field, value in update.model_dump(exclude_none=True).items():
        if field == "timeline" and incident.timeline:
            # Append to existing timeline
            incident.timeline = (incident.timeline or []) + value
        else:
            setattr(incident, field, value)
    db.commit()
    db.refresh(incident)
    await manager.broadcast(json.dumps({"type": "INCIDENT_UPDATE", "id": id, "status": incident.status}))
    return incident


@app.post("/api/incidents/{id}/respond")
async def respond_to_incident(
    id: int, action: schemas.AnalystAction, db: Session = Depends(db.get_db)
):
    incident = (
        db.query(models.Incident).filter(models.Incident.id == id).first()
    )
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    if action.action == "approve":
        incident.status = "Resolved"
        response_note = f"Analyst approved response. Note: {action.analyst_note or 'None'}"
    else:
        incident.status = "Investigating"
        response_note = f"Analyst rejected auto-response. Note: {action.analyst_note or 'None'}"

    timeline_entry = {"time": str(datetime.now(timezone.utc)), "action": response_note, "actor": "Analyst"}
    incident.timeline = (incident.timeline or []) + [timeline_entry]
    db.commit()
    await manager.broadcast(
        json.dumps(
            {
                "type": "INCIDENT_UPDATE",
                "id": id,
                "status": incident.status,
                "action": action.action,
            }
        )
    )
    return {"status": "success", "incident_status": incident.status}


@app.get("/api/morning-brief", response_model=schemas.MorningBriefResponse)
async def get_morning_brief(db: Session = Depends(db.get_db)):
    brief = (
        db.query(models.MorningBrief)
        .order_by(models.MorningBrief.date.desc())
        .first()
    )
    if not brief:
        raise HTTPException(
            status_code=404, detail="No morning brief available"
        )
    return brief


@app.get("/api/stats/asset-exposure")
async def get_asset_exposure_stats(db: Session = Depends(db.get_db)):
    total_cves = db.query(models.CVE).count()
    affecting_assets = db.query(models.CVE).filter(models.CVE.asset_affected == True).count()
    
    # Exposure score: % of critical/high CVEs affecting assets
    crit_high_cves = db.query(models.CVE).filter(models.CVE.cvss_score >= 7.0).all()
    total_crit_high = len(crit_high_cves)
    affecting_crit_high = sum(1 for c in crit_high_cves if c.asset_affected)
    exposure_score = (affecting_crit_high / total_crit_high * 100) if total_crit_high > 0 else 0
    
    # Most exposed asset
    from collections import Counter
    assets = db.query(models.Asset).all()
    # In a real app we'd have a mapping table. For now, we calculate it.
    # Note: This is simplified.
    affected_cves = db.query(models.CVE).filter(models.CVE.asset_affected == True).all()
    asset_counts = [
        {"name": asset.name, "count": sum(1 for cve in affected_cves if matched_software(cve, asset.software_list))}
        for asset in assets
    ]
    
    most_exposed = max(asset_counts, key=lambda x: x["count"], default={"name": "N/A", "count": 0})
    
    return {
        "total_cves": total_cves,
        "affecting_your_assets": affecting_assets,
        "exposure_score": round(exposure_score, 1),
        "most_exposed_asset": most_exposed
    }

@app.get("/api/assets/exposure-detail")
async def get_assets_exposure_detail(db: Session = Depends(db.get_db)):
    try:
        assets = db.query(models.Asset).all()
        logging.debug(f"Assets retrieved: {assets}")

        result = []
        for asset in assets:
            count = 0
            highest_risk_cve = None
            max_score = 0
            vulnerable_pkg = "N/A"

            for cve in db.query(models.CVE).filter(models.CVE.asset_affected == True).all():
                matched = matched_software(cve, asset.software_list)
                if matched:
                    count += 1
                    if cve.cvss_score is not None and cve.cvss_score > max_score:
                        max_score = cve.cvss_score
                        highest_risk_cve = {"id": cve.cve_id, "score": cve.cvss_score}
                        vulnerable_pkg = matched[0]

            result.append({
                "hostname": asset.name,
                "os": asset.os,
                "affecting_cves": count,
                "highest_risk_cve": highest_risk_cve,
                "most_vulnerable_package": vulnerable_pkg
            })
        return result
    except Exception as e:
        logging.error(f"Error in get_assets_exposure_detail: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error")


@app.get("/api/network/flagged-ips")
async def get_flagged_ips(db: Session = Depends(db.get_db)):
    return db.query(models.FlaggedConnection).order_by(models.FlaggedConnection.abuse_score.desc()).all()

@app.get("/api/check-ip/{ip}")
async def get_ip_reputation_endpoint(ip: str, machine_id: Optional[int] = None, db: Session = Depends(db.get_db)):
    machine_hostname = None
    if machine_id:
        asset = db.query(models.Asset).filter(models.Asset.id == machine_id).first()
        if asset: machine_hostname = asset.name
            
    try:
        data = check_ip_reputation(ip, db_session=db, machine_id=machine_id, machine_hostname=machine_hostname)
    except ValueError:
        raise HTTPException(status_code=400, detail="Not a valid IP address")

    # Broadcast if malicious
    if data.get("is_malicious"):
        await manager.broadcast(json.dumps({
            "type": "FLAGGED_CONNECTION",
            "data": {
                "machine_hostname": machine_hostname or "Unknown",
                "destination_ip": ip,
                "abuse_score": data.get("score"),
                "source": data.get("source"),
                "reference": data.get("reference"),
                "country": data.get("country"),
                "isp": data.get("isp"),
                "last_seen": str(datetime.now(timezone.utc))
            }
        }))
    return data


@app.post("/api/ingest/nvd")
async def ingest_nvd():
    threading.Thread(name=JOB_THREAD, target=lambda: safe_run_job(lambda: run_nvd_sync(notify), "Manual NVD Sync")).start()
    return {"status": "started"}

@app.post("/api/ingest/otx")
async def ingest_otx():
    threading.Thread(name=JOB_THREAD, target=lambda: safe_run_job(lambda db: fetch_osint_alerts(db, notify), "Manual OSINT Sync")).start()
    return {"status": "started"}

@app.post("/api/ingest/mitre")
async def ingest_mitre():
    threading.Thread(name=JOB_THREAD, target=lambda: safe_run_job(sync_mitre_data, "Manual MITRE Sync")).start()
    return {"status": "started"}

@app.post("/api/system/shutdown")
def shutdown_backend():
    """Clean exit for the desktop app's quit: let running syncs and background jobs finish,
    close the database, then end the process (a hard kill mid-write is what corrupts the database files)."""
    if app_scheduler is not None and app_scheduler.running:
        app_scheduler.shutdown(wait=True)
    for t in threading.enumerate():
        if t.name == JOB_THREAD and t is not threading.current_thread():
            t.join(timeout=120)
    db.engine.dispose()
    threading.Timer(0.5, os._exit, args=(0,)).start()  # after this response is sent
    return {"status": "stopped"}


@app.get("/api/scheduler/logs")
async def get_scheduler_logs(db: Session = Depends(db.get_db)):
    return db.query(models.SchedulerLog).order_by(models.SchedulerLog.ran_at.desc()).limit(20).all()

def _cve_or_404(db: Session, cve_id: str):
    cve = db.query(models.CVE).filter(models.CVE.cve_id == cve_id).first()
    if not cve:
        raise HTTPException(status_code=404, detail="CVE not found")
    return cve


def _cve_facts(cve, kev) -> dict:
    """Published fields only (NVD, EPSS, CISA KEV, asset match) for the AI prompt."""
    raw = cve.raw_json or {}
    refs = raw.get("references", [])
    cvss = ((raw.get("metrics", {}).get("cvssMetricV31") or [{}])[0]).get("cvssData", {})
    return {
        "cve_id": cve.cve_id,
        "description": cve.description,
        "published": str(cve.published_date),
        "cvss_score": cve.cvss_score,
        "cvss_vector": cvss.get("vectorString"),
        "weaknesses_cwe": sorted({d["value"] for w in raw.get("weaknesses", [])
                                  for d in w.get("description", []) if d.get("value", "").startswith("CWE-")}),
        "affected_products_from_nvd_cpe": cve.affected_products or [],
        "reference_tags": sorted({t for r in refs for t in r.get("tags", [])}),
        "patch_or_advisory_links": [r["url"] for r in refs
                                    if {"Patch", "Vendor Advisory"} & set(r.get("tags", []))][:5],
        "epss_percentile": cve.epss_percentile,
        "cisa_kev": {"required_action": kev.required_action, "due_date": kev.due_date,
                     "known_ransomware_use": bool(kev.ransomware_use)} if kev else None,
        "matches_software_on_your_assets": cve.affected_asset_count or 0,
    }


@app.get("/api/cves/{cve_id}/ai-summary")
async def get_cve_ai_summary(cve_id: str, db: Session = Depends(db.get_db)):
    """The stored GPT-4o summary, or {"generated": false} if none was made yet."""
    cve = _cve_or_404(db, cve_id)
    return json.loads(cve.ai_summary) if cve.ai_summary else {"generated": False}


@app.post("/api/cves/{cve_id}/ai-summary")
async def generate_cve_ai_summary(cve_id: str, db: Session = Depends(db.get_db)):
    """Summary written by GPT-4o from the CVE's published fields; stored so each CVE costs one call."""
    cve = _cve_or_404(db, cve_id)
    kev = db.query(models.CisaKev).filter(models.CisaKev.cve_id == cve_id).first()
    result = await ask_gpt4o_json(
        "You explain one CVE to a SOC analyst. " + NO_GUESSING +
        " If a field is missing (for example no affected products or no patch link), say it is not published yet. "
        'Return JSON: {"what_is_affected": "1-2 sentences", "how_it_works": "1-3 sentences", '
        '"what_to_do_now": "1-3 sentences; use the CISA KEV required action and patch links when given"}.',
        "CVE RECORD (JSON):\n" + json.dumps(_cve_facts(cve, kev), default=str),
    )
    fields = ("what_is_affected", "how_it_works", "what_to_do_now")
    summary = {f: str(result.get(f) or "").strip() for f in fields}
    if not all(summary.values()):
        raise HTTPException(status_code=502, detail="AI service returned an incomplete summary")
    summary.update(generated=True, model="gpt-4o", generated_at=datetime.now(timezone.utc).isoformat())
    cve.ai_summary = json.dumps(summary)
    db.commit()
    return summary


@app.get("/api/cves/{cve_id}/correlations")
async def get_cve_correlations(cve_id: str, db: Session = Depends(db.get_db)):
    """Your assets whose software NVD lists as affected (CPE match), and their open incidents.

    An open incident on an affected asset is context, not evidence that this CVE was exploited.
    """
    cve = _cve_or_404(db, cve_id)
    assets = []
    for asset in db.query(models.Asset).all():
        software = matched_software(cve, asset.software_list)
        if software:
            assets.append({"id": asset.id, "name": asset.name, "software": software})
    incidents = db.query(models.Incident).filter(
        models.Incident.machine_id.in_([a["id"] for a in assets]),
        models.Incident.status != "Resolved",
    ).all() if assets else []
    return {
        "affected_assets": assets,
        "open_incidents": [{"id": i.id, "type": i.type, "severity": i.severity, "asset_id": i.machine_id}
                           for i in incidents],
    }

@app.get("/api/incidents/{incident_id}/correlations")
async def get_incident_correlations(incident_id: int, db: Session = Depends(db.get_db)):
    """Get correlation data for an incident"""
    try:
        incident = db.query(models.Incident).filter(models.Incident.id == incident_id).first()
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")
        
        # Look for related CVEs (simplified correlation logic)
        related_cves = db.query(models.CVE).filter(
            models.CVE.actively_exploited == True
        ).limit(5).all()
        
        correlation_statement = None
        if related_cves and incident.severity in ['Critical', 'High']:
            correlation_statement = f"Incident behavior matches exploitation patterns of {related_cves[0].cve_id if related_cves else 'known vulnerabilities'}"
        
        return {
            'correlation_statement': correlation_statement,
            'related_cves': [cve.cve_id for cve in related_cves],
            'correlation_score': 0.7 if correlation_statement else 0.0
        }
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error getting correlations for incident {incident_id}: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/api/incidents/{incident_id}/playbook")
async def get_incident_playbook(incident_id: int, db: Session = Depends(db.get_db)):
    """Remediation playbook written by GPT-4o from this incident's recorded fields."""
    incident = db.query(models.Incident).filter(models.Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    asset = db.query(models.Asset).filter(models.Asset.id == incident.machine_id).first()
    facts = json.dumps({
        "type": incident.type, "severity": incident.severity, "status": incident.status,
        "process_name": incident.process_name, "details": incident.details,
        "mitre_tags": incident.mitre_tags, "auto_response_action": incident.auto_response_action,
        "timeline": incident.timeline,
        "asset": {"name": asset.name, "os": asset.os} if asset else None,
    }, default=str)
    result = await ask_gpt4o_json(
        "You are an incident responder writing a remediation playbook for one incident. " + NO_GUESSING +
        " Where evidence is missing, add a step to collect it instead of assuming. Commands must suit the "
        "asset's OS and name only processes, files or addresses present in the data; use an empty string "
        'when no command applies. Return JSON: {"steps": [{"action": "...", "command": "...", '
        '"priority": "immediate|high|medium|low", "risk_level": "low|medium|high"}]} with 3-7 steps.',
        "INCIDENT RECORD (JSON):\n" + facts,
    )
    steps = [s for s in result.get("steps") or [] if isinstance(s, dict) and s.get("action")][:7]
    if not steps:
        raise HTTPException(status_code=502, detail="AI service returned no playbook steps")
    for n, s in enumerate(steps, 1):
        s["step"] = n
    return {
        "incident_id": incident_id,
        "steps": steps,
        "total_steps": len(steps),
        "model": "gpt-4o",
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }

@app.get("/api/threat-actors")
async def get_all_threat_actors(db: Session = Depends(db.get_db)):
    groups = db.query(models.MitreGroup).order_by(func.lower(models.MitreGroup.name)).all()
    # Only what the cards and search use; the detail route has the description and technique list
    return [{
        "id": group.id,
        "mitre_id": group.mitre_id,
        "name": group.name,
        "aliases": group.aliases,
        "technique_count": len(group.techniques or []),
    } for group in groups]

@app.get("/api/threat-actors/{group_id}")
async def get_threat_actor_detail(group_id: int, db: Session = Depends(db.get_db)):
    group = db.query(models.MitreGroup).filter(models.MitreGroup.id == group_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    techniques = [
        {"technique_id": t.technique_id, "name": t.name, "tactic": t.tactic}
        for t in db.query(models.MitreTechnique).order_by(models.MitreTechnique.technique_id).all()
        if group.mitre_id in (t.associated_groups or [])
    ]
    return {"group": group, "techniques": techniques}



# â”€â”€ AI ANALYST COPILOT â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

@app.post("/api/copilot/ask")
async def copilot_ask(request: Request, db: Session = Depends(db.get_db)):
    """
    AI Analyst Copilot â€” natural language Q&A on CVEs, alerts, IOCs.
    Uses OpenAI GPT-4o with live context pulled from the DB.
    """
    body = await request.json()
    question = (body.get("question") or "").strip()
    if not question:
        raise HTTPException(status_code=400, detail="question is required")

    # --- Build live context from DB ---
    context_parts = []

    # Top 10 CVEs by risk
    top_cves = (
        db.query(models.CVE)
        .order_by(models.CVE.risk_score.desc().nullslast())
        .limit(10)
        .all()
    )
    if top_cves:
        context_parts.append("TOP CVEs IN DATABASE:\n" + "\n".join(_cve_context_line(c) for c in top_cves))

    # Active incidents
    active_incidents = (
        db.query(models.Incident)
        .filter(models.Incident.status == "Active")
        .limit(5)
        .all()
    )
    if active_incidents:
        inc_lines = [
            f"  - [{i.severity}] {i.type}: {(i.details or '')[:100]}"
            for i in active_incidents
        ]
        context_parts.append("ACTIVE INCIDENTS:\n" + "\n".join(inc_lines))

    # OSINT alerts
    osint = (
        db.query(models.OSINTAlert)
        .order_by(models.OSINTAlert.created_at.desc())
        .limit(5)
        .all()
    )
    if osint:
        osint_lines = [
            f"  - [{o.severity}] {o.indicator} ({o.type}): {(o.description or '')[:100]}"
            for o in osint
        ]
        context_parts.append("RECENT OSINT ALERTS:\n" + "\n".join(osint_lines))

    # If question mentions a specific CVE, pull full detail
    import re
    cve_mentions = re.findall(r'CVE-\d{4}-\d+', question.upper())
    for cve_id in cve_mentions[:3]:
        cve = db.query(models.CVE).filter(models.CVE.cve_id == cve_id).first()
        if cve:
            context_parts.append(
                f"DETAIL FOR {cve_id}:\n"
                f"  Description: {cve.description or 'N/A'}\n"
                f"  CVSS: {cve.cvss_score} | EPSS: {round((cve.epss_score or 0)*100,1)}%\n"
                f"  KEV: {bool(cve.cisa_kev)} | Ransomware: {bool(cve.ransomware_use)}\n"
                f"  Actively Exploited: {bool(cve.actively_exploited)}\n"
                f"  AI Summary: {cve.ai_summary or 'Not yet generated'}"
            )

    # If question mentions an IP/hash/domain, pull OSINT
    ioc_pattern = re.findall(
        r'\b(?:\d{1,3}\.){3}\d{1,3}\b|'
        r'\b[a-fA-F0-9]{32,64}\b|'
        r'\b(?:[a-z0-9\-]+\.)+(?:com|net|org|io|ru|cn|ir|gov)\b',
        question
    )
    for ioc in ioc_pattern[:3]:
        alert = db.query(models.OSINTAlert).filter(
            models.OSINTAlert.indicator == ioc
        ).first()
        if alert:
            context_parts.append(
                f"IOC MATCH â€” {ioc}:\n"
                f"  Type: {alert.type} | Severity: {alert.severity}\n"
                f"  Source: {alert.source}\n"
                f"  Description: {alert.description or 'N/A'}"
            )

    # Threat actor stats
    total_cves = db.query(models.CVE).count()
    kev_count = db.query(models.CVE).filter(models.CVE.cisa_kev == True).count()
    incident_count = db.query(models.Incident).filter(models.Incident.status == "Active").count()

    context_parts.append(
        f"PLATFORM STATS:\n"
        f"  Total CVEs tracked: {total_cves}\n"
        f"  CISA KEV entries: {kev_count}\n"
        f"  Active incidents: {incident_count}"
    )

    context_block = "\n\n".join(context_parts)

    system_prompt = """You are ThreatLens AI, an expert cybersecurity analyst assistant embedded in a threat intelligence platform.

You have access to live data from the platform including CVEs, incidents, OSINT alerts, and threat actor mappings.

Your role:
- Answer questions about specific CVEs, IOCs, threat actors, and incidents using the provided context
- Assess exploitation likelihood and business impact clearly
- Give concise, actionable answers â€” not walls of text
- Flag if a CVE is on the CISA KEV list, actively exploited, or linked to ransomware groups
- Be direct: security teams need fast, clear answers

Format:
- Use short paragraphs or bullet points as appropriate
- Lead with the most important finding
- End with a concrete recommended action if relevant
- Keep responses under 300 words unless the question genuinely requires more detail

If you don't have enough data to answer confidently, say so clearly rather than speculating."""

    user_prompt = f"""LIVE PLATFORM CONTEXT:
{context_block}

ANALYST QUESTION:
{question}"""

    answer = await ask_gpt4o(system_prompt, user_prompt)
    return {
        "answer": answer,
        "context_used": len(context_parts),
        "cves_referenced": cve_mentions,
        "iocs_checked": ioc_pattern,
    }


# Country centroids for the attack map. OTX names countries in ISO style ("Korea, Republic of"),
# so COUNTRY_ALIASES maps those spellings onto these keys.
COUNTRY_COORDS = {
    "Argentina": (-38.42, -63.62), "Australia": (-25.27, 133.78), "Austria": (47.52, 14.55),
    "Bangladesh": (23.68, 90.36), "Belarus": (53.71, 27.95), "Belgium": (50.50, 4.47),
    "Brazil": (-14.24, -51.93), "Canada": (56.13, -106.35), "Chile": (-35.68, -71.54),
    "China": (35.86, 104.20), "Colombia": (4.57, -74.30), "Czechia": (49.82, 15.47),
    "Denmark": (56.26, 9.50), "Egypt": (26.82, 30.80), "Finland": (61.92, 25.75),
    "France": (46.23, 2.21), "Germany": (51.17, 10.45), "Greece": (39.07, 21.82),
    "Hong Kong": (22.32, 114.17), "Hungary": (47.16, 19.50), "India": (20.59, 78.96),
    "Indonesia": (-0.79, 113.92), "Iran": (32.43, 53.69), "Iraq": (33.22, 43.68),
    "Ireland": (53.41, -8.24), "Israel": (31.05, 34.85), "Italy": (41.87, 12.57),
    "Japan": (36.20, 138.25), "Jordan": (30.59, 36.24), "Kazakhstan": (48.02, 66.92),
    "Kenya": (-0.02, 37.91), "Kuwait": (29.31, 47.48), "Lebanon": (33.85, 35.86),
    "Malaysia": (4.21, 101.98), "Mexico": (23.63, -102.55), "Morocco": (31.79, -7.09),
    "Netherlands": (52.13, 5.29), "New Zealand": (-40.90, 174.89), "Nigeria": (9.08, 8.68),
    "North Korea": (40.34, 127.51), "Norway": (60.47, 8.47), "Pakistan": (30.38, 69.35),
    "Palestine": (31.95, 35.23), "Peru": (-9.19, -75.02), "Philippines": (12.88, 121.77),
    "Poland": (51.92, 19.15), "Portugal": (39.40, -8.22), "Qatar": (25.35, 51.18),
    "Romania": (45.94, 24.97), "Russia": (61.52, 105.32), "Saudi Arabia": (23.89, 45.08),
    "Singapore": (1.35, 103.82), "South Africa": (-30.56, 22.94), "South Korea": (35.91, 127.77),
    "Spain": (40.46, -3.75), "Sri Lanka": (7.87, 80.77), "Sweden": (60.13, 18.64),
    "Switzerland": (46.82, 8.23), "Syria": (34.80, 38.997), "Taiwan": (23.70, 120.96),
    "Thailand": (15.87, 100.99), "Turkey": (38.96, 35.24), "Ukraine": (48.38, 31.17),
    "United Arab Emirates": (23.42, 53.85), "United Kingdom": (55.38, -3.44),
    "United States": (37.09, -95.71), "Venezuela": (6.42, -66.59), "Vietnam": (14.06, 108.28),
}
COUNTRY_ALIASES = {
    "united states of america": "United States", "usa": "United States", "us": "United States",
    "united kingdom of great britain and northern ireland": "United Kingdom", "uk": "United Kingdom",
    "russian federation": "Russia", "korea, republic of": "South Korea", "republic of korea": "South Korea",
    "korea, democratic people's republic of": "North Korea", "iran, islamic republic of": "Iran",
    "viet nam": "Vietnam", "taiwan, province of china": "Taiwan", "syrian arab republic": "Syria",
    "czech republic": "Czechia", "turkiye": "Turkey", "türkiye": "Turkey",
    "palestine, state of": "Palestine", "venezuela, bolivarian republic of": "Venezuela",
}


def _map_country(name: str):
    """Canonical COUNTRY_COORDS key for an OTX country name, or None if it has no coordinates here."""
    name = (name or "").strip()
    if name in COUNTRY_COORDS:
        return name
    return COUNTRY_ALIASES.get(name.lower()) or next((k for k in COUNTRY_COORDS if k.lower() == name.lower()), None)


def _iso_utc(dt):
    """ISO time with an explicit UTC offset; SQLite hands back naive UTC, which browsers would read as local."""
    if dt is None:
        return None
    return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).isoformat()


@app.get("/api/attack-map")
async def get_attack_map(db: Session = Depends(db.get_db)):
    """Countries that OTX pulses list as targeted, with the adversaries and sectors those pulses name.

    Only published structured fields are used; nothing is inferred from text, and there is no
    composite threat score. Adversaries are linked to MITRE ATT&CK groups by exact name/alias.
    """
    from collections import defaultdict

    alias_to_group = {}
    for g in db.query(models.MitreGroup).all():
        for alias in [g.name] + (g.aliases or []):
            alias_to_group[alias.lower()] = g

    alerts = db.query(models.OSINTAlert).order_by(models.OSINTAlert.created_at.desc()).all()
    countries = defaultdict(lambda: {"alerts": [], "actors": {}, "sectors": defaultdict(int)})
    unmapped = set()
    alerts_with_countries = 0
    for alert in alerts:
        if alert.targeted_countries:
            alerts_with_countries += 1
        mapped = set()  # one count per alert, even if it spells a country two ways
        for raw_country in alert.targeted_countries or []:
            country = _map_country(raw_country)
            if country:
                mapped.add(country)
            else:
                unmapped.add(raw_country)
        for country in mapped:
            entry = countries[country]
            entry["alerts"].append({"indicator": alert.indicator, "severity": alert.severity, "source": alert.source})
            for sector in alert.industries or []:
                entry["sectors"][sector] += 1
            adversary = (alert.adversary or "").strip()
            if adversary:
                group = alias_to_group.get(adversary.lower())
                # one entry per actor however OTX spells it
                actor = entry["actors"].setdefault(group.mitre_id if group else adversary.lower(), {
                    "name": group.name if group else adversary,
                    "mitre_id": group.mitre_id if group else None,
                    "techniques": (group.techniques or [])[:8] if group else [],
                    "alert_count": 0,
                })
                actor["alert_count"] += 1

    nodes = []
    for country, entry in countries.items():
        lat, lng = COUNTRY_COORDS[country]
        nodes.append({
            "country": country,
            "lat": lat,
            "lng": lng,
            "alert_count": len(entry["alerts"]),
            "recent_alerts": entry["alerts"][:5],
            "sectors": [s for s, _ in sorted(entry["sectors"].items(), key=lambda kv: -kv[1])],
            "actors": sorted(entry["actors"].values(), key=lambda a: -a["alert_count"]),
        })
    nodes.sort(key=lambda n: -n["alert_count"])

    ticker = []
    for alert in alerts[:20]:
        tag = "[RED]" if alert.severity == "High" else "[ORANGE]" if alert.severity == "Medium" else "[WHITE]"
        ticker.append(f"{tag} {(alert.indicator or alert.description or '')[:120]}")

    # Your assets, at the exact spot the user placed them, with their open incidents
    severity_rank = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
    asset_pins = []
    for asset in db.query(models.Asset).filter(models.Asset.latitude.isnot(None)).all():
        open_incidents = db.query(models.Incident).filter(
            models.Incident.machine_id == asset.id, models.Incident.status != "Resolved"
        ).order_by(models.Incident.created_at.desc()).all()
        asset_pins.append({
            "id": asset.id, "name": asset.name, "os": asset.os, "ip_address": asset.ip_address,
            "status": asset.status, "last_seen": _iso_utc(asset.last_seen),
            "lat": asset.latitude, "lng": asset.longitude, "location_label": asset.location_label,
            "highest_severity": max((i.severity for i in open_incidents),
                                    key=lambda sev: severity_rank.get(sev, 0), default=None),
            "open_incidents": [{"id": i.id, "type": i.type, "severity": i.severity, "details": i.details,
                                "created_at": _iso_utc(i.created_at)} for i in open_incidents],
        })

    # Malicious IPs, placed approximately by GeoIP (attacker infrastructure, not targets)
    ip_areas = []
    seen_ips = set()
    sources = [(c.destination_ip, {"abuse_score": c.abuse_score, "machine": c.machine_hostname,
                                   "last_seen": _iso_utc(c.last_seen), "source": "Flagged connection",
                                   "detected_by": c.source, "reference": c.reference})
               for c in db.query(models.FlaggedConnection).all()]
    sources += [(a.indicator, {"abuse_score": None, "machine": None, "last_seen": _iso_utc(a.created_at),
                               "source": "IOC Hunter", "detected_by": None, "reference": None})
                for a in alerts if a.source == "IOC Hunter" and (a.type or "").upper() == "IP"]
    for ip, info in sources:
        if ip in seen_ips:
            continue
        seen_ips.add(ip)
        place = geoip.locate(ip)
        if place and place["accuracy_km"]:  # without MaxMind's radius there's no honest area to draw
            ip_areas.append({"ip": ip, **place, **info})

    return {
        "nodes": nodes,
        "asset_pins": asset_pins,
        "ip_areas": ip_areas,
        "geoip_configured": geoip.configured(),
        "unmapped_countries": sorted(unmapped),
        "ticker": ticker or ["[WHITE] No OSINT alerts yet"],
        "summary": {
            "targeted_countries": len(nodes),
            "named_actors": len({a["name"] for n in nodes for a in n["actors"]}),
            "osint_alerts": len(alerts),
            "alerts_with_countries": alerts_with_countries,
            "total_cves": db.query(models.CVE).count(),
            "kev_count": db.query(models.CisaKev).count(),
            "active_incidents": db.query(models.Incident).filter(models.Incident.status != "Resolved").count(),
        },
    }


# â”€â”€ IOC HUNTER â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

import re as _re

def _detect_ioc_type(value: str) -> str:
    """Classify a raw IOC string into: ip | hash | url | domain"""
    v = value.strip()
    # IP address
    if _re.match(r'^\d{1,3}(\.\d{1,3}){3}$', v):
        return "ip"
    # File hash â€” MD5 (32), SHA1 (40), SHA256 (64)
    if _re.match(r'^[a-fA-F0-9]{32}$', v) or \
       _re.match(r'^[a-fA-F0-9]{40}$', v) or \
       _re.match(r'^[a-fA-F0-9]{64}$', v):
        return "hash"
    # URL
    if v.startswith("http://") or v.startswith("https://"):
        return "url"
    # Domain (fallback)
    if _re.match(r'^([a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}$', v):
        return "domain"
    return "unknown"


@app.post("/api/ioc/lookup")
async def ioc_lookup(request: Request, db: Session = Depends(db.get_db)):
    """
    IOC Hunter â€” paste any IP, file hash, URL, or domain.
    Fans out to AbuseIPDB, VirusTotal, and local OSINT DB in parallel.
    Returns a unified threat report.
    """
    import asyncio
    import os
    from concurrent.futures import ThreadPoolExecutor
    from backend.services.abuseipdb import check_ip_reputation
    from backend.services.virustotal import check_file_hash, check_url_reputation

    body = await request.json()
    raw = (body.get("ioc") or "").strip()
    if not raw:
        raise HTTPException(status_code=400, detail="ioc field is required")

    ioc_type = _detect_ioc_type(raw)
    if ioc_type == "unknown":
        raise HTTPException(status_code=422, detail=f"Could not classify IOC: '{raw}'")

    results = {
        "ioc":      raw,
        "type":     ioc_type,
        "sources":  {},
        "verdict":  "Unknown",
        "risk":     "none",   # none | low | medium | high | critical
        "tags":     [],
    }

    # â”€â”€ 1. Local OSINT DB match â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    osint_match = db.query(models.OSINTAlert).filter(
        models.OSINTAlert.indicator.ilike(f"%{raw}%")
    ).first()
    if osint_match:
        results["sources"]["osint_db"] = {
            "found":       True,
            "source":      osint_match.source,
            "severity":    osint_match.severity,
            "description": osint_match.description,
            "type":        osint_match.type,
        }
        results["tags"].append("In local OSINT DB")
    else:
        results["sources"]["osint_db"] = {"found": False}

    # â”€â”€ 2. AbuseIPDB (IPs only) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if ioc_type == "ip":
        try:
            rep_ip = check_ip_reputation(raw, db_session=db)
            listed = rep_ip["source"] not in (None, "AbuseIPDB")
            results["sources"]["blocklist"] = (
                {"found": True, "list": rep_ip["source"], "network": rep_ip["network"], "reference": rep_ip["reference"]}
                if listed else {"found": False})
            if listed:
                results["tags"].append(f"Listed on {rep_ip['source']}")
            elif "error" in rep_ip:
                results["sources"]["abuseipdb"] = {"error": rep_ip["error"]}
            elif rep_ip["source"] == "AbuseIPDB":
                results["sources"]["abuseipdb"] = {
                    "score":        rep_ip["score"],
                    "is_malicious": rep_ip["is_malicious"],
                    "country":      rep_ip["country"],
                    "isp":          rep_ip["isp"],
                    "usage_type":   rep_ip["usage_type"],
                }
                if rep_ip["is_malicious"]:
                    results["tags"].append(f"AbuseIPDB score {rep_ip['score']}/100")
        except Exception as e:
            results["sources"]["abuseipdb"] = {"error": str(e)}

    # â”€â”€ 3. VirusTotal (hash or URL) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if ioc_type == "hash":
        try:
            vt = check_file_hash(raw)
            if vt and "error" not in vt:
                results["sources"]["virustotal"] = vt
                if vt.get("malicious", 0) > 0:
                    results["tags"].append(f"VT {vt['malicious']} engines flagged")
            elif vt:
                results["sources"]["virustotal"] = vt
            else:
                results["sources"]["virustotal"] = {"error": "No response"}
        except Exception as e:
            results["sources"]["virustotal"] = {"error": str(e)}

    elif ioc_type == "url":
        try:
            vt = check_url_reputation(raw)
            if vt and "error" not in vt:
                results["sources"]["virustotal"] = vt
                if vt.get("malicious", 0) > 0:
                    results["tags"].append(f"VT flagged as malicious")
            elif vt:
                results["sources"]["virustotal"] = vt
            else:
                results["sources"]["virustotal"] = {"error": "No response"}
        except Exception as e:
            results["sources"]["virustotal"] = {"error": str(e)}

    elif ioc_type == "domain":
        # Treat domain as a URL for VT lookup
        try:
            vt = check_url_reputation(f"http://{raw}")
            if vt and "error" not in vt:
                results["sources"]["virustotal"] = vt
                if vt.get("malicious", 0) > 0:
                    results["tags"].append("VT flagged domain")
            elif vt:
                results["sources"]["virustotal"] = vt
            else:
                results["sources"]["virustotal"] = {"error": "No response"}
        except Exception as e:
            results["sources"]["virustotal"] = {"error": str(e)}

    # â”€â”€ 4. Compute unified verdict â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    is_malicious = (
        results["sources"].get("blocklist", {}).get("found") or
        results["sources"].get("abuseipdb", {}).get("is_malicious") or
        results["sources"].get("virustotal", {}).get("verdict") == "Malicious" or
        results["sources"].get("virustotal", {}).get("malicious", 0) > 0
    )
    osint_hit = results["sources"].get("osint_db", {}).get("found")
    abuse_score = results["sources"].get("abuseipdb", {}).get("score", 0)

    if is_malicious and (abuse_score or 0) >= 75:
        results["verdict"] = "Malicious"
        results["risk"]    = "critical"
    elif is_malicious:
        results["verdict"] = "Malicious"
        results["risk"]    = "high"
    elif osint_hit:
        results["verdict"] = "Suspicious"
        results["risk"]    = "medium"
    elif abuse_score and abuse_score > 0:
        results["verdict"] = "Suspicious"
        results["risk"]    = "low"
    else:
        results["verdict"] = "Clean"
        results["risk"]    = "none"

    # â”€â”€ 5. Log as OSINT alert if malicious and not already stored â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if is_malicious and not osint_hit:
        try:
            new_alert = models.OSINTAlert(
                source="IOC Hunter",
                indicator=raw,
                type=ioc_type.upper(),
                description=f"Manual IOC lookup flagged as malicious. Tags: {', '.join(results['tags'])}",
                severity="High" if results["risk"] == "critical" else "Medium",
            )
            db.add(new_alert)
            db.commit()
            results["tags"].append("Logged to OSINT DB")
        except Exception as e:
            print(f"[IOC] Failed to log alert: {e}")

    return results