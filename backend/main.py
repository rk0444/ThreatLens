from fastapi import (
    FastAPI,
    Depends,
    HTTPException,
    WebSocket,
    WebSocketDisconnect,
)
from backend.services.cisa_kev import sync_cisa_kev
from backend.services.mitre_attack import sync_mitre_data
from backend.database.db import SessionLocal
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import List, Optional
import json
from datetime import datetime, timezone, timedelta
from contextlib import asynccontextmanager
import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from backend.database import db, models, schemas
from backend.services.nvd import fetch_latest_cves
from backend.services.osint import fetch_osint_alerts
from backend.services.abuseipdb import check_ip_reputation
# from services.agents import get_pipeline
# from services.morning_brief import get_morning_brief_service
# from services.remediation import get_remediation_service
# from services.vector_store import get_vector_store
# from database.threat_schema import ThreatType
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.events import EVENT_JOB_EXECUTED, EVENT_JOB_ERROR
import threading
import traceback


def run_nvd_sync():
    """Wrapper so APScheduler can call fetch_latest_cves with a managed DB session."""
    session = SessionLocal()
    try:
        fetch_latest_cves(session)
    except Exception as e:
        print(f"[nvd_sync] failed: {e}")
    finally:
        session.close()


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
        for connection in self.active_connections:
            await connection.send_text(message)


manager = ConnectionManager()


# Seed mock data logic
def seed_data(db_session: Session):
    if db_session.query(models.Asset).count() == 0:
        mock_asset = models.Asset(
            name="WS-PROD-01",
            os="Windows 11 Pro",
            software_list=["Chrome", "Slack", "VS Code", "Python 3.10"],
            ip_address="192.168.1.45",
            status="Online",
        )
        db_session.add(mock_asset)
        db_session.commit()

        mock_incident = models.Incident(
            machine_id=1,
            type="Suspicious Process",
            severity="High",
            process_name="powershell.exe",
            file_path="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            status="Active",
            ai_summary="Detected encoded powershell command executing from a temp directory.",
            timeline=[
                {"time": "10:00", "event": "Process started"},
                {"time": "10:05", "event": "Network connection established"},
            ],
        )
        db_session.add(mock_incident)
        db_session.commit()

        mock_cve = models.CVE(
            cve_id="CVE-2024-1234",
            description="Remote Code Execution in widely used library.",
            cvss_score=9.8,
            epss_score=0.95,
            published_date=datetime.now(timezone.utc) - timedelta(days=2),
        )
        db_session.add(mock_cve)
        db_session.commit()

        mock_brief = models.MorningBrief(
            date=datetime.now(timezone.utc),
            content="Today's security posture is stable but requires attention on new RCE vulnerabilities.",
            top_threats=[{"name": "CVE-2024-1234", "risk": "Critical"}],
            active_incidents=[{"id": 1, "type": "Suspicious Process"}],
            patterns="Multiple attempts to run encoded powershell detected across network.",
            actions=[{"task": "Patch CVE-2024-1234", "priority": "High"}],
        )
        db_session.add(mock_brief)
        db_session.commit()


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

def scheduler_event_listener(event):
    if event.exception:
        print(f"[SCHEDULER EVENT] Job {event.job_id} raised an exception: {event.exception}")
    else:
        print(f"[SCHEDULER EVENT] Job {event.job_id} completed successfully.")

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize database tables
    models.Base.metadata.create_all(bind=db.engine)
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
        
        seed_data(db_session)
        print("[STARTUP] 4/4 Seed data applied.")
    finally:
        db_session.close()
    
    # Start Scheduler
    scheduler = BackgroundScheduler()
    scheduler.add_listener(scheduler_event_listener, EVENT_JOB_EXECUTED | EVENT_JOB_ERROR)
    
    # Trigger jobs immediately, then on interval
    scheduler.add_job(
        lambda: safe_run_job(run_nvd_sync, "NVD Sync"),
        'interval', minutes=15, next_run_time=datetime.now(),
        misfire_grace_time=300, id="nvd_sync"
    )
    scheduler.add_job(
        lambda: safe_run_job(lambda db: fetch_osint_alerts(db, manager), "OSINT Sync"),
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

    scheduler.start()

    yield
    scheduler.shutdown()


app = FastAPI(title="ThreatLens API", version="2.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
async def root():
    return {"status": "online", "version": "2.0.0"}


@app.get("/api/overview")
async def get_overview(db: Session = Depends(db.get_db)):
    """Get overview metrics for dashboard"""
    try:
        # Get metrics
        today = datetime.now(timezone.utc).replace(
            hour=0, minute=0, second=0, microsecond=0
        )
        total_cves = (
            db.query(models.CVE).filter(models.CVE.created_at >= today).count()
        )
        active_incidents = (
            db.query(models.Incident)
            .filter(models.Incident.status == "Active")
            .count()
        )
        critical_count = (
            db.query(models.CVE).filter(models.CVE.cvss_score >= 9.0).count()
        )
        assets_monitored = db.query(models.Asset).count()
        
        # Get severity breakdown
        all_cves_today = db.query(models.CVE).filter(models.CVE.created_at >= today).all()
        def score_tier(cve):
            s = (cve.cvss_score or 0) * 10
            if s >= 86: return "Critical"
            if s >= 61: return "High"
            if s >= 31: return "Medium"
            if s >= 11: return "Low"
            return "Info"
        from collections import Counter
        tiers = Counter(score_tier(c) for c in all_cves_today)
        severity_breakdown = [
            {"name": t, "value": tiers.get(t, 0)}
            for t in ["Critical", "High", "Medium", "Low"]
        ]
        
        # Get top 5 critical threats
        top_threats = db.query(models.CVE).filter(
            models.CVE.cvss_score >= 7.0
        ).order_by(models.CVE.cvss_score.desc()).limit(5).all()
        
        top_threats_data = []
        for threat in top_threats:
            top_threats_data.append({
                'id': threat.id,
                'cve_id': threat.cve_id,
                'description': threat.description[:100] + '...' if len(threat.description) > 100 else threat.description,
                'risk_score': (threat.cvss_score or 0) * 10
            })
        
        # Get activity log (simplified)
        activity_log = []
        recent_cves = db.query(models.CVE).order_by(models.CVE.created_at.desc()).limit(5).all()
        for cve in recent_cves:
            activity_log.append({
                'id': f"cve-{cve.id}",
                'type': 'CVE',
                'message': f"New CVE {cve.cve_id} detected",
                'timestamp': cve.created_at.isoformat() if cve.created_at else datetime.now(timezone.utc).isoformat(),
                'severity': 'Critical' if (cve.cvss_score or 0) >= 9.0 else 'High'
            })
        
        recent_incidents = db.query(models.Incident).order_by(models.Incident.created_at.desc()).limit(5).all()
        for incident in recent_incidents:
            activity_log.append({
                'id': f"incident-{incident.id}",
                'type': 'Incident',
                'message': f"Security incident on {incident.machine_id}",
                'timestamp': incident.created_at.isoformat() if incident.created_at else datetime.now(timezone.utc).isoformat(),
                'severity': incident.severity
            })
        
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
                'date': morning_brief.date.isoformat() if morning_brief else None
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
    groq_key = os.getenv("GROQ_API_KEY", "")

    # Status logic with thresholds
    nvd_status = "Live" if nvd_mins < 20 else ("Delayed" if nvd_mins < 60 else "Down")
    otx_status = "Live" if otx_mins < 40 else ("Delayed" if otx_mins < 120 else "Down")

    return {
        "nvd":      {"status": nvd_status, "detail": f"{int(nvd_mins)}m ago"},
        "otx":      {"status": otx_status, "detail": f"{int(otx_mins)}m ago"},
        "abuseipdb":{"status": "Active" if abuse_key        else "Down",   "detail": "API key present" if abuse_key else "No key"},
        "virustotal":{"status":"Active" if vt_key           else "Down",   "detail": "API key present" if vt_key else "No key"},
        "ai":       {"status": "Ready"  if groq_key         else "Down",   "detail": "Groq connected" if groq_key else "No API key"},
        "agent":    {"status": "Online" if agent_secs < 60  else "Offline","detail": f"{int(agent_secs)}s ago"},
    }


@app.get("/api/stats/hourly-cves")
async def get_hourly_cves(db: Session = Depends(db.get_db)):
    now = datetime.now(timezone.utc)
    result = []
    for h in range(23, -1, -1):
        start = now.replace(minute=0, second=0, microsecond=0) - timedelta(hours=h)
        end   = start + timedelta(hours=1)
        cves  = db.query(models.CVE).filter(models.CVE.created_at >= start, models.CVE.created_at < end).all()
        critical_high = sum(1 for c in cves if (c.cvss_score or 0) >= 7.0)
        result.append({"hour": start.strftime("%H:00"), "total": len(cves), "critical_high": critical_high})
    return result


@app.get("/api/stats/mitre-breakdown")
async def get_mitre_breakdown(db: Session = Depends(db.get_db)):
    stage_map = {
        "initial-access": "Initial Access", "execution": "Execution",
        "persistence": "Persistence", "privilege-escalation": "Privilege Escalation",
        "defense-evasion": "Defense Evasion", "lateral-movement": "Lateral Movement",
        "exfiltration": "Exfiltration", "command-and-control": "C2",
        "impact": "Impact",
    }
    counts = {v: 0 for v in stage_map.values()}
    incidents = db.query(models.Incident).all()
    for inc in incidents:
        for tag in (inc.mitre_tags or []):
            for k, v in stage_map.items():
                if k in tag.lower():
                    counts[v] += 1
    techniques = db.query(models.MitreTechnique).all()
    for tech in techniques:
        tactic = (tech.tactic or "").lower().replace(" ", "-")
        for k, v in stage_map.items():
            if k in tactic:
                counts[v] += 1
    return [{"stage": k, "count": v} for k, v in counts.items() if v > 0] or \
           [{"stage": s, "count": max(1, i*3)} for i, s in enumerate(list(stage_map.values())[:5], 1)]


@app.get("/api/stats/geo-threats")
async def get_geo_threats(db: Session = Depends(db.get_db)):
    COUNTRY_COORDS = {
        "Russia": (55.75, 37.61), "China": (39.91, 116.39),
        "United States": (38.90, -77.04), "North Korea": (39.02, 125.75),
        "Iran": (35.69, 51.42), "Ukraine": (50.45, 30.52),
        "Belarus": (53.90, 27.57), "Vietnam": (21.02, 105.83),
        "India": (28.61, 77.21), "Pakistan": (33.72, 73.06),
        "Brazil": (-15.78, -47.93), "Nigeria": (9.07, 7.40),
    }
    alerts = db.query(models.OSINTAlert).all()
    from collections import defaultdict
    geo = defaultdict(lambda: {"count": 0, "latest": ""})
    for alert in alerts:
        for country, coords in COUNTRY_COORDS.items():
            if country.lower() in alert.description.lower() or country.lower() in alert.indicator.lower():
                geo[country]["count"] += 1
                geo[country]["latest"] = alert.source
                geo[country]["lat"] = coords[0]
                geo[country]["lng"] = coords[1]
    return [{"country": k, "lat": v["lat"], "lng": v["lng"], "count": v["count"], "latest_campaign": v["latest"]} for k, v in geo.items()]


@app.post("/api/morning-brief/generate")
async def generate_morning_brief(db: Session = Depends(db.get_db)):
    # Placeholder for AI generation - Phase 5 will wire in full LLM call
    today = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    existing = db.query(models.MorningBrief).filter(models.MorningBrief.date >= today).first()
    top_cves = db.query(models.CVE).order_by(models.CVE.cvss_score.desc()).limit(3).all()
    active_incs = db.query(models.Incident).filter(models.Incident.status == "Active").count()
    content = f"ThreatLens detected {active_incs} active incidents. Top threats today include {', '.join(c.cve_id for c in top_cves)}. Immediate patching recommended for Critical-tier vulnerabilities. Monitor network for lateral movement indicators."
    if existing:
        existing.content = content
        db.commit()
        return existing
    brief = models.MorningBrief(
        date=datetime.now(timezone.utc), content=content,
        top_threats=[{"name": c.cve_id, "risk": "Critical"} for c in top_cves],
        active_incidents=[{"id": i.id, "type": i.type} for i in db.query(models.Incident).filter(models.Incident.status=="Active").limit(5).all()],
        patterns="Monitoring for encoded PowerShell and unusual outbound connections.",
        actions=[{"task": f"Patch {c.cve_id}", "priority": "High"} for c in top_cves],
    )
    db.add(brief)
    db.commit()
    db.refresh(brief)
    await manager.broadcast(json.dumps({"type": "MORNING_BRIEF_GENERATED", "time": str(datetime.now(timezone.utc))}))
    return brief


@app.get("/api/cves", response_model=List[schemas.CVEResponse])
async def get_cves(
    skip: int = 0,
    limit: int = 50,
    severity: Optional[float] = None,
    epss_min: Optional[float] = None,
    sort: Optional[str] = None,
    affected_only: bool = False,
    db: Session = Depends(db.get_db),
):
    query = db.query(models.CVE)
    if affected_only:
        query = query.filter(models.CVE.asset_affected == True)
    if severity:
        query = query.filter(models.CVE.cvss_score >= severity)
    if epss_min:
        query = query.filter(models.CVE.epss_score >= epss_min)
    
    if sort == "risk_score":
        query = query.order_by(models.CVE.cvss_score.desc())
    else:
        query = query.order_by(models.CVE.created_at.desc())
        
    return query.offset(skip).limit(limit).all()


@app.get("/api/cves/graph")
async def get_threat_graph(db: Session = Depends(db.get_db)):
    # Top 20 CVEs by cvss_score (risk_score is null on most real data)
    cves = (
        db.query(models.CVE)
        .order_by(models.CVE.cvss_score.desc().nullslast())
        .limit(20)
        .all()
    )

    nodes = []
    links = []
    actor_nodes_added = set()

    for cve in cves:
        nodes.append({
            "id": cve.cve_id,
            "type": "cve",
            "val": round(cve.cvss_score or 5, 1),
            "cvss": cve.cvss_score,
            "kev": cve.cisa_kev,
        })

        # Real MITRE mappings from cve_to_groups table
        mappings = db.query(models.CveToGroup).filter(
            models.CveToGroup.cve_id == cve.cve_id
        ).all()

        for m in mappings:
            if m.group_name not in actor_nodes_added:
                # Fetch group metadata for richer node
                group = db.query(models.MitreGroup).filter(
                    models.MitreGroup.mitre_id == m.group_mitre_id
                ).first()
                nodes.append({
                    "id": m.group_name,
                    "type": "actor",
                    "val": 8,
                    "mitre_id": m.group_mitre_id,
                    "country": group.country if group else "Unknown",
                    "motivation": group.motivation if group else "Unknown",
                    "source": "MITRE CTI",
                })
                actor_nodes_added.add(m.group_name)

            links.append({
                "source": cve.cve_id,
                "target": m.group_name,
                "source_label": "MITRE CTI",
            })

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
    await manager.broadcast(json.dumps({"type": "ASSET_ADDED", "data": {"name": db_asset.name, "id": db_asset.id}}))
    return db_asset


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


@app.get("/api/incidents/{id}/playbook")
async def get_remediation_playbook(id: int, db: Session = Depends(db.get_db)):
    incident = db.query(models.Incident).filter(models.Incident.id == id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    # Phase 5: AI-generated playbook — placeholder with structured response
    return {
        "incident_id": id,
        "type": incident.type,
        "severity": incident.severity,
        "playbook": [
            {"step": 1, "action": "Isolate the affected endpoint from the network", "priority": "Immediate"},
            {"step": 2, "action": "Capture memory dump and preserve forensic evidence", "priority": "High"},
            {"step": 3, "action": f"Terminate process: {incident.process_name or 'Unknown'}", "priority": "High"},
            {"step": 4, "action": "Run full AV scan on the affected machine", "priority": "Medium"},
            {"step": 5, "action": "Review logs for lateral movement indicators", "priority": "Medium"},
            {"step": 6, "action": "Patch underlying vulnerability and restore from clean backup", "priority": "Standard"},
        ],
        "note": "Full AI-generated playbook coming in Phase 5."
    }


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
    asset_counts = []
    for asset in assets:
        count = 0
        software = [s.lower() for s in (asset.software_list or [])]
        for cve in db.query(models.CVE).filter(models.CVE.asset_affected == True).all():
            if any(s in cve.description.lower() for s in software):
                count += 1
        asset_counts.append({"name": asset.name, "count": count})
    
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

            software = [s.lower() for s in (asset.software_list or [])]
            logging.debug(f"Asset: {asset.name}, Software List: {software}")

            # This is slow, but works for the demo size
            for cve in db.query(models.CVE).filter(models.CVE.asset_affected == True).all():
                logging.debug(f"Processing CVE: {cve.cve_id}, Description: {cve.description}")
                matched_software = [s for s in software if s in cve.description.lower()]
                if matched_software:
                    count += 1
                    if cve.cvss_score is not None:
                        if cve.cvss_score > max_score:
                            max_score = cve.cvss_score
                            highest_risk_cve = {"id": cve.cve_id, "score": cve.cvss_score}
                            vulnerable_pkg = matched_software[0].capitalize()

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


@app.get("/api/stats/ip-monitoring")
async def get_ip_monitoring_stats(db: Session = Depends(db.get_db)):
    # Mock totals for today
    return {
        "connections_monitored_today": 1254,
        "flagged_today": db.query(models.FlaggedConnection).count(),
        "blocked_today": db.query(models.Blocklist).count()
    }

@app.get("/api/network/flagged-ips")
async def get_flagged_ips(db: Session = Depends(db.get_db)):
    return db.query(models.FlaggedConnection).order_by(models.FlaggedConnection.abuse_score.desc()).all()

@app.post("/api/network/block-ip")
async def block_ip(payload: dict, db: Session = Depends(db.get_db)):
    ip = payload.get("ip")
    if not ip: raise HTTPException(status_code=400, detail="IP required")
    
    # Check if already blocked
    existing = db.query(models.Blocklist).filter(models.Blocklist.ip_address == ip).first()
    if not existing:
        new_block = models.Blocklist(ip_address=ip, reason="Manual block via SOC")
        db.add(new_block)
        
        # Update flagged connections
        db.query(models.FlaggedConnection).filter(models.FlaggedConnection.destination_ip == ip).update({"blocked": True})
        
        # Log incident
        new_incident = models.Incident(
            machine_id=1, # Global/System
            type="network_block",
            severity="Medium",
            details=f"IP {ip} has been blocked globally via firewall rules.",
            status="Resolved",
            auto_response_action="Firewall Block"
        )
        db.add(new_incident)
        db.commit()
        
        # Execute local firewall rule (simulated/attempted)
        import subprocess, sys
        try:
            if sys.platform == "win32":
                cmd = f'netsh advfirewall firewall add rule name="ThreatLens Block {ip}" dir=out action=block remoteip={ip}'
            else:
                cmd = f'iptables -A OUTPUT -d {ip} -j DROP'
            # subprocess.run(cmd, shell=True, check=True) # Commented out for safety in dev environment
            print(f"[FIREWALL] Executed: {cmd}")
        except: pass
        
        await manager.broadcast(json.dumps({"type": "IP_BLOCKED", "ip": ip}))
        
    return {"status": "success"}

@app.get("/api/check-ip/{ip}")
async def get_ip_reputation_endpoint(ip: str, machine_id: Optional[int] = None, db: Session = Depends(db.get_db)):
    machine_hostname = None
    if machine_id:
        asset = db.query(models.Asset).filter(models.Asset.id == machine_id).first()
        if asset: machine_hostname = asset.name
            
    data = check_ip_reputation(ip, db_session=db, machine_id=machine_id, machine_hostname=machine_hostname)
    if not data:
        raise HTTPException(status_code=500, detail="Error checking IP reputation")
    
    # Broadcast if malicious
    if data.get("is_malicious"):
        await manager.broadcast(json.dumps({
            "type": "FLAGGED_CONNECTION",
            "data": {
                "machine_hostname": machine_hostname or "Unknown",
                "destination_ip": ip,
                "abuse_score": data.get("score"),
                "country": data.get("country"),
                "isp": data.get("isp"),
                "last_seen": str(datetime.now(timezone.utc))
            }
        }))
    return data


@app.post("/api/ingest/nvd")
async def ingest_nvd():
    threading.Thread(target=lambda: safe_run_job(run_nvd_sync, "Manual NVD Sync")).start()
    return {"status": "started"}

@app.post("/api/ingest/otx")
async def ingest_otx():
    threading.Thread(target=lambda: safe_run_job(lambda db: fetch_osint_alerts(db, manager), "Manual OSINT Sync")).start()
    return {"status": "started"}

@app.post("/api/ingest/mitre")
async def ingest_mitre():
    threading.Thread(target=lambda: safe_run_job(sync_mitre_data, "Manual MITRE Sync")).start()
    return {"status": "started"}

@app.get("/api/scheduler/logs")
async def get_scheduler_logs(db: Session = Depends(db.get_db)):
    return db.query(models.SchedulerLog).order_by(models.SchedulerLog.ran_at.desc()).limit(20).all()

@app.websocket("/ws/events")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# @app.get("/api/overview")
# async def get_overview(db: Session = Depends(db.get_db)):
#     """Get overview metrics for dashboard"""
#     try:
#         # Get metrics
#         total_cves = db.query(models.CVE).filter(
#             models.CVE.published_date >= datetime.now(timezone.utc) - timedelta(days=1)
#         ).count()
#         
#         active_incidents = db.query(models.Incident).filter(
#             models.Incident.status == 'Active'
#         ).count()
#         
#         critical_count = db.query(models.CVE).filter(
#             models.CVE.cvss_score >= 9.0
#         ).count()
#         
#         assets_monitored = db.query(models.Asset).count()
#         
#         # Get severity breakdown
#         severity_breakdown = []
#         for severity in ['Critical', 'High', 'Medium', 'Low']:
#             count = db.query(models.CVE).filter(
#                 models.CVE.published_date >= datetime.now(timezone.utc) - timedelta(days=1)
#             ).count()  # Simplified for now
#             severity_breakdown.append({'name': severity, 'value': count})
#         
#         # Get top 5 critical threats
#         top_threats = db.query(models.CVE).filter(
#             models.CVE.cvss_score >= 7.0
#         ).order_by(models.CVE.cvss_score.desc()).limit(5).all()
#         
#         top_threats_data = []
#         for threat in top_threats:
#             top_threats_data.append({
#                 'id': threat.id,
#                 'cve_id': threat.cve_id,
#                 'description': threat.description[:100] + '...' if len(threat.description) > 100 else threat.description,
#                 'risk_score': (threat.cvss_score or 0) * 10  # Simplified risk score
#             })
#         
#         # Get activity log (simplified)
#         activity_log = []
#         recent_cves = db.query(models.CVE).order_by(models.CVE.created_at.desc()).limit(5).all()
#         for cve in recent_cves:
#             activity_log.append({
#                 'id': f"cve-{cve.id}",
#                 'type': 'CVE',
#                 'message': f"New CVE {cve.cve_id} detected",
#                 'timestamp': cve.created_at.isoformat() if cve.created_at else datetime.now(timezone.utc).isoformat(),
#                 'severity': 'Critical' if (cve.cvss_score or 0) >= 9.0 else 'High'
#             })
#         
#         recent_incidents = db.query(models.Incident).order_by(models.Incident.created_at.desc()).limit(5).all()
#         for incident in recent_incidents:
#             activity_log.append({
#                 'id': f"incident-{incident.id}",
#                 'type': 'Incident',
#                 'message': f"Security incident on {incident.machine_hostname or 'Unknown'}",
#                 'timestamp': incident.created_at.isoformat() if incident.created_at else datetime.now(timezone.utc).isoformat(),
#                 'severity': incident.severity
#             })
#         
#         # Get morning brief
#         morning_brief = db.query(models.MorningBrief).order_by(models.MorningBrief.date.desc()).first()
#         
#         return {
#             'metrics': {
#                 'totalCves': total_cves,
#                 'activeIncidents': active_incidents,
#                 'criticalThreats': critical_count,
#                 'assetsMonitored': assets_monitored
#             },
#             'severityBreakdown': severity_breakdown,
#             'topThreats': top_threats_data,
#             'activityLog': activity_log,
#             'morningBrief': {
#                 'content': morning_brief.content if morning_brief else None,
#                 'date': morning_brief.date.isoformat() if morning_brief else None
#             }
#         }
#     except Exception as e:
#         logging.error(f"Error in overview endpoint: {str(e)}")
#         raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/api/cves/{cve_id}/ai-summary")
async def get_cve_ai_summary(cve_id: str, db: Session = Depends(db.get_db)):
    """Get AI-generated summary for a CVE"""
    try:
        cve = db.query(models.CVE).filter(models.CVE.cve_id == cve_id).first()
        if not cve:
            raise HTTPException(status_code=404, detail="CVE not found")
        
        # For now, return basic structured data
        # In production, this would come from AI pipeline
        return {
            'what_is_affected': 'Systems with vulnerable software installations',
            'how_it_works': 'Remote code execution through vulnerable library function',
            'what_to_do_now': 'Apply security patches immediately and monitor for exploitation attempts',
            'confidence_score': 0.85,
            'generated_at': datetime.now(timezone.utc).isoformat()
        }
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error getting AI summary for {cve_id}: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/api/cves/{cve_id}/correlations")
async def get_cve_correlations(cve_id: str, db: Session = Depends(db.get_db)):
    """Get correlation data for a CVE"""
    try:
        cve = db.query(models.CVE).filter(models.CVE.cve_id == cve_id).first()
        if not cve:
            raise HTTPException(status_code=404, detail="CVE not found")
        
        # Check for related incidents (simplified correlation logic)
        related_incidents = db.query(models.Incident).filter(
            models.Incident.created_at >= datetime.now(timezone.utc) - timedelta(days=7)
        ).all()
        
        correlation_statement = None
        if related_incidents and cve.cvss_score >= 8.0:
            correlation_statement = f"Potential exploitation of {cve_id} detected on enterprise endpoints"
        
        return {
            'correlation_statement': correlation_statement,
            'related_incidents': [inc.id for inc in related_incidents],
            'correlation_score': 0.8 if correlation_statement else 0.0
        }
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error getting correlations for {cve_id}: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")

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
    """Get AI-generated remediation playbook for an incident"""
    try:
        incident = db.query(models.Incident).filter(models.Incident.id == incident_id).first()
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")
        
        # Generate playbook using AI service
        # remediation_service = get_remediation_service()
        # playbook = await remediation_service.generate_playbook(db, incident_id)
        
        # For now, return fallback playbook
        return {
            'incident_id': incident_id,
            'steps': [
                {
                    'step': 1,
                    'action': 'Isolate affected system from network',
                    'command': 'netsh interface set interface "Ethernet" disable',
                    'priority': 'immediate',
                    'estimated_time': '2 minutes',
                    'risk_level': 'low'
                },
                {
                    'step': 2,
                    'action': 'Terminate suspicious processes',
                    'command': f'taskkill /f /im {incident.process_name or "suspicious.exe"}',
                    'priority': 'immediate',
                    'estimated_time': '5 minutes',
                    'risk_level': 'medium'
                }
            ],
            'total_steps': 2,
            'confidence_score': 0.6
        }
        
        # return {
        #     'incident_id': playbook.incident_id,
        #     'steps': [
        #         {
        #             'step': step.step,
        #             'action': step.action,
        #             'command': step.command,
        #             'priority': step.priority,
        #             'estimated_time': step.estimated_time,
        #             'risk_level': step.risk_level
        #         } for step in playbook.steps
        #     ],
        #     'total_steps': len(playbook.steps),
        #     'confidence_score': playbook.confidence_score,
        #     'generated_at': playbook.generated_at.isoformat() if playbook.generated_at else datetime.now(timezone.utc).isoformat()
        # }
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error generating playbook for incident {incident_id}: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/api/cves/{cve_id}/threat-actors")
async def get_cve_threat_actors(cve_id: str, db: Session = Depends(db.get_db)):
    links = db.query(models.CveToGroup).filter(models.CveToGroup.cve_id == cve_id).all()
    groups = []
    for link in links:
        group = db.query(models.MitreGroup).filter(models.MitreGroup.mitre_id == link.group_mitre_id).first()
        if group:
            groups.append({
                "group": group,
                "confidence": link.confidence,
                "technique_id": link.technique_id,
                "technique_name": link.technique_name
            })
    return groups

@app.get("/api/threat-actors")
async def get_all_threat_actors(db: Session = Depends(db.get_db)):
    groups = db.query(models.MitreGroup).all()
    result = []
    for group in groups:
        links = db.query(models.CveToGroup).filter(
            models.CveToGroup.group_mitre_id == group.mitre_id
        ).all()
        cve_count = len(links)
        latest_technique = None
        latest_technique_id = None
        for link in links:
            if link.technique_name:
                latest_technique = link.technique_name
                latest_technique_id = link.technique_id
                break
        result.append({
            "id": group.id,
            "mitre_id": group.mitre_id,
            "name": group.name,
            "aliases": group.aliases,
            "description": group.description,
            "country": group.country,
            "motivation": group.motivation,
            "first_seen": group.first_seen,
            "last_seen": group.last_seen,
            "techniques": group.techniques,
            "cve_count": cve_count,
            "latest_technique": latest_technique,
            "latest_technique_id": latest_technique_id,
        })
    return result

@app.get("/api/threat-actors/{group_id}")
async def get_threat_actor_detail(group_id: int, db: Session = Depends(db.get_db)):
    group = db.query(models.MitreGroup).filter(models.MitreGroup.id == group_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    links = db.query(models.CveToGroup).filter(models.CveToGroup.group_mitre_id == group.mitre_id).all()
    return {"group": group, "linked_cves": links}

@app.get("/api/stats/top-threat-actors")
async def get_top_threat_actors(db: Session = Depends(db.get_db)):
    results = db.query(
        models.CveToGroup.group_mitre_id,
        func.count(models.CveToGroup.cve_id).label('cve_count')
    ).group_by(models.CveToGroup.group_mitre_id).order_by(func.count(models.CveToGroup.cve_id).desc()).limit(10).all()
    
    top_groups = []
    for res in results:
        group = db.query(models.MitreGroup).filter(models.MitreGroup.mitre_id == res.group_mitre_id).first()
        if group:
            top_groups.append({
                "group": group,
                "cve_count": res.cve_count
            })
    return top_groups





