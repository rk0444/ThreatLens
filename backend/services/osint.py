import requests
import os
from sqlalchemy.orm import Session
from backend.database import models
from dotenv import load_dotenv

load_dotenv()

OTX_API_KEY = os.getenv("OTX_API_KEY")
OTX_API_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"

def fetch_osint_alerts(db_session: Session, websocket_manager=None):
    if not OTX_API_KEY:
        return

    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    
    try:
        response = requests.get(OTX_API_URL, headers=headers, timeout=15)
        if response.status_code == 200:
            data = response.json()
            pulses = data.get("results", [])
            
            for pulse in pulses:
                indicator = pulse.get("name")
                structured = {
                    "adversary": pulse.get("adversary") or None,
                    "targeted_countries": pulse.get("targeted_countries") or [],
                    "industries": pulse.get("industries") or [],
                }
                # Check if exists (refresh structured fields, which older rows lack)
                existing = db_session.query(models.OSINTAlert).filter(models.OSINTAlert.indicator == indicator).first()
                if existing:
                    for field, value in structured.items():
                        setattr(existing, field, value)
                    db_session.commit()
                    continue

                alert = models.OSINTAlert(
                    source="AlienVault OTX",
                    indicator=indicator,
                    type="Pulse",
                    description=pulse.get("description", ""),
                    severity="Medium", # Default
                    **structured,
                )
                db_session.add(alert)
                db_session.commit()
                
                # Push via WebSocket
                if websocket_manager:
                    import asyncio
                    import json
                    asyncio.run(websocket_manager.broadcast(json.dumps({
                        "type": "OSINT_ALERT",
                        "data": {
                            "indicator": indicator,
                            "description": pulse.get("description"),
                            "source": "AlienVault OTX"
                        }
                    })))
                    
    except Exception as e:
        print(f"Error fetching OSINT alerts: {e}")
