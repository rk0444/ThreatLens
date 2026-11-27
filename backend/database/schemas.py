from pydantic import BaseModel, ConfigDict, Field, field_validator
from datetime import datetime, timezone
from typing import List, Optional


class CVEBase(BaseModel):
    cve_id: str
    description: str
    cvss_score: Optional[float] = None
    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None
    published_date: Optional[datetime] = None
    affected_products: Optional[List[str]] = None


class CVEResponse(CVEBase):
    id: int
    created_at: datetime
    actively_exploited: Optional[bool] = False
    # Risk formula inputs (frontend/src/utils/riskScore.js reads these)
    cisa_kev: Optional[bool] = False
    asset_affected: Optional[bool] = False
    affected_asset_count: Optional[int] = 0
    ransomware_use: Optional[bool] = False
    patch_available: Optional[bool] = None
    risk_score: Optional[float] = None
    risk_band: Optional[str] = None
    model_config = ConfigDict(from_attributes=True)

    @field_validator("published_date", "created_at")
    @classmethod
    def _as_utc(cls, v):
        # SQLite returns naive datetimes that are UTC; without an offset browsers read them as local time
        return v.replace(tzinfo=timezone.utc) if v is not None and v.tzinfo is None else v


class AssetBase(BaseModel):
    name: str
    os: str
    software_list: List[str]
    software_versions: Optional[dict] = None  # name -> installed version (agent inventory)
    ip_address: str
    status: Optional[str] = None  # ignored: online/offline comes from the agent's heartbeat (last_seen)
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    location_label: Optional[str] = None


class AssetInventory(BaseModel):
    """What the agent reads from the machine itself (OS, LAN address, installed programs and versions)."""
    os: str = Field(..., max_length=200)
    ip_address: str = Field(..., max_length=64)
    software_list: List[str] = Field(..., max_length=2000)
    software_versions: dict = Field(default_factory=dict)


class IOCLookup(BaseModel):
    ioc: str = Field(..., max_length=2048)


class IOCSave(BaseModel):
    ioc: str = Field(..., max_length=2048)
    summary: str = Field("", max_length=500)  # the lookup's findings, e.g. "VirusTotal: 56 engines flagged it"


class AssetLocation(BaseModel):
    """Where the user placed an asset; all null clears it."""
    latitude: Optional[float] = Field(None, ge=-90, le=90)
    longitude: Optional[float] = Field(None, ge=-180, le=180)
    location_label: Optional[str] = Field(None, max_length=200)


class AssetCreate(AssetBase):
    pass


class AssetResponse(AssetBase):
    id: int
    last_seen: datetime
    model_config = ConfigDict(from_attributes=True)

    @field_validator("last_seen")
    @classmethod
    def _as_utc(cls, v):
        return v.replace(tzinfo=timezone.utc) if v is not None and v.tzinfo is None else v


class IncidentBase(BaseModel):
    machine_id: int
    type: str
    severity: str
    process_name: Optional[str] = None
    file_path: Optional[str] = None
    network_connection: Optional[str] = None
    details: Optional[str] = None
    status: str
    timeline: Optional[List[dict]] = None


class IncidentCreate(IncidentBase):
    pass


class IncidentUpdate(BaseModel):
    status: Optional[str] = None
    auto_response_action: Optional[str] = None
    sandbox_verdict: Optional[str] = None
    virustotal_result: Optional[dict] = None
    ai_summary: Optional[str] = None
    mitre_tags: Optional[List[str]] = None
    timeline: Optional[List[dict]] = None


class IncidentResponse(IncidentBase):
    id: int
    sandbox_verdict: Optional[str] = None
    virustotal_result: Optional[dict] = None
    auto_response_action: Optional[str] = None
    ai_summary: Optional[str] = None
    mitre_tags: Optional[List[str]] = None
    timeline: Optional[List[dict]] = None
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)

    @field_validator("created_at")
    @classmethod
    def _as_utc(cls, v):
        # naive UTC from SQLite; add the offset so browsers don't read it as local time
        return v.replace(tzinfo=timezone.utc) if v is not None and v.tzinfo is None else v


class AnalystAction(BaseModel):
    action: str  # "resolve" or "investigate"
    analyst_note: Optional[str] = None


class OverviewResponse(BaseModel):
    total_cves_today: int
    active_incidents: int
    critical_count: int
    assets_monitored: int


class MorningBriefResponse(BaseModel):
    date: datetime
    content: str
    top_threats: List[dict]
    active_incidents: List[dict]
    patterns: str
    actions: List[dict]


class ChatQuery(BaseModel):
    query: str
