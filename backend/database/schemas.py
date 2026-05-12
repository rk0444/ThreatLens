from pydantic import BaseModel, ConfigDict
from datetime import datetime
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
    model_config = ConfigDict(from_attributes=True)


class AssetBase(BaseModel):
    name: str
    os: str
    software_list: List[str]
    ip_address: str
    status: str


class AssetCreate(AssetBase):
    pass


class AssetResponse(AssetBase):
    id: int
    last_seen: datetime
    model_config = ConfigDict(from_attributes=True)


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


class AnalystAction(BaseModel):
    action: str  # "approve" or "reject"
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
