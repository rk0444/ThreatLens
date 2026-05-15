from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any, Union
from datetime import datetime
from enum import Enum


class ThreatType(str, Enum):
    CVE = "cve"
    INCIDENT = "incident"
    OSINT = "osint"


class SeverityLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class MITREStage(str, Enum):
    INITIAL_ACCESS = "Initial Access"
    EXECUTION = "Execution"
    PERSISTENCE = "Persistence"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    DEFENSE_EVASION = "Defense Evasion"
    CREDENTIAL_ACCESS = "Credential Access"
    DISCOVERY = "Discovery"
    LATERAL_MOVEMENT = "Lateral Movement"
    COLLECTION = "Collection"
    EXFILTRATION = "Exfiltration"
    COMMAND_AND_CONTROL = "Command and Control"
    IMPACT = "Impact"


class AssetContext(BaseModel):
    """Asset information relevant to the threat"""
    asset_id: Optional[int] = None
    asset_name: Optional[str] = None
    asset_ip: Optional[str] = None
    asset_os: Optional[str] = None
    software_list: Optional[List[str]] = None
    is_affected: bool = False
    vulnerability_count: int = 0


class CorrelationInfo(BaseModel):
    """Information about correlated threats"""
    correlated_threats: List[str] = []
    correlation_score: float = 0.0
    correlation_statement: Optional[str] = None
    related_cves: List[str] = []
    related_incidents: List[int] = []


class AnalystSummary(BaseModel):
    """AI-generated analyst summary"""
    what_is_affected: str
    how_it_works: str
    what_to_do_now: str
    confidence_score: float = Field(ge=0.0, le=1.0)
    generated_at: datetime = Field(default_factory=datetime.utcnow)


class ThreatSchema(BaseModel):
    """Standardized threat schema for AI processing"""
    
    # Core identification
    threat_id: str
    threat_type: ThreatType
    title: str
    description: str
    severity: SeverityLevel
    
    # Temporal information
    published_date: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    
    # CVE-specific fields
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    epss_score: Optional[float] = None
    affected_products: Optional[List[str]] = None
    actively_exploited: bool = False
    ransomware_use: bool = False
    patch_available: Optional[bool] = None
    
    # Incident-specific fields
    machine_id: Optional[int] = None
    machine_hostname: Optional[str] = None
    process_name: Optional[str] = None
    file_path: Optional[str] = None
    network_connection: Optional[str] = None
    sandbox_verdict: Optional[str] = None
    virustotal_result: Optional[Dict[str, Any]] = None
    
    # OSINT-specific fields
    source: Optional[str] = None
    indicator: Optional[str] = None
    indicator_type: Optional[str] = None
    
    # AI-generated content
    mitre_stage: Optional[MITREStage] = None
    mitre_tags: List[str] = []
    analyst_summary: Optional[AnalystSummary] = None
    
    # Context and correlations
    asset_context: Optional[AssetContext] = None
    correlation_info: Optional[CorrelationInfo] = None
    
    # Metadata
    raw_data: Optional[Dict[str, Any]] = None
    processing_status: str = "pending"  # pending, processing, completed, failed
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class ThreatProcessingResult(BaseModel):
    """Result of AI pipeline processing"""
    success: bool
    threat_id: str
    processing_time: float
    error_message: Optional[str] = None
    warnings: List[str] = []
    
    # Pipeline stage results
    hunter_result: Optional[Dict[str, Any]] = None
    correlator_result: Optional[Dict[str, Any]] = None
    context_result: Optional[Dict[str, Any]] = None
    analyst_result: Optional[Dict[str, Any]] = None


class RemediationStep(BaseModel):
    """Single step in incident remediation playbook"""
    step: int
    action: str
    command: Optional[str] = None
    priority: str  # immediate, high, medium, low
    estimated_time: Optional[str] = None
    risk_level: str  # low, medium, high, critical


class RemediationPlaybook(BaseModel):
    """AI-generated remediation playbook"""
    incident_id: int
    threat_id: str
    total_steps: int
    estimated_total_time: Optional[str] = None
    steps: List[RemediationStep]
    generated_at: datetime = Field(default_factory=datetime.utcnow)
    confidence_score: float = Field(ge=0.0, le=1.0)
