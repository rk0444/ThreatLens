from sqlalchemy import String, Float, DateTime, JSON, Text, ForeignKey, func, Boolean, Integer
from sqlalchemy.orm import Mapped, mapped_column
from datetime import datetime
from typing import List, Optional
from .db import Base


class CVE(Base):
    __tablename__ = "cves"
    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    cve_id: Mapped[str] = mapped_column(String, unique=True, index=True)
    description: Mapped[str] = mapped_column(Text)
    cvss_score: Mapped[Optional[float]] = mapped_column(Float)
    epss_score: Mapped[Optional[float]] = mapped_column(Float)
    epss_percentile: Mapped[Optional[float]] = mapped_column(Float)
    published_date: Mapped[Optional[datetime]] = mapped_column(DateTime)
    affected_products: Mapped[Optional[List[str]]] = mapped_column(JSON)
    raw_json: Mapped[Optional[dict]] = mapped_column(JSON)
    asset_affected: Mapped[bool] = mapped_column(default=False)
    actively_exploited: Mapped[Optional[bool]] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class Asset(Base):
    __tablename__ = "assets"
    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String)
    os: Mapped[str] = mapped_column(String)
    software_list: Mapped[List[str]] = mapped_column(JSON)
    ip_address: Mapped[str] = mapped_column(String)
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    status: Mapped[str] = mapped_column(String)  # Online, Offline, Vulnerable


class Incident(Base):
    __tablename__ = "incidents"
    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    machine_id: Mapped[int] = mapped_column(ForeignKey("assets.id"))
    type: Mapped[str] = mapped_column(String)
    severity: Mapped[str] = mapped_column(String)
    process_name: Mapped[Optional[str]] = mapped_column(String)
    file_path: Mapped[Optional[str]] = mapped_column(String)
    network_connection: Mapped[Optional[str]] = mapped_column(String)
    details: Mapped[Optional[str]] = mapped_column(Text)
    sandbox_verdict: Mapped[Optional[str]] = mapped_column(String)
    virustotal_result: Mapped[Optional[dict]] = mapped_column(JSON)
    auto_response_action: Mapped[Optional[str]] = mapped_column(String)
    ai_summary: Mapped[Optional[str]] = mapped_column(Text)
    mitre_tags: Mapped[Optional[List[str]]] = mapped_column(JSON)
    timeline: Mapped[Optional[List[dict]]] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(String)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class ThreatActor(Base):
    __tablename__ = "threat_actors"
    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String, unique=True)
    associated_cves: Mapped[Optional[List[str]]] = mapped_column(JSON)
    campaigns: Mapped[Optional[List[dict]]] = mapped_column(JSON)


class OSINTAlert(Base):
    __tablename__ = "osint_alerts"
    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    source: Mapped[str] = mapped_column(String)
    indicator: Mapped[str] = mapped_column(String)
    type: Mapped[str] = mapped_column(String)
    description: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class MorningBrief(Base):
    __tablename__ = "morning_briefs"
    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    date: Mapped[datetime] = mapped_column(DateTime, unique=True)
    content: Mapped[str] = mapped_column(Text)
    top_threats: Mapped[List[dict]] = mapped_column(JSON)
    active_incidents: Mapped[List[dict]] = mapped_column(JSON)
    patterns: Mapped[str] = mapped_column(Text)
    actions: Mapped[List[dict]] = mapped_column(JSON)


class MitreGroup(Base):
    __tablename__ = "mitre_groups"
    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    mitre_id: Mapped[str] = mapped_column(String, unique=True, index=True)
    name: Mapped[str] = mapped_column(String)
    aliases: Mapped[Optional[List[str]]] = mapped_column(JSON)
    description: Mapped[Optional[str]] = mapped_column(Text)
    country: Mapped[Optional[str]] = mapped_column(String)
    motivation: Mapped[Optional[str]] = mapped_column(String)
    first_seen: Mapped[Optional[str]] = mapped_column(String)
    last_seen: Mapped[Optional[str]] = mapped_column(String)
    techniques: Mapped[Optional[List[str]]] = mapped_column(JSON)

class MitreTechnique(Base):
    __tablename__ = "mitre_techniques"
    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    technique_id: Mapped[str] = mapped_column(String, unique=True, index=True)
    name: Mapped[str] = mapped_column(String)
    description: Mapped[Optional[str]] = mapped_column(Text)
    tactic: Mapped[Optional[str]] = mapped_column(String)
    platforms: Mapped[Optional[List[str]]] = mapped_column(JSON)
    associated_groups: Mapped[Optional[List[str]]] = mapped_column(JSON)

class CveToGroup(Base):
    __tablename__ = "cve_to_groups"
    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    cve_id: Mapped[str] = mapped_column(String, index=True)
    group_name: Mapped[str] = mapped_column(String)
    group_mitre_id: Mapped[str] = mapped_column(String)
    technique_id: Mapped[Optional[str]] = mapped_column(String)
    technique_name: Mapped[Optional[str]] = mapped_column(String)
    confidence: Mapped[str] = mapped_column(String)
    source: Mapped[str] = mapped_column(String)

class CisaKev(Base):
    __tablename__ = "cisa_kev"
    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    cve_id: Mapped[str] = mapped_column(String, unique=True, index=True)
    vendor: Mapped[Optional[str]] = mapped_column(String)
    product: Mapped[Optional[str]] = mapped_column(String)
    vulnerability_name: Mapped[Optional[str]] = mapped_column(String)
    date_added: Mapped[Optional[str]] = mapped_column(String)
    required_action: Mapped[Optional[str]] = mapped_column(Text)
    due_date: Mapped[Optional[str]] = mapped_column(String)
    ransomware_use: Mapped[Optional[bool]] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

class SchedulerLog(Base):
    __tablename__ = "scheduler_logs"
    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    job_name: Mapped[str] = mapped_column(String)
    status: Mapped[str] = mapped_column(String) # Success, Failed
    error_message: Mapped[Optional[str]] = mapped_column(Text)
    ran_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

class FlaggedConnection(Base):
    __tablename__ = "flagged_connections"
    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    machine_id: Mapped[int] = mapped_column(Integer)
    machine_hostname: Mapped[str] = mapped_column(String)
    destination_ip: Mapped[str] = mapped_column(String)
    abuse_score: Mapped[int] = mapped_column(Integer)
    country: Mapped[Optional[str]] = mapped_column(String)
    isp: Mapped[Optional[str]] = mapped_column(String)
    times_seen: Mapped[int] = mapped_column(Integer, default=1)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    blocked: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

class Blocklist(Base):
    __tablename__ = "blocklist"
    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    ip_address: Mapped[str] = mapped_column(String, unique=True)
    reason: Mapped[Optional[str]] = mapped_column(String)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
