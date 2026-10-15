"""
CyberShield AI — REST API Pydantic Schemas

Defines request and response schemas for all CyberShield AI REST endpoints,
ensuring strict type validation, comprehensive API documentation, and
consistent serialization.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


# =====================================================================
# Health & Status Schemas
# =====================================================================

class HealthResponse(BaseModel):
    """System health check and runtime status response."""
    status: str = Field(..., description="Operational status: 'ok' or 'degraded'")
    service: str = Field(default="CyberShield AI", description="Service identity")
    database: str = Field(default="sqlite", description="Underlying database engine")
    version: str = Field(default="1.0.0", description="CyberShield AI API version")
    timestamp: str = Field(..., description="Current server UTC timestamp (ISO-8601)")

    model_config = ConfigDict(extra="ignore")


# =====================================================================
# Security Event Schemas
# =====================================================================

class SecurityEventSchema(BaseModel):
    """Normalized security telemetry event."""
    id: Optional[int] = Field(default=None, description="Database primary key identifier")
    timestamp: str = Field(..., description="ISO-8601 UTC timestamp")
    source_ip: str = Field(..., description="Source IPv4/IPv6 address")
    destination_ip: str = Field(default="10.0.0.1", description="Destination IP address")
    username: str = Field(..., description="User identity or subject")
    event_type: str = Field(..., description="Normalized event type (e.g., login, file_access)")
    status: str = Field(..., description="Normalized outcome (success, failed, denied, error)")
    resource: str = Field(default="/", description="Accessed target resource or endpoint")
    payload_size: int = Field(default=0, description="Transferred payload size in bytes")
    fingerprint: str = Field(default="", description="Unique event fingerprint")

    model_config = ConfigDict(from_attributes=True, extra="ignore")


class EventListResponse(BaseModel):
    """Paginated security events response."""
    total: int = Field(..., description="Total count matching query filters")
    count: int = Field(..., description="Number of events returned in this batch")
    limit: int = Field(..., description="Page limit applied")
    offset: int = Field(..., description="Page offset applied")
    events: List[SecurityEventSchema] = Field(..., description="List of security events")


# =====================================================================
# Alert & Incident Schemas
# =====================================================================

class AlertStatusUpdate(BaseModel):
    """Payload to update an alert's SOC triage status."""
    status: str = Field(..., description="New status: Open, Investigating, Resolved, or Dismissed")

    model_config = ConfigDict(extra="forbid")


class AlertResponse(BaseModel):
    """
    Standardized threat alert and correlated incident response.
    Maintains 100% backward compatibility with legacy frontend/MVP while
    exposing enriched explainability fields from Phases 03-05.
    """
    id: int = Field(..., description="Database alert primary key")
    alert_id: Optional[str] = Field(default=None, description="Canonical incident/alert ID (e.g. CS-ALERT-0001)")
    timestamp: str = Field(..., description="ISO-8601 UTC timestamp of trigger or latest event")
    source_ip: str = Field(..., description="Source IP address of affected subject")
    entity_type: str = Field(default="source_ip", description="Entity category: source_ip, username, composite")
    entity_value: str = Field(default="", description="Target entity value")
    category: str = Field(..., description="Incident category or primary triggered rule")
    severity: str = Field(..., description="Severity tier: Low, Medium, High, Critical")
    risk_score: int = Field(..., description="Composite risk score in [0, 100]")
    confidence: float = Field(default=0.8, description="Evidentiary confidence in [0.0, 1.0]")
    anomaly_score: Optional[float] = Field(default=None, description="ML anomaly score in [0.0, 1.0]")
    is_confirmed: bool = Field(default=False, description="Whether incident is corroborated beyond anomaly alone")
    description: str = Field(..., description="Human-readable executive summary")
    evidence: List[str] = Field(..., description="Supporting evidence bullet points")
    recommendation: str = Field(..., description="Actionable SOC investigation guidance")
    mitre_technique: str = Field(default="T1110", description="MITRE ATT&CK technique reference")
    status: str = Field(default="Open", description="SOC triage state: Open, Investigating, Resolved, Dismissed")
    fingerprint: str = Field(default="", description="Unique deduplication fingerprint")
    related_event_ids: List[str] = Field(default_factory=list, description="IDs/fingerprints of supporting events")

    model_config = ConfigDict(from_attributes=True, extra="ignore")


class AlertListResponse(BaseModel):
    """Paginated list of alerts and correlated incidents."""
    total: int = Field(..., description="Total alerts matching filter criteria")
    count: int = Field(..., description="Number of alerts returned in current page")
    limit: int = Field(..., description="Page limit applied")
    offset: int = Field(..., description="Page offset applied")
    alerts: List[AlertResponse] = Field(..., description="List of alert records")


# =====================================================================
# Dashboard Metrics Schemas
# =====================================================================

class EventTrendPoint(BaseModel):
    """Daily event count aggregate."""
    date: str = Field(..., description="Date formatted as YYYY-MM-DD")
    count: int = Field(..., description="Number of events recorded on this date")


class TopEntityStat(BaseModel):
    """Top entity ranking for dashboard widgets."""
    entity: str = Field(..., description="Entity identifier (IP or username)")
    count: int = Field(..., description="Number of associated alerts or events")


class DashboardStatsResponse(BaseModel):
    """Summary dashboard metrics for SOC monitoring overview."""
    processed_events: int = Field(..., description="Total security events in the system")
    total_alerts: int = Field(..., description="Total threat alerts generated")
    open_alerts: int = Field(..., description="Count of alerts currently in 'Open' status")
    high_critical_alerts: int = Field(..., description="Count of alerts with High or Critical severity")
    severity_distribution: Dict[str, int] = Field(..., description="Alert count breakdown by severity")
    status_distribution: Dict[str, int] = Field(default_factory=dict, description="Alert count breakdown by status")
    event_trend: List[EventTrendPoint] = Field(..., description="Recent daily event trends")
    ml_anomaly_count: int = Field(default=0, description="Total ML anomaly findings scored")
    top_source_ips: List[TopEntityStat] = Field(default_factory=list, description="Top source IPs by alert frequency")
    top_targeted_users: List[TopEntityStat] = Field(default_factory=list, description="Top targeted accounts")


# =====================================================================
# Ingestion & Detection Action Schemas
# =====================================================================

class RejectedRowSummary(BaseModel):
    """Diagnostic details for rows rejected during log ingestion."""
    line: int = Field(..., description="CSV line number (1-indexed header)")
    reason: str = Field(..., description="Validation failure explanation")


class UploadLogsResponse(BaseModel):
    """Response returned after processing an uploaded security log file."""
    success: bool = Field(default=True, description="Whether upload succeeded")
    message: str = Field(default="CSV processed", description="Operational outcome message")
    rows_received: int = Field(..., description="Total lines received in CSV payload")
    valid_rows: int = Field(..., description="Number of validated rows")
    new_events: int = Field(..., description="Number of newly inserted events")
    rejected_count: int = Field(default=0, description="Number of rejected rows")
    duplicate_count: int = Field(default=0, description="Number of duplicate rows suppressed")
    rejected_rows: List[RejectedRowSummary] = Field(default_factory=list, description="Sample of rejected rows")
    total_alerts: int = Field(..., description="Cumulative alerts present in database")
    detection_summary: Optional[Dict[str, Any]] = Field(default=None, description="Summary of detection run")


class DetectionRunResponse(BaseModel):
    """Outcome of an on-demand detection and correlation execution."""
    message: str = Field(default="Detection completed successfully")
    total_events_analyzed: int = Field(..., description="Total events evaluated")
    rule_alerts_generated: int = Field(..., description="Rule-based alerts triggered")
    anomalies_detected: int = Field(..., description="ML anomalies detected")
    incidents_created: int = Field(..., description="Correlated incidents created or updated")
    duration_ms: float = Field(..., description="Pipeline execution time in milliseconds")


# =====================================================================
# Error Response Schema
# =====================================================================

class ErrorDetail(BaseModel):
    """Standardized API error response format avoiding information leakage."""
    error: str = Field(..., description="Error category or summary code")
    detail: str = Field(..., description="Safe, client-friendly explanation")
    timestamp: str = Field(..., description="Error occurrence timestamp (ISO-8601)")
