"""
CyberShield AI — Threat Risk Assessment & Incident Correlation Models

Defines the data structures, severity classifications, and risk breakdown
models produced by the CyberShield Threat Risk Assessment Engine.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class RiskSeverity(str, Enum):
    """Standard 4-tier severity levels."""
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class ConfidenceLevel(str, Enum):
    """Evidentiary confidence levels."""
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"


@dataclass
class RiskFactor:
    """
    Transparent explanatory component contributing to the composite risk score.

    Attributes:
        factor_name: Name of the evaluation criterion.
        weight: Relative weight or points attributed.
        observed_evidence: Concrete observation triggering this factor.
        score_delta: Numerical points added to the composite score.
        explanation: Human-readable rationale for this risk adjustment.
    """
    factor_name: str
    weight: float
    observed_evidence: str
    score_delta: int
    explanation: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CorrelatedIncident:
    """
    Correlated security incident combining rule detections, ML anomalies,
    and asset context into an explainable, prioritized finding.

    Attributes:
        incident_id: Unique sequential identifier (e.g. 'CS-INCIDENT-0001').
        title: Descriptive summary title.
        entity_type: Primary subject type ('username', 'source_ip', 'composite').
        entity_value: Primary subject identity (e.g. 'admin' or '203.0.113.100').
        severity: Recommended severity tier ('Critical', 'High', 'Medium', 'Low').
        confidence: Evidentiary confidence score in [0.0, 1.0].
        confidence_level: Categorical confidence ('High', 'Medium', 'Low').
        anomaly_score: Statistical ML anomaly score in [0.0, 1.0] (kept strictly separate from severity).
        composite_risk_score: Normalized composite priority score in [0, 100].
        is_confirmed: Boolean flag. Never set to True based solely on an anomaly score.
        confirmation_status: Descriptive confirmation state ('Unconfirmed Anomaly', 'Corroborated Threat', 'Confirmed Incident').
        first_seen: Earliest event timestamp in the correlation window (ISO-8601 UTC).
        last_seen: Latest event timestamp in the correlation window (ISO-8601 UTC).
        event_count: Number of correlated telemetry events.
        related_event_ids: Unique fingerprints of all supporting events.
        triggered_rule_names: List of distinct rule names fired within this incident.
        mitre_techniques: Associated MITRE ATT&CK technique tags.
        risk_breakdown: List of transparent RiskFactor components.
        risk_explanation: Comprehensive narrative explaining the risk calculation.
        defensive_recommendations: Safe, non-destructive SOC investigation steps.
        fingerprint: Deterministic cryptographic hash preventing duplicate incidents.
        metadata: Additional contextual metrics and raw finding references.
    """
    incident_id: str
    title: str
    entity_type: str
    entity_value: str
    severity: str
    confidence: float
    confidence_level: str
    anomaly_score: Optional[float]
    composite_risk_score: int
    is_confirmed: bool
    confirmation_status: str
    first_seen: str
    last_seen: str
    event_count: int
    related_event_ids: List[str] = field(default_factory=list)
    triggered_rule_names: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    risk_breakdown: List[RiskFactor] = field(default_factory=list)
    risk_explanation: str = ""
    defensive_recommendations: List[str] = field(default_factory=list)
    fingerprint: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert the incident instance to a JSON-serializable dictionary."""
        d = asdict(self)
        d["risk_breakdown"] = [rf.to_dict() for rf in self.risk_breakdown]
        return d
