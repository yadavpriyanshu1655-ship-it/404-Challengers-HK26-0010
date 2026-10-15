"""
CyberShield AI — Threat Alert Models

Defines the finding data structures, severity ratings, and investigation
specifications produced by the CyberShield Threat Detection Engine.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


@dataclass
class ThreatAlert:
    """
    Explainable security finding produced by the detection engine.

    Attributes:
        alert_id: Unique identifier for the alert (e.g. 'CS-ALERT-0001').
        rule_name: Canonical name of the triggered detection rule.
        timestamp: ISO-8601 UTC timestamp of the alert trigger event.
        entity_type: Type of the affected entity ('username', 'source_ip', 'composite').
        entity_value: Identity or address of the affected entity (e.g. 'admin' or '192.168.1.10').
        severity: Recommended severity level ('Critical', 'High', 'Medium', 'Low').
        evidence_strength: Confidence in the finding ('Strong', 'Moderate', 'Weak').
        explanation: Detailed human-readable explanation of why the rule fired.
        observed_value: Observed metric value that triggered the alert.
        threshold: Configured threshold that was exceeded.
        recommended_investigation_step: Concrete action recommended for SOC analysts.
        related_event_ids: List of fingerprints or identifiers of supporting events.
        mitre_technique: Associated MITRE ATT&CK technique reference (e.g. 'T1110').
        fingerprint: Deterministic SHA-256 hash to prevent duplicate alerts.
        metadata: Additional contextual attributes or baseline metrics.
    """
    alert_id: str
    rule_name: str
    timestamp: str
    entity_type: str
    entity_value: str
    severity: str
    evidence_strength: str
    explanation: str
    observed_value: str
    threshold: str
    recommended_investigation_step: str
    related_event_ids: List[str] = field(default_factory=list)
    mitre_technique: str = "T1110"
    fingerprint: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert the alert instance to a JSON-serializable dictionary."""
        return asdict(self)
