"""
CyberShield AI — Machine Learning Anomaly Models

Defines the finding data structures, metrics, and explanatory schemas
produced by the Scikit-learn Anomaly Detection Pipeline.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class AnomalyFinding:
    """
    Structured outcome of machine-learning anomaly scoring on a security event.

    Attributes:
        finding_id: Unique identifier for the finding (e.g. 'CS-ANOMALY-0001').
        event_fingerprint: Fingerprint of the evaluated security telemetry event.
        timestamp: ISO-8601 UTC timestamp of the evaluated event.
        entity: Associated user identity or source IP address.
        is_anomaly: Boolean flag indicating if the event was flagged as an outlier.
        anomaly_score: Calibrated anomaly score in [0.0, 1.0] (higher = more anomalous).
        raw_score: Raw decision function score from the model.
        contributing_factors: List of human-readable feature deviations contributing to the outlier score.
        disclaimer: Explicit advisory noting that statistical anomalies are not necessarily malicious.
        metadata: Additional contextual model inferences and feature values.
    """
    finding_id: str
    event_fingerprint: str
    timestamp: str
    entity: str
    is_anomaly: bool
    anomaly_score: float
    raw_score: float
    contributing_factors: List[str] = field(default_factory=list)
    disclaimer: str = "Statistical anomaly indicator only; does not necessarily indicate malicious intent."
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding into a JSON-serializable dictionary."""
        return asdict(self)


@dataclass
class ModelEvaluationReport:
    """
    Evaluation metrics reported on held-out synthetic test telemetry.
    """
    model_name: str
    algorithm: str
    training_sample_count: int
    evaluation_sample_count: int
    contamination_rate: float
    detected_anomalies_count: int
    anomaly_rate: float
    mean_anomaly_score: float
    limitations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
