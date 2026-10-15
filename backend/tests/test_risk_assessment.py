"""
Unit and integration tests for CyberShield AI Threat Risk Assessment & Alert Correlation.

Covers:
- 4-Tier severity boundaries (Low, Medium, High, Critical).
- Separation of severity, confidence, and anomaly scores.
- Combining rule-based evidence and ML findings transparently.
- Correlation of related events vs. preservation of unrelated events.
- Alert and incident deduplication across repeated runs.
- Prioritization ranking based on documented risk factors.
- Explainability breakdown and risk narrative verification.
- Safe defensive investigation recommendations.
- Strict constraint: Non-confirmation of anomaly-only findings.
- Missing context and edge-case handling.
"""

from datetime import datetime, timedelta
import pytest

from backend.models.alert import ThreatAlert
from backend.models.anomaly import AnomalyFinding
from backend.models.event import SecurityEvent
from backend.models.risk import ConfidenceLevel, CorrelatedIncident, RiskSeverity
from backend.risk_assessment import RiskAssessmentConfig, ThreatRiskEngine


@pytest.fixture
def risk_engine() -> ThreatRiskEngine:
    """Fixture providing a fresh ThreatRiskEngine with default configuration."""
    return ThreatRiskEngine()


def make_alert(
    rule_name: str = "Repeated Failed Logins",
    timestamp: str = "2026-10-15T09:05:00Z",
    entity_type: str = "source_ip",
    entity_value: str = "203.0.113.100",
    severity: str = "High",
    evidence_strength: str = "Strong",
    observed_value: str = "5 failed attempts in 5.0m",
    threshold: str = ">= 5 in <= 10m",
) -> ThreatAlert:
    """Helper creating a test ThreatAlert."""
    return ThreatAlert(
        alert_id="CS-ALERT-0001",
        rule_name=rule_name,
        timestamp=timestamp,
        entity_type=entity_type,
        entity_value=entity_value,
        severity=severity,
        evidence_strength=evidence_strength,
        explanation=f"Test explanation for {rule_name}",
        observed_value=observed_value,
        threshold=threshold,
        recommended_investigation_step="Inspect authentication telemetry.",
        related_event_ids=["fp_1", "fp_2"],
        mitre_technique="T1110",
        fingerprint=f"alert_fp_{rule_name}_{entity_value}_{timestamp}",
    )


def make_anomaly(
    timestamp: str = "2026-10-15T09:05:00Z",
    entity: str = "203.0.113.100",
    anomaly_score: float = 0.85,
    is_anomaly: bool = True,
) -> AnomalyFinding:
    """Helper creating a test AnomalyFinding."""
    return AnomalyFinding(
        finding_id="CS-ANOMALY-0001",
        event_fingerprint="fp_anomaly_1",
        timestamp=timestamp,
        entity=entity,
        is_anomaly=is_anomaly,
        anomaly_score=anomaly_score,
        raw_score=-0.25,
        contributing_factors=["Off-hours activity", "External IP source"],
    )


# =====================================================================
# 1. Severity Boundaries & Edge Score Tests
# =====================================================================

def test_severity_boundaries(risk_engine: ThreatRiskEngine):
    """
    Verify 4-tier severity boundaries:
    Critical: >= 85
    High: 65 - 84
    Medium: 40 - 64
    Low: < 40
    """
    # 1. Critical test (Critical rule: base 80 + external IP 5 = 85 -> Critical)
    crit_alert = make_alert(
        rule_name="Success Following Repeated Failures",
        severity="Critical",
        entity_value="admin",
        entity_type="username",
    )
    # Add external IP event
    ext_event = SecurityEvent(
        timestamp="2026-10-15T09:05:00Z",
        source_ip="203.0.113.55",
        username="admin",
        event_type="login",
        status="success",
    )
    incidents = risk_engine.assess_and_correlate(events=[ext_event], rule_alerts=[crit_alert])
    assert len(incidents) == 1
    assert incidents[0].composite_risk_score >= 85
    assert incidents[0].severity == RiskSeverity.CRITICAL.value

    risk_engine.reset()

    # 2. High test (High rule: base 65 -> High)
    high_alert = make_alert(
        rule_name="Repeated Failed Logins",
        severity="High",
        entity_value="192.168.1.10",
        entity_type="source_ip",
    )
    high_incidents = risk_engine.assess_and_correlate(rule_alerts=[high_alert])
    assert len(high_incidents) == 1
    assert 65 <= high_incidents[0].composite_risk_score < 85
    assert high_incidents[0].severity == RiskSeverity.HIGH.value

    risk_engine.reset()

    # 3. Medium test (Medium rule: base 40 -> Medium)
    med_alert = make_alert(
        rule_name="Unusual Login Hours",
        severity="Medium",
        entity_value="carol",
        entity_type="username",
    )
    med_incidents = risk_engine.assess_and_correlate(rule_alerts=[med_alert])
    assert len(med_incidents) == 1
    assert 40 <= med_incidents[0].composite_risk_score < 65
    assert med_incidents[0].severity == RiskSeverity.MEDIUM.value

    risk_engine.reset()

    # 4. Low test (Low rule: base 20 -> Low)
    low_alert = make_alert(
        rule_name="Minor Policy Notice",
        severity="Low",
        entity_value="david",
        entity_type="username",
    )
    low_incidents = risk_engine.assess_and_correlate(rule_alerts=[low_alert])
    assert len(low_incidents) == 1
    assert low_incidents[0].composite_risk_score < 40
    assert low_incidents[0].severity == RiskSeverity.LOW.value


# =====================================================================
# 2. Separation of Severity, Confidence, and Anomaly Score
# =====================================================================

def test_separation_of_severity_confidence_and_anomaly_score(risk_engine: ThreatRiskEngine):
    """
    Requirement Check:
    Keep severity, confidence, and anomaly score strictly separate.
    """
    alert = make_alert(
        rule_name="Repeated Failed Logins",
        severity="High",
        entity_value="admin",
        entity_type="username",
    )
    anomaly = make_anomaly(
        entity="admin",
        anomaly_score=0.91,
        is_anomaly=True,
    )
    incidents = risk_engine.assess_and_correlate(rule_alerts=[alert], anomaly_findings=[anomaly])
    assert len(incidents) == 1
    inc = incidents[0]

    # Verify each dimension is populated independently
    assert isinstance(inc.severity, str)
    assert inc.severity in {"Critical", "High", "Medium", "Low"}
    assert isinstance(inc.confidence, float)
    assert 0.0 <= inc.confidence <= 1.0
    assert inc.confidence_level in {"High", "Medium", "Low"}
    assert isinstance(inc.anomaly_score, float)
    assert inc.anomaly_score == 0.91
    assert isinstance(inc.composite_risk_score, int)
    assert 0 <= inc.composite_risk_score <= 100

    # Ensure severity does NOT overwrite anomaly_score, and vice versa
    assert inc.anomaly_score != inc.composite_risk_score


# =====================================================================
# 3. Transparent Combination of Rules and ML Findings
# =====================================================================

def test_transparent_risk_combination_breakdown(risk_engine: ThreatRiskEngine):
    """Verify additive risk factor breakdown is transparent and documented."""
    alert = make_alert(
        rule_name="Success Following Repeated Failures",
        severity="Critical",
        entity_value="root",
        entity_type="username",
    )
    anomaly = make_anomaly(entity="root", anomaly_score=0.88)
    event = SecurityEvent(
        timestamp="2026-10-15T09:05:00Z",
        source_ip="203.0.113.77",
        username="root",
        event_type="login",
        status="success",
    )

    incidents = risk_engine.assess_and_correlate(
        events=[event], rule_alerts=[alert], anomaly_findings=[anomaly]
    )
    assert len(incidents) == 1
    inc = incidents[0]

    # Check risk breakdown components
    factor_names = [f.factor_name for f in inc.risk_breakdown]
    assert "Rule Evidence Baseline" in factor_names
    assert "Machine Learning Anomaly Score" in factor_names
    assert "Privileged Identity Target" in factor_names
    assert "External Network Origin" in factor_names

    # Check explanation narrative
    assert "Composite Risk Score" in inc.risk_explanation
    assert inc.composite_risk_score >= 85


# =====================================================================
# 4. Correlation of Related Events vs Unrelated Events
# =====================================================================

def test_correlate_related_events(risk_engine: ThreatRiskEngine):
    """Evidence for same entity within correlation window is merged into single incident."""
    alert1 = make_alert(
        rule_name="Repeated Failed Logins",
        timestamp="2026-10-15T09:00:00Z",
        entity_value="admin",
        entity_type="username",
    )
    alert2 = make_alert(
        rule_name="Success Following Repeated Failures",
        timestamp="2026-10-15T09:05:00Z",
        entity_value="admin",
        entity_type="username",
    )
    anomaly = make_anomaly(timestamp="2026-10-15T09:05:00Z", entity="admin")

    incidents = risk_engine.assess_and_correlate(
        rule_alerts=[alert1, alert2], anomaly_findings=[anomaly]
    )
    assert len(incidents) == 1
    assert set(incidents[0].triggered_rule_names) == {
        "Repeated Failed Logins",
        "Success Following Repeated Failures",
    }


def test_unrelated_events_remain_separated(risk_engine: ThreatRiskEngine):
    """
    Requirement Check:
    Correlate related events ONLY when evidence supports the relationship.
    Unrelated entities and distant timestamps must remain separate incidents.
    """
    # Incident 1: Alice at 09:00
    alert_alice = make_alert(
        rule_name="Repeated Failed Logins",
        timestamp="2026-10-15T09:00:00Z",
        entity_value="alice",
        entity_type="username",
    )
    # Incident 2: Bob at 09:02 (different entity)
    alert_bob = make_alert(
        rule_name="Unusually High Login Frequency",
        timestamp="2026-10-15T09:02:00Z",
        entity_value="bob",
        entity_type="username",
    )
    # Incident 3: Alice at 18:00 (same entity, but 9 hours apart!)
    alert_alice_late = make_alert(
        rule_name="Unusual Login Hours",
        timestamp="2026-10-15T18:00:00Z",
        entity_value="alice",
        entity_type="username",
    )

    incidents = risk_engine.assess_and_correlate(
        rule_alerts=[alert_alice, alert_bob, alert_alice_late]
    )

    # Must produce 3 separate incidents
    assert len(incidents) == 3
    entities_and_times = {(inc.entity_value, inc.first_seen) for inc in incidents}
    assert ("alice", "2026-10-15T09:00:00Z") in entities_and_times
    assert ("bob", "2026-10-15T09:02:00Z") in entities_and_times
    assert ("alice", "2026-10-15T18:00:00Z") in entities_and_times


# =====================================================================
# 5. Alert Deduplication
# =====================================================================

def test_incident_deduplication(risk_engine: ThreatRiskEngine):
    """Requirement: Deduplicate related alerts during repeated processing."""
    alert = make_alert(entity_value="target_user", entity_type="username")

    # First pass produces incident
    pass1 = risk_engine.assess_and_correlate(rule_alerts=[alert])
    assert len(pass1) == 1

    # Second pass with exact same evidence produces 0 duplicates
    pass2 = risk_engine.assess_and_correlate(rule_alerts=[alert])
    assert len(pass2) == 0

    # Reset cache allows clean re-alerting
    risk_engine.reset()
    pass3 = risk_engine.assess_and_correlate(rule_alerts=[alert])
    assert len(pass3) == 1


# =====================================================================
# 6. Prioritization by Documented Factors
# =====================================================================

def test_prioritization_ordering(risk_engine: ThreatRiskEngine):
    """Verify incidents are sorted descending by composite risk score."""
    low_alert = make_alert(
        rule_name="Policy Notice",
        severity="Low",
        entity_value="user_low",
        entity_type="username",
    )
    high_alert = make_alert(
        rule_name="Repeated Failed Logins",
        severity="High",
        entity_value="user_high",
        entity_type="username",
    )
    crit_alert = make_alert(
        rule_name="Success Following Repeated Failures",
        severity="Critical",
        entity_value="root",
        entity_type="username",
    )

    incidents = risk_engine.assess_and_correlate(
        rule_alerts=[low_alert, high_alert, crit_alert]
    )
    assert len(incidents) == 3
    # Critical should be first, then High, then Low
    assert incidents[0].severity == "Critical"
    assert incidents[1].severity == "High"
    assert incidents[2].severity == "Low"
    assert incidents[0].composite_risk_score >= incidents[1].composite_risk_score >= incidents[2].composite_risk_score


# =====================================================================
# 7. Strict Non-Confirmation of Anomaly-Only Findings
# =====================================================================

def test_anomaly_only_not_marked_confirmed(risk_engine: ThreatRiskEngine):
    """
    Requirement Check:
    Do not mark an incident confirmed based solely on an anomaly score.
    """
    anomaly = make_anomaly(entity="developer_1", anomaly_score=0.92, is_anomaly=True)
    incidents = risk_engine.assess_and_correlate(anomaly_findings=[anomaly])

    assert len(incidents) == 1
    inc = incidents[0]

    # Explicit assertions per requirement
    assert inc.is_confirmed is False
    assert inc.confirmation_status == "Unconfirmed Anomaly"
    assert inc.confidence <= 0.45
    assert inc.confidence_level == ConfidenceLevel.LOW.value
    assert inc.severity != RiskSeverity.CRITICAL.value
    # Safe defensive recommendation verification
    assert any("do not block access based solely on anomaly score" in r.lower() for r in inc.defensive_recommendations)


# =====================================================================
# 8. Missing Context and Edge Cases
# =====================================================================

def test_missing_context_handled_gracefully(risk_engine: ThreatRiskEngine):
    """Handle events with missing optional fields without crashing."""
    corrupt_event = {
        "timestamp": "2026-10-15T09:00:00Z",
        "username": None,
        "source_ip": "127.0.0.1",
    }
    incidents = risk_engine.assess_and_correlate(events=[corrupt_event])
    assert incidents == []


def test_empty_inputs_returns_empty(risk_engine: ThreatRiskEngine):
    """Verify empty inputs return empty list."""
    assert risk_engine.assess_and_correlate() == []
    assert risk_engine.assess_and_correlate(events=[], rule_alerts=[], anomaly_findings=[]) == []
