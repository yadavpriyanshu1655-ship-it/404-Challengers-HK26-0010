"""
Unit and integration tests for CyberShield AI Rule-Based Threat Detection Engine.

Covers:
- Repeated failed login detection (thresholds & time-window boundaries).
- Successful login following repeated failures.
- Unusually high login frequency (burst velocity).
- Unusual login hours (strictly baseline-governed).
- Suspicious behavioral shifts (strictly baseline-governed).
- Non-attack filtering (single failed logins, benign user behaviors).
- Alert deduplication during repeated processing.
- Missing data, non-auth events, and malformed telemetry resilience.
- Integration test with Phase 02 Ingestion Engine.
"""

from datetime import datetime, timedelta
import pytest

from backend.detection import DetectionConfig, ThreatDetectionEngine
from backend.ingestion import SecurityLogIngestion
from backend.models.alert import ThreatAlert
from backend.models.event import SecurityEvent


@pytest.fixture
def detection_engine() -> ThreatDetectionEngine:
    """Fixture providing a fresh ThreatDetectionEngine with default configurations."""
    return ThreatDetectionEngine()


def make_event(
    timestamp: str,
    source_ip: str = "192.168.1.10",
    username: str = "alice",
    event_type: str = "login",
    status: str = "success",
    resource: str = "/auth/login",
    destination_ip: str = "10.0.0.1",
    payload_size: int = 128,
) -> SecurityEvent:
    """Helper creating a typed SecurityEvent for testing."""
    return SecurityEvent(
        timestamp=timestamp,
        source_ip=source_ip,
        destination_ip=destination_ip,
        username=username,
        event_type=event_type,
        status=status,
        resource=resource,
        payload_size=payload_size,
        fingerprint=f"fp_{timestamp}_{source_ip}_{username}_{status}",
    )


# =====================================================================
# 1. Rule 1: Repeated Failed Logins
# =====================================================================

def test_repeated_failed_logins_positive(detection_engine: ThreatDetectionEngine):
    """5 failed logins within 10 minutes triggers Repeated Failed Logins alert."""
    base_time = datetime(2026, 10, 15, 9, 0, 0)
    events = [
        make_event(
            (base_time + timedelta(minutes=i)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            source_ip="203.0.113.100",
            username="admin",
            status="failed",
        )
        for i in range(5)
    ]
    alerts = detection_engine.detect(events)
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_name == "Repeated Failed Logins"
    assert alert.severity == "High"
    assert alert.evidence_strength == "Strong"
    assert "203.0.113.100" in alert.explanation
    assert alert.mitre_technique == "T1110.001 - Brute Force: Password Guessing"
    assert len(alert.related_event_ids) == 5


def test_repeated_failed_logins_negative_below_threshold(detection_engine: ThreatDetectionEngine):
    """4 failed logins (below threshold of 5) does NOT trigger an alert."""
    base_time = datetime(2026, 10, 15, 9, 0, 0)
    events = [
        make_event(
            (base_time + timedelta(minutes=i)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            source_ip="203.0.113.100",
            username="admin",
            status="failed",
        )
        for i in range(4)
    ]
    alerts = detection_engine.detect(events)
    assert len(alerts) == 0


def test_isolated_failed_logins_not_treated_as_attack(detection_engine: ThreatDetectionEngine):
    """Requirement: Do not treat every failed login as an attack."""
    events = [
        make_event("2026-10-15T09:00:00Z", source_ip="192.168.1.10", username="alice", status="failed"),
        make_event("2026-10-15T10:30:00Z", source_ip="192.168.1.10", username="alice", status="failed"),
    ]
    alerts = detection_engine.detect(events)
    assert len(alerts) == 0


def test_repeated_failed_logins_outside_window_boundary(detection_engine: ThreatDetectionEngine):
    """5 failed logins spread over 30 minutes (exceeding 10m window) do NOT trigger an alert."""
    base_time = datetime(2026, 10, 15, 9, 0, 0)
    events = [
        make_event(
            (base_time + timedelta(minutes=i * 6)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            source_ip="203.0.113.100",
            username="admin",
            status="failed",
        )
        for i in range(5)
    ]
    alerts = detection_engine.detect(events)
    assert len(alerts) == 0


def test_configurable_failed_login_threshold():
    """Verify threshold can be configured to custom limits (e.g. 3 attempts in 5 mins)."""
    custom_config = DetectionConfig(failed_login_threshold=3, failed_login_window_minutes=5.0)
    engine = ThreatDetectionEngine(config=custom_config)

    base_time = datetime(2026, 10, 15, 9, 0, 0)
    events = [
        make_event(
            (base_time + timedelta(minutes=i)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            source_ip="10.0.0.22",
            username="bob",
            status="failed",
        )
        for i in range(3)
    ]
    alerts = engine.detect(events)
    assert len(alerts) == 1
    assert alerts[0].rule_name == "Repeated Failed Logins"


# =====================================================================
# 2. Rule 2: Successful Login Following Repeated Failures
# =====================================================================

def test_success_following_failures_positive(detection_engine: ThreatDetectionEngine):
    """Successful login following 3 failures in 10 minutes triggers Critical alert."""
    base_time = datetime(2026, 10, 15, 9, 0, 0)
    events = [
        make_event((base_time + timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%SZ"), source_ip="203.0.113.5", username="admin", status="failed"),
        make_event((base_time + timedelta(minutes=2)).strftime("%Y-%m-%dT%H:%M:%SZ"), source_ip="203.0.113.5", username="admin", status="failed"),
        make_event((base_time + timedelta(minutes=3)).strftime("%Y-%m-%dT%H:%M:%SZ"), source_ip="203.0.113.5", username="admin", status="failed"),
        make_event((base_time + timedelta(minutes=4)).strftime("%Y-%m-%dT%H:%M:%SZ"), source_ip="203.0.113.5", username="admin", status="success"),
    ]
    alerts = detection_engine.detect(events)
    assert any(a.rule_name == "Success Following Repeated Failures" for a in alerts)
    alert = next(a for a in alerts if a.rule_name == "Success Following Repeated Failures")
    assert alert.severity == "Critical"
    assert alert.entity_value == "admin"
    assert "immediately followed 3 failed attempts" in alert.explanation


def test_success_following_failures_negative_below_threshold(detection_engine: ThreatDetectionEngine):
    """Successful login following only 2 failures (below threshold of 3) does NOT trigger Rule 2."""
    base_time = datetime(2026, 10, 15, 9, 0, 0)
    events = [
        make_event((base_time + timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%SZ"), source_ip="203.0.113.5", username="admin", status="failed"),
        make_event((base_time + timedelta(minutes=2)).strftime("%Y-%m-%dT%H:%M:%SZ"), source_ip="203.0.113.5", username="admin", status="failed"),
        make_event((base_time + timedelta(minutes=3)).strftime("%Y-%m-%dT%H:%M:%SZ"), source_ip="203.0.113.5", username="admin", status="success"),
    ]
    alerts = detection_engine.detect(events)
    assert not any(a.rule_name == "Success Following Repeated Failures" for a in alerts)


def test_success_without_preceding_failures(detection_engine: ThreatDetectionEngine):
    """Standard successful login without failures does NOT trigger Rule 2."""
    events = [
        make_event("2026-10-15T09:00:00Z", source_ip="192.168.1.10", username="alice", status="success")
    ]
    alerts = detection_engine.detect(events)
    assert len(alerts) == 0


def test_success_after_failures_outside_window(detection_engine: ThreatDetectionEngine):
    """Failures occurring 25 minutes prior to success (exceeding 10m window) do NOT trigger Rule 2."""
    events = [
        make_event("2026-10-15T08:00:00Z", source_ip="203.0.113.5", username="admin", status="failed"),
        make_event("2026-10-15T08:01:00Z", source_ip="203.0.113.5", username="admin", status="failed"),
        make_event("2026-10-15T08:02:00Z", source_ip="203.0.113.5", username="admin", status="failed"),
        make_event("2026-10-15T08:35:00Z", source_ip="203.0.113.5", username="admin", status="success"),
    ]
    alerts = detection_engine.detect(events)
    assert not any(a.rule_name == "Success Following Repeated Failures" for a in alerts)


# =====================================================================
# 3. Rule 3: Unusually High Login Frequency
# =====================================================================

def test_high_login_frequency_positive(detection_engine: ThreatDetectionEngine):
    """10 logins from one IP within 2 minutes triggers High Frequency alert."""
    base_time = datetime(2026, 10, 15, 9, 0, 0)
    events = [
        make_event(
            (base_time + timedelta(seconds=i * 10)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            source_ip="198.51.100.99",
            username=f"user_{i}",
            status="failed",
        )
        for i in range(10)
    ]
    alerts = detection_engine.detect(events)
    assert any(a.rule_name == "Unusually High Login Frequency" for a in alerts)
    alert = next(a for a in alerts if a.rule_name == "Unusually High Login Frequency")
    assert alert.severity == "High"
    assert "attempts/minute" in alert.explanation


def test_high_login_frequency_negative(detection_engine: ThreatDetectionEngine):
    """9 logins in 2 minutes (below threshold of 10) does NOT trigger high frequency alert."""
    base_time = datetime(2026, 10, 15, 9, 0, 0)
    events = [
        make_event(
            (base_time + timedelta(seconds=i * 10)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            source_ip="198.51.100.99",
            username=f"user_{i}",
            status="failed",
        )
        for i in range(9)
    ]
    alerts = detection_engine.detect(events)
    assert not any(a.rule_name == "Unusually High Login Frequency" for a in alerts)


# =====================================================================
# 4. Rule 4: Unusual Login Hours (Baseline-governed)
# =====================================================================

def test_unusual_login_hours_positive_with_baseline(detection_engine: ThreatDetectionEngine):
    """User with established daytime baseline logging in at 02:00 AM triggers Unusual Login Hours."""
    # Seed baseline: 6 logins between 09:00 and 17:00 UTC
    baseline_events = [
        make_event(f"2026-10-10T{h:02d}:00:00Z", source_ip="192.168.1.10", username="carol", status="success")
        for h in (9, 10, 11, 14, 15, 17)
    ]
    detection_engine.learn_baseline(baseline_events)

    # Unusual login at 02:00 AM UTC (7 hours away from 09:00, tolerance is 2h)
    new_event = make_event("2026-10-15T02:00:00Z", source_ip="192.168.1.10", username="carol", status="success")
    alerts = detection_engine.detect([new_event])

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_name == "Unusual Login Hours"
    assert alert.entity_value == "carol"
    assert "02:00 UTC" in alert.observed_value
    assert alert.metadata["baseline_count"] == 6


def test_unusual_login_hours_negative_without_baseline(detection_engine: ThreatDetectionEngine):
    """Requirement: NO alert when user has no established baseline profile."""
    # Brand new user with zero prior history
    new_event = make_event("2026-10-15T02:00:00Z", source_ip="192.168.1.10", username="new_hire", status="success")
    alerts = detection_engine.detect([new_event])
    assert not any(a.rule_name == "Unusual Login Hours" for a in alerts)


def test_unusual_login_hours_negative_insufficient_baseline(detection_engine: ThreatDetectionEngine):
    """Requirement: NO alert when user has fewer than min_baseline_events (e.g. only 2 events)."""
    insufficient_baseline = [
        make_event("2026-10-10T09:00:00Z", source_ip="192.168.1.10", username="dave", status="success"),
        make_event("2026-10-10T10:00:00Z", source_ip="192.168.1.10", username="dave", status="success"),
    ]
    detection_engine.learn_baseline(insufficient_baseline)

    new_event = make_event("2026-10-15T02:00:00Z", source_ip="192.168.1.10", username="dave", status="success")
    alerts = detection_engine.detect([new_event])
    assert not any(a.rule_name == "Unusual Login Hours" for a in alerts)


def test_unusual_login_hours_negative_during_normal_hours(detection_engine: ThreatDetectionEngine):
    """Normal hour login within baseline does NOT trigger an alert."""
    baseline_events = [
        make_event(f"2026-10-10T{h:02d}:00:00Z", source_ip="192.168.1.10", username="carol", status="success")
        for h in (9, 10, 11, 14, 15, 17)
    ]
    detection_engine.learn_baseline(baseline_events)

    normal_event = make_event("2026-10-15T10:30:00Z", source_ip="192.168.1.10", username="carol", status="success")
    alerts = detection_engine.detect([normal_event])
    assert not any(a.rule_name == "Unusual Login Hours" for a in alerts)


# =====================================================================
# 5. Rule 5: Suspicious Changes in Login Behavior (Baseline-governed)
# =====================================================================

def test_suspicious_behavioral_shift_positive_with_baseline(detection_engine: ThreatDetectionEngine):
    """User with 10 internal subnet logins suddenly authenticating from external subnet triggers alert."""
    # Seed baseline: 10 logins strictly within 192.168.1.0/24
    baseline_events = [
        make_event(
            f"2026-10-10T09:{i:02d}:00Z",
            source_ip=f"192.168.1.{10 + i}",
            username="engineering_lead",
            status="success",
        )
        for i in range(10)
    ]
    detection_engine.learn_baseline(baseline_events)

    # Anomaly: Sudden login from unfamiliar external IP
    anomalous_event = make_event(
        "2026-10-15T14:00:00Z",
        source_ip="203.0.113.88",
        username="engineering_lead",
        status="success",
    )
    alerts = detection_engine.detect([anomalous_event])

    assert any(a.rule_name == "Suspicious Login Behavioral Shift" for a in alerts)
    alert = next(a for a in alerts if a.rule_name == "Suspicious Login Behavioral Shift")
    assert alert.severity == "High"
    assert alert.evidence_strength == "Strong"
    assert "203.0.113.88" in alert.observed_value
    assert alert.metadata["baseline_count"] == 10


def test_suspicious_behavioral_shift_negative_without_baseline(detection_engine: ThreatDetectionEngine):
    """Requirement: NO alert when user has no established behavioral baseline."""
    anomalous_event = make_event(
        "2026-10-15T14:00:00Z",
        source_ip="203.0.113.88",
        username="unknown_contractor",
        status="success",
    )
    alerts = detection_engine.detect([anomalous_event])
    assert not any(a.rule_name == "Suspicious Login Behavioral Shift" for a in alerts)


def test_suspicious_behavioral_shift_negative_within_known_subnet(detection_engine: ThreatDetectionEngine):
    """Login within an established subnet does NOT trigger behavioral shift alert."""
    baseline_events = [
        make_event(
            f"2026-10-10T09:{i:02d}:00Z",
            source_ip=f"192.168.1.{10 + i}",
            username="engineering_lead",
            status="success",
        )
        for i in range(10)
    ]
    detection_engine.learn_baseline(baseline_events)

    # Another IP in the same /24 subnet
    normal_shift_event = make_event(
        "2026-10-15T14:00:00Z",
        source_ip="192.168.1.99",
        username="engineering_lead",
        status="success",
    )
    alerts = detection_engine.detect([normal_shift_event])
    assert not any(a.rule_name == "Suspicious Login Behavioral Shift" for a in alerts)


# =====================================================================
# 6. Deduplication & Repeated Processing
# =====================================================================

def test_alert_deduplication_during_repeated_processing(detection_engine: ThreatDetectionEngine):
    """Requirement: Prevent duplicate alerts during repeated processing."""
    base_time = datetime(2026, 10, 15, 9, 0, 0)
    events = [
        make_event(
            (base_time + timedelta(minutes=i)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            source_ip="203.0.113.100",
            username="admin",
            status="failed",
        )
        for i in range(5)
    ]
    # First pass: generates alert
    pass1_alerts = detection_engine.detect(events)
    assert len(pass1_alerts) == 1

    # Second pass: exact same events processed again -> 0 duplicate alerts
    pass2_alerts = detection_engine.detect(events)
    assert len(pass2_alerts) == 0

    # Reset cache: allows clean re-alerting
    detection_engine.reset_alert_cache()
    pass3_alerts = detection_engine.detect(events)
    assert len(pass3_alerts) == 1


# =====================================================================
# 7. Non-Auth Events & Missing / Malformed Data
# =====================================================================

def test_non_auth_events_ignored(detection_engine: ThreatDetectionEngine):
    """Non-authentication telemetry (file_access, database_query) is safely skipped."""
    events = [
        make_event("2026-10-15T09:00:00Z", event_type="file_access", status="failed"),
        make_event("2026-10-15T09:01:00Z", event_type="database_query", status="failed"),
        make_event("2026-10-15T09:02:00Z", event_type="network_sync", status="failed"),
    ]
    alerts = detection_engine.detect(events)
    assert len(alerts) == 0


def test_empty_input_list(detection_engine: ThreatDetectionEngine):
    """Empty event sequence returns empty alert list cleanly."""
    alerts = detection_engine.detect([])
    assert alerts == []


def test_dict_input_handling(detection_engine: ThreatDetectionEngine):
    """Detection engine accepts raw dict dictionaries as well as SecurityEvent dataclasses."""
    base_time = datetime(2026, 10, 15, 9, 0, 0)
    raw_dicts = [
        {
            "timestamp": (base_time + timedelta(minutes=i)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "source_ip": "10.10.10.10",
            "username": "root",
            "event_type": "login",
            "status": "failed",
            "fingerprint": f"fp_dict_{i}",
        }
        for i in range(5)
    ]
    alerts = detection_engine.detect(raw_dicts)
    assert len(alerts) == 1
    assert alerts[0].rule_name == "Repeated Failed Logins"


# =====================================================================
# 8. End-to-End Pipeline Integration with Synthetic Telemetry
# =====================================================================

def test_end_to_end_synthetic_logs_detection():
    """Verify that Ingestion Engine and Detection Engine seamlessly integrate on synthetic logs."""
    ingestion = SecurityLogIngestion()
    detection = ThreatDetectionEngine()

    from pathlib import Path
    data_path = Path(__file__).resolve().parent.parent / "data" / "synthetic_logs.csv"
    ingestion_result = ingestion.process_file(data_path)

    assert ingestion_result.accepted_count == 25

    # Run detection on ingested events
    alerts = detection.detect(ingestion_result)

    # In synthetic_logs.csv:
    # 203.0.113.100 performs 5 failed logins from 09:00 to 09:04 -> Rule 1
    # 203.0.113.100 then logs in successfully at 09:05 -> Rule 2
    rule_names = {a.rule_name for a in alerts}
    assert "Repeated Failed Logins" in rule_names
    assert "Success Following Repeated Failures" in rule_names

    for alert in alerts:
        assert isinstance(alert, ThreatAlert)
        assert alert.alert_id.startswith("CS-ALERT-")
        assert len(alert.related_event_ids) > 0
        assert alert.severity in {"Critical", "High", "Medium", "Low"}
        assert alert.evidence_strength in {"Strong", "Moderate", "Weak"}
        assert len(alert.explanation) > 0
        assert len(alert.recommended_investigation_step) > 0
