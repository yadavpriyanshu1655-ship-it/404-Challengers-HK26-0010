"""
CyberShield AI — Rule-Based Threat Detection Engine

Configurable, explainable detection engine processing normalized security events.
Detects:
1. Repeated failed login attempts within a configurable time window (Brute-Force).
2. Successful login following repeated failures (Compromised Account).
3. Unusually high login frequency (Volumetric / Stuffing Burst).
4. Unusual login hours (strictly when a valid behavioral baseline exists).
5. Suspicious changes in login behavior (strictly when sufficient historical evidence exists).

Provides comprehensive, explainable findings with observed values, thresholds,
evidence strength, MITRE ATT&CK mapping, and actionable SOC investigation steps.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import ipaddress
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple, Union

from backend.models.alert import ThreatAlert
from backend.models.event import IngestionResult, SecurityEvent


# =====================================================================
# Configuration
# =====================================================================

@dataclass
class DetectionConfig:
    """
    Configurable detection thresholds and behavioral baseline parameters.
    """
    # Rule 1: Repeated Failed Logins
    failed_login_threshold: int = 5
    failed_login_window_minutes: float = 10.0

    # Rule 2: Successful Login Following Repeated Failures
    preceding_failures_threshold: int = 3
    preceding_failures_window_minutes: float = 10.0

    # Rule 3: High Login Frequency (Burst Rate)
    high_frequency_threshold: int = 10
    high_frequency_window_minutes: float = 2.0

    # Rule 4: Unusual Login Hours (Baseline-governed)
    min_baseline_events_for_hours: int = 5
    unusual_hour_tolerance_hours: float = 2.0

    # Rule 5: Suspicious Changes in Login Behavior (Baseline-governed)
    min_baseline_events_for_behavior: int = 8


# =====================================================================
# Behavioral Baseline Entity Profile
# =====================================================================

@dataclass
class UserBaselineProfile:
    """
    Historical behavioral profile for an individual user identity.
    """
    username: str
    historical_timestamps: List[datetime] = field(default_factory=list)
    seen_ips: Set[str] = field(default_factory=set)
    seen_subnets: Set[str] = field(default_factory=set)
    seen_hours: Set[int] = field(default_factory=set)

    def add_event(self, dt: datetime, ip: str) -> None:
        """Register an observed historical event into the baseline."""
        self.historical_timestamps.append(dt)
        self.seen_ips.add(ip)
        self.seen_hours.add(dt.hour)
        try:
            # Group IPv4 by /24 subnet or IPv6 by /64
            addr = ipaddress.ip_address(ip)
            if addr.version == 4:
                net = ipaddress.ip_network(f"{ip}/24", strict=False)
            else:
                net = ipaddress.ip_network(f"{ip}/64", strict=False)
            self.seen_subnets.add(str(net))
        except ValueError:
            self.seen_subnets.add(ip)

    @property
    def total_events(self) -> int:
        return len(self.historical_timestamps)

    @property
    def min_hour(self) -> int:
        return min(self.seen_hours) if self.seen_hours else 0

    @property
    def max_hour(self) -> int:
        return max(self.seen_hours) if self.seen_hours else 23

    def hour_distance(self, target_hour: int) -> float:
        """Calculate circular hour distance (0-12 hours) from established hours."""
        if not self.seen_hours:
            return 0.0
        return min(
            min(abs(target_hour - h), 24 - abs(target_hour - h))
            for h in self.seen_hours
        )


# =====================================================================
# Detection Engine
# =====================================================================

class ThreatDetectionEngine:
    """
    Rule-based, explainable threat detection engine.
    """

    AUTH_EVENT_TYPES: Set[str] = {
        "login", "auth", "signin", "sign_in", "ssh_session", "session_start"
    }
    FAILURE_STATUSES: Set[str] = {
        "failed", "failure", "denied", "error", "rejected"
    }
    SUCCESS_STATUSES: Set[str] = {
        "success", "successful", "ok", "accepted", "approved"
    }

    def __init__(self, config: Optional[DetectionConfig] = None):
        self.config = config or DetectionConfig()
        self.seen_alert_fingerprints: Set[str] = set()
        self.user_baselines: Dict[str, UserBaselineProfile] = {}
        self._alert_counter: int = 0

    def reset_alert_cache(self) -> None:
        """Clear cached alert fingerprints to allow clean re-processing."""
        self.seen_alert_fingerprints.clear()
        self._alert_counter = 0

    def reset_baselines(self) -> None:
        """Clear learned behavioral baselines."""
        self.user_baselines.clear()

    # -----------------------------------------------------------------
    # Baseline Ingestion
    # -----------------------------------------------------------------

    def learn_baseline(self, events: Iterable[Union[SecurityEvent, Dict[str, Any]]]) -> None:
        """
        Train/populate behavioral baselines from trusted historical telemetry.
        
        Args:
            events: Sequence of historical security events.
        """
        normalized_events = self._normalize_inputs(events)
        for ev, dt in normalized_events:
            if not self._is_auth_event(ev):
                continue
            username = ev.get("username", "").strip()
            source_ip = ev.get("source_ip", "").strip()
            if not username or not source_ip:
                continue

            if username not in self.user_baselines:
                self.user_baselines[username] = UserBaselineProfile(username=username)
            self.user_baselines[username].add_event(dt, source_ip)

    # -----------------------------------------------------------------
    # Main Detection Entrypoint
    # -----------------------------------------------------------------

    def detect(
        self,
        events: Union[IngestionResult, Iterable[Union[SecurityEvent, Dict[str, Any]]]],
        update_baselines: bool = False,
    ) -> List[ThreatAlert]:
        """
        Evaluate all 5 detection rules against the provided security events.
        
        Args:
            events: IngestionResult or sequence of SecurityEvents/dictionaries.
            update_baselines: If True, adds evaluated events into user behavioral baselines.
            
        Returns:
            List of generated ThreatAlert findings.
        """
        if isinstance(events, IngestionResult):
            raw_input = events.events
        else:
            raw_input = events

        normalized_events = self._normalize_inputs(raw_input)
        if not normalized_events:
            return []

        # Sort chronologically by timestamp
        normalized_events.sort(key=lambda item: item[1])

        alerts: List[ThreatAlert] = []

        # Rule 1: Repeated Failed Logins within Configurable Time Window
        alerts.extend(self._detect_repeated_failed_logins(normalized_events))

        # Rule 2: Successful Login Following Repeated Failures
        alerts.extend(self._detect_success_following_failures(normalized_events))

        # Rule 3: Unusually High Login Frequency (Burst Rate)
        alerts.extend(self._detect_high_login_frequency(normalized_events))

        # Rule 4: Unusual Login Hours (Baseline-governed)
        alerts.extend(self._detect_unusual_login_hours(normalized_events))

        # Rule 5: Suspicious Changes in Login Behavior (Baseline-governed)
        alerts.extend(self._detect_suspicious_behavioral_shifts(normalized_events))

        # Optionally update baselines with events evaluated in this run
        if update_baselines:
            for ev, dt in normalized_events:
                if self._is_auth_event(ev):
                    user = ev.get("username")
                    ip = ev.get("source_ip")
                    if user and ip:
                        if user not in self.user_baselines:
                            self.user_baselines[user] = UserBaselineProfile(username=user)
                        self.user_baselines[user].add_event(dt, ip)

        return alerts

    # -----------------------------------------------------------------
    # Rule 1: Repeated Failed Logins
    # -----------------------------------------------------------------

    def _detect_repeated_failed_logins(
        self, events: List[Tuple[Dict[str, Any], datetime]]
    ) -> List[ThreatAlert]:
        alerts: List[ThreatAlert] = []
        auth_events = [(ev, dt) for ev, dt in events if self._is_auth_event(ev)]

        # Group by source IP
        by_ip: Dict[str, List[Tuple[Dict[str, Any], datetime]]] = {}
        for ev, dt in auth_events:
            ip = ev.get("source_ip")
            if ip:
                by_ip.setdefault(ip, []).append((ev, dt))

        window_seconds = self.config.failed_login_window_minutes * 60.0
        threshold = self.config.failed_login_threshold

        for ip, ip_events in by_ip.items():
            failed_events = [(ev, dt) for ev, dt in ip_events if self._is_failure(ev)]
            if len(failed_events) < threshold:
                continue

            # Sliding window over failed events
            i = 0
            while i < len(failed_events):
                window = [failed_events[i]]
                j = i + 1
                while j < len(failed_events):
                    delta = (failed_events[j][1] - failed_events[i][1]).total_seconds()
                    if delta <= window_seconds:
                        window.append(failed_events[j])
                        j += 1
                    else:
                        break

                if len(window) >= threshold:
                    start_dt = window[0][1]
                    end_dt = window[-1][1]
                    duration_min = max(0.1, (end_dt - start_dt).total_seconds() / 60.0)
                    count = len(window)
                    target_users = sorted(set(ev.get("username", "") for ev, _ in window))

                    alert = self._create_alert(
                        rule_name="Repeated Failed Logins",
                        timestamp=end_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
                        entity_type="source_ip",
                        entity_value=ip,
                        severity="High",
                        evidence_strength="Strong",
                        explanation=(
                            f"Detected {count} consecutive failed authentication attempts from IP '{ip}' "
                            f"within {duration_min:.1f} minutes, targeting account(s): {', '.join(target_users[:5])}. "
                            f"Pattern strongly indicates automated brute-force password guessing."
                        ),
                        observed_value=f"{count} failed attempts in {duration_min:.1f} minutes",
                        threshold=f">= {threshold} failed attempts in <= {self.config.failed_login_window_minutes:.1f} minutes",
                        recommended_investigation_step=(
                            f"Inspect authentication logs for targeted users, verify if source IP '{ip}' "
                            f"belongs to a known VPN or malicious reputation list, and enforce IP-level rate limiting."
                        ),
                        related_event_ids=[ev.get("fingerprint", "") for ev, _ in window if ev.get("fingerprint")],
                        mitre_technique="T1110.001 - Brute Force: Password Guessing",
                        metadata={"target_users": target_users, "failure_count": count},
                    )
                    if alert:
                        alerts.append(alert)
                    # Advance past this window to avoid duplicate alerts on the same cluster
                    i = j
                else:
                    i += 1

        return alerts

    # -----------------------------------------------------------------
    # Rule 2: Successful Login Following Repeated Failures
    # -----------------------------------------------------------------

    def _detect_success_following_failures(
        self, events: List[Tuple[Dict[str, Any], datetime]]
    ) -> List[ThreatAlert]:
        alerts: List[ThreatAlert] = []
        auth_events = [(ev, dt) for ev, dt in events if self._is_auth_event(ev)]
        window_seconds = self.config.preceding_failures_window_minutes * 60.0
        threshold = self.config.preceding_failures_threshold

        for idx, (ev, dt) in enumerate(auth_events):
            if not self._is_success(ev):
                continue

            username = ev.get("username", "")
            source_ip = ev.get("source_ip", "")

            # Look back for failures by this user OR source IP within window
            preceding_failures: List[Tuple[Dict[str, Any], datetime]] = []
            for prev_ev, prev_dt in reversed(auth_events[:idx]):
                delta = (dt - prev_dt).total_seconds()
                if delta > window_seconds:
                    break
                if self._is_failure(prev_ev) and (
                    prev_ev.get("username") == username or prev_ev.get("source_ip") == source_ip
                ):
                    preceding_failures.append((prev_ev, prev_dt))

            if len(preceding_failures) >= threshold:
                failures_count = len(preceding_failures)
                earliest_dt = preceding_failures[-1][1]
                duration_min = max(0.1, (dt - earliest_dt).total_seconds() / 60.0)

                related_fps = [prev_ev.get("fingerprint", "") for prev_ev, _ in preceding_failures]
                if ev.get("fingerprint"):
                    related_fps.insert(0, ev.get("fingerprint"))

                alert = self._create_alert(
                    rule_name="Success Following Repeated Failures",
                    timestamp=dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    entity_type="username",
                    entity_value=username,
                    severity="Critical",
                    evidence_strength="Strong",
                    explanation=(
                        f"A successful authentication for user '{username}' from IP '{source_ip}' at "
                        f"{dt.strftime('%H:%M:%S UTC')} immediately followed {failures_count} failed "
                        f"attempts within {duration_min:.1f} minutes. This sequence strongly indicates "
                        f"compromise via brute-force or credential stuffing."
                    ),
                    observed_value=f"1 successful login preceded by {failures_count} failed attempts within {duration_min:.1f} minutes",
                    threshold=f">= {threshold} preceding failed attempts in <= {self.config.preceding_failures_window_minutes:.1f} minutes",
                    recommended_investigation_step=(
                        f"Immediately contact user '{username}' via an out-of-band communication channel "
                        f"to confirm authorization. Terminate active sessions and initiate an immediate password reset."
                    ),
                    related_event_ids=[fp for fp in related_fps if fp],
                    mitre_technique="T1110.001 - Brute Force: Password Guessing",
                    metadata={"preceding_failures": failures_count, "source_ip": source_ip},
                )
                if alert:
                    alerts.append(alert)

        return alerts

    # -----------------------------------------------------------------
    # Rule 3: Unusually High Login Frequency (Burst Rate)
    # -----------------------------------------------------------------

    def _detect_high_login_frequency(
        self, events: List[Tuple[Dict[str, Any], datetime]]
    ) -> List[ThreatAlert]:
        alerts: List[ThreatAlert] = []
        auth_events = [(ev, dt) for ev, dt in events if self._is_auth_event(ev)]
        window_seconds = self.config.high_frequency_window_minutes * 60.0
        threshold = self.config.high_frequency_threshold

        # Group by source IP
        by_ip: Dict[str, List[Tuple[Dict[str, Any], datetime]]] = {}
        for ev, dt in auth_events:
            ip = ev.get("source_ip")
            if ip:
                by_ip.setdefault(ip, []).append((ev, dt))

        for ip, ip_events in by_ip.items():
            if len(ip_events) < threshold:
                continue

            i = 0
            while i < len(ip_events):
                window = [ip_events[i]]
                j = i + 1
                while j < len(ip_events):
                    delta = (ip_events[j][1] - ip_events[i][1]).total_seconds()
                    if delta <= window_seconds:
                        window.append(ip_events[j])
                        j += 1
                    else:
                        break

                if len(window) >= threshold:
                    start_dt = window[0][1]
                    end_dt = window[-1][1]
                    duration_min = max(0.05, (end_dt - start_dt).total_seconds() / 60.0)
                    count = len(window)
                    rate = count / duration_min

                    alert = self._create_alert(
                        rule_name="Unusually High Login Frequency",
                        timestamp=end_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
                        entity_type="source_ip",
                        entity_value=ip,
                        severity="High",
                        evidence_strength="Strong",
                        explanation=(
                            f"Observed {count} authentication attempts from IP '{ip}' within "
                            f"{duration_min:.1f} minutes ({rate:.1f} attempts/minute). "
                            f"Volumetric burst velocity greatly exceeds standard human interaction limits."
                        ),
                        observed_value=f"{count} attempts in {duration_min:.1f} minutes ({rate:.1f} req/min)",
                        threshold=f">= {threshold} attempts in <= {self.config.high_frequency_window_minutes:.1f} minutes",
                        recommended_investigation_step=(
                            f"Check for automated scripts or credential spraying tool signatures from '{ip}'. "
                            f"Block the IP at the edge firewall if unverified."
                        ),
                        related_event_ids=[ev.get("fingerprint", "") for ev, _ in window if ev.get("fingerprint")],
                        mitre_technique="T1110.003 - Brute Force: Password Spraying",
                        metadata={"rate_per_min": round(rate, 1), "attempt_count": count},
                    )
                    if alert:
                        alerts.append(alert)
                    i = j
                else:
                    i += 1

        return alerts

    # -----------------------------------------------------------------
    # Rule 4: Unusual Login Hours (Baseline-governed)
    # -----------------------------------------------------------------

    def _detect_unusual_login_hours(
        self, events: List[Tuple[Dict[str, Any], datetime]]
    ) -> List[ThreatAlert]:
        alerts: List[ThreatAlert] = []
        auth_events = [(ev, dt) for ev, dt in events if self._is_auth_event(ev)]
        min_baseline = self.config.min_baseline_events_for_hours
        tolerance = self.config.unusual_hour_tolerance_hours

        for ev, dt in auth_events:
            username = ev.get("username", "").strip()
            if not username:
                continue

            profile = self.user_baselines.get(username)
            # Explicit constraint: ONLY alert when a valid behavioral baseline exists!
            if not profile or profile.total_events < min_baseline:
                continue

            distance = profile.hour_distance(dt.hour)
            if distance > tolerance:
                min_h = profile.min_hour
                max_h = profile.max_hour
                baseline_count = profile.total_events
                is_failed = self._is_failure(ev)
                severity = "High" if is_failed else "Medium"
                evidence_strength = "Strong" if baseline_count >= 15 else "Moderate"

                alert = self._create_alert(
                    rule_name="Unusual Login Hours",
                    timestamp=dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    entity_type="username",
                    entity_value=username,
                    severity=severity,
                    evidence_strength=evidence_strength,
                    explanation=(
                        f"User '{username}' authenticated at {dt.hour:02d}:{dt.minute:02d} UTC, "
                        f"which deviates by {distance:.1f} hours from their established active baseline "
                        f"[{min_h:02d}:00 - {max_h:02d}:00 UTC] (computed from {baseline_count} historical events)."
                    ),
                    observed_value=f"Login at {dt.hour:02d}:{dt.minute:02d} UTC (distance: {distance:.1f}h)",
                    threshold=f"Baseline active hours: [{min_h:02d}:00 - {max_h:02d}:00 UTC] (tolerance: {tolerance:.1f}h, {baseline_count} events)",
                    recommended_investigation_step=(
                        f"Verify if user '{username}' has approved overtime, traveling, or on-call duties. "
                        f"Confirm originating source IP '{ev.get('source_ip', '')}' matches recognized locations."
                    ),
                    related_event_ids=[ev.get("fingerprint", "")] if ev.get("fingerprint") else [],
                    mitre_technique="T1078 - Valid Accounts",
                    metadata={
                        "event_hour": dt.hour,
                        "baseline_min_hour": min_h,
                        "baseline_max_hour": max_h,
                        "baseline_count": baseline_count,
                    },
                )
                if alert:
                    alerts.append(alert)

        return alerts

    # -----------------------------------------------------------------
    # Rule 5: Suspicious Changes in Login Behavior (Baseline-governed)
    # -----------------------------------------------------------------

    def _detect_suspicious_behavioral_shifts(
        self, events: List[Tuple[Dict[str, Any], datetime]]
    ) -> List[ThreatAlert]:
        alerts: List[ThreatAlert] = []
        auth_events = [(ev, dt) for ev, dt in events if self._is_auth_event(ev)]
        min_history = self.config.min_baseline_events_for_behavior

        for ev, dt in auth_events:
            username = ev.get("username", "").strip()
            source_ip = ev.get("source_ip", "").strip()
            if not username or not source_ip:
                continue

            profile = self.user_baselines.get(username)
            # Explicit constraint: ONLY alert when sufficient historical evidence exists!
            if not profile or profile.total_events < min_history:
                continue

            # Check subnet novelty
            try:
                addr = ipaddress.ip_address(source_ip)
                event_subnet = str(ipaddress.ip_network(f"{source_ip}/24" if addr.version == 4 else f"{source_ip}/64", strict=False))
            except ValueError:
                event_subnet = source_ip

            # If user has an established history exclusively in known subnets, and an entirely new subnet appears:
            if event_subnet not in profile.seen_subnets and source_ip not in profile.seen_ips:
                baseline_count = profile.total_events
                known_subnets = sorted(profile.seen_subnets)

                alert = self._create_alert(
                    rule_name="Suspicious Login Behavioral Shift",
                    timestamp=dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    entity_type="username",
                    entity_value=username,
                    severity="High",
                    evidence_strength="Strong",
                    explanation=(
                        f"User '{username}' initiated a login from previously unobserved network subnet "
                        f"'{event_subnet}' (IP: {source_ip}). This represents an unprecedented deviation "
                        f"from established historical baseline of {baseline_count} logins across {known_subnets}."
                    ),
                    observed_value=f"New origin subnet '{event_subnet}' (IP: {source_ip})",
                    threshold=f"Established baseline across {baseline_count} logins in known subnets {known_subnets}",
                    recommended_investigation_step=(
                        f"Perform geolocation and reputation inspection on source IP '{source_ip}'. "
                        f"Verify if user '{username}' initiated this connection or if session hijacking occurred."
                    ),
                    related_event_ids=[ev.get("fingerprint", "")] if ev.get("fingerprint") else [],
                    mitre_technique="T1078.003 - Valid Accounts: Local Accounts",
                    metadata={
                        "new_subnet": event_subnet,
                        "known_subnets": known_subnets,
                        "baseline_count": baseline_count,
                    },
                )
                if alert:
                    alerts.append(alert)

        return alerts

    # -----------------------------------------------------------------
    # Helper Utilities
    # -----------------------------------------------------------------

    def _normalize_inputs(
        self, events: Iterable[Union[SecurityEvent, Dict[str, Any]]]
    ) -> List[Tuple[Dict[str, Any], datetime]]:
        normalized: List[Tuple[Dict[str, Any], datetime]] = []
        for item in events:
            if isinstance(item, SecurityEvent):
                d = item.to_dict()
            elif isinstance(item, dict):
                d = dict(item)
            else:
                continue

            ts_str = d.get("timestamp")
            if not ts_str:
                continue
            try:
                clean_ts = str(ts_str).strip().replace("Z", "+00:00")
                dt = datetime.fromisoformat(clean_ts)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                else:
                    dt = dt.astimezone(timezone.utc)
                normalized.append((d, dt))
            except Exception:
                continue
        return normalized

    def _is_auth_event(self, ev: Dict[str, Any]) -> bool:
        etype = str(ev.get("event_type", "")).strip().lower()
        return any(a in etype for a in self.AUTH_EVENT_TYPES)

    def _is_failure(self, ev: Dict[str, Any]) -> bool:
        status = str(ev.get("status", "")).strip().lower()
        return status in self.FAILURE_STATUSES or status.startswith("fail")

    def _is_success(self, ev: Dict[str, Any]) -> bool:
        status = str(ev.get("status", "")).strip().lower()
        return status in self.SUCCESS_STATUSES

    def _create_alert(
        self,
        rule_name: str,
        timestamp: str,
        entity_type: str,
        entity_value: str,
        severity: str,
        evidence_strength: str,
        explanation: str,
        observed_value: str,
        threshold: str,
        recommended_investigation_step: str,
        related_event_ids: List[str],
        mitre_technique: str,
        metadata: Dict[str, Any],
    ) -> Optional[ThreatAlert]:
        """
        Construct a ThreatAlert and enforce deduplication.
        """
        # Deterministic alert fingerprint prevents duplicate alerts during repeated processing
        raw_fp = f"{rule_name}|{entity_type}|{entity_value}|{timestamp}|{observed_value}"
        fp = hashlib.sha256(raw_fp.encode("utf-8")).hexdigest()

        if fp in self.seen_alert_fingerprints:
            return None

        self.seen_alert_fingerprints.add(fp)
        self._alert_counter += 1
        alert_id = f"CS-ALERT-{self._alert_counter:04d}"

        return ThreatAlert(
            alert_id=alert_id,
            rule_name=rule_name,
            timestamp=timestamp,
            entity_type=entity_type,
            entity_value=entity_value,
            severity=severity,
            evidence_strength=evidence_strength,
            explanation=explanation,
            observed_value=observed_value,
            threshold=threshold,
            recommended_investigation_step=recommended_investigation_step,
            related_event_ids=related_event_ids,
            mitre_technique=mitre_technique,
            fingerprint=fp,
            metadata=metadata,
        )
