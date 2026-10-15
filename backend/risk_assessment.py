"""
CyberShield AI — Threat Risk Assessment & Incident Correlation Engine

Correlates rule-based findings and machine-learning anomaly detections into
explainable, prioritized security incidents with transparent risk scoring.

Core Principles:
- 4-Tier Severity: Low (0-39), Medium (40-64), High (65-84), Critical (85-100).
- Strict separation of severity, confidence, and anomaly scores.
- Transparent additive risk factor calculation with human-readable explanations.
- Evidence-based correlation strictly linking related entities within temporal windows.
- Non-confirmation constraint: Never mark an incident confirmed based solely on an anomaly score.
- Deduplication of overlapping alerts into unified incident records.
- Prescriptive, safe, non-destructive defensive investigation recommendations.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import ipaddress
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple, Union

from backend.models.alert import ThreatAlert
from backend.models.anomaly import AnomalyFinding
from backend.models.event import IngestionResult, SecurityEvent
from backend.models.risk import ConfidenceLevel, CorrelatedIncident, RiskFactor, RiskSeverity


# =====================================================================
# Configuration
# =====================================================================

@dataclass
class RiskAssessmentConfig:
    """
    Configurable parameters for risk scoring, severity bands, and correlation windows.
    """
    correlation_window_minutes: float = 15.0

    # Severity score cutoffs
    critical_threshold: int = 85
    high_threshold: int = 65
    medium_threshold: int = 40

    # Base scores by rule severity
    rule_base_critical: int = 80
    rule_base_high: int = 65
    rule_base_medium: int = 40
    rule_base_low: int = 20
    anomaly_only_base: int = 30

    # Modifiers
    anomaly_high_boost: int = 15      # anomaly_score >= 0.70
    anomaly_medium_boost: int = 10    # anomaly_score >= 0.50
    anomaly_low_boost: int = 5        # anomaly present < 0.50
    privileged_entity_boost: int = 10
    external_ip_boost: int = 5
    multi_rule_boost: int = 10
    high_velocity_boost: int = 5


# =====================================================================
# Internal Evidence Cluster
# =====================================================================

@dataclass
class EvidenceCluster:
    """Working container aggregating telemetry and findings for an entity within a time window."""
    entity_type: str
    entity_value: str
    events: List[Tuple[Dict[str, Any], datetime]] = field(default_factory=list)
    rule_alerts: List[ThreatAlert] = field(default_factory=list)
    anomaly_findings: List[AnomalyFinding] = field(default_factory=list)

    @property
    def start_time(self) -> datetime:
        dts = [dt for _, dt in self.events]
        for a in self.rule_alerts:
            try:
                dts.append(datetime.fromisoformat(a.timestamp.replace("Z", "+00:00")))
            except Exception:
                pass
        for af in self.anomaly_findings:
            try:
                dts.append(datetime.fromisoformat(af.timestamp.replace("Z", "+00:00")))
            except Exception:
                pass
        return min(dts) if dts else datetime.now(timezone.utc)

    @property
    def end_time(self) -> datetime:
        dts = [dt for _, dt in self.events]
        for a in self.rule_alerts:
            try:
                dts.append(datetime.fromisoformat(a.timestamp.replace("Z", "+00:00")))
            except Exception:
                pass
        for af in self.anomaly_findings:
            try:
                dts.append(datetime.fromisoformat(af.timestamp.replace("Z", "+00:00")))
            except Exception:
                pass
        return max(dts) if dts else datetime.now(timezone.utc)


# =====================================================================
# Threat Risk Assessment Engine
# =====================================================================

class ThreatRiskEngine:
    """
    Engine combining rule evidence, ML anomaly findings, and contextual telemetry
    into prioritized, explainable CorrelatedIncident objects.
    """

    PRIVILEGED_USERS = {
        "root", "admin", "administrator", "system_svc", "daemon", "wheel", "superuser"
    }

    def __init__(self, config: Optional[RiskAssessmentConfig] = None):
        self.config = config or RiskAssessmentConfig()
        self.seen_incident_fingerprints: Set[str] = set()
        self._incident_counter: int = 0

    def reset(self) -> None:
        """Clear incident fingerprint cache."""
        self.seen_incident_fingerprints.clear()
        self._incident_counter = 0

    # -----------------------------------------------------------------
    # Primary Assessment & Correlation Entrypoint
    # -----------------------------------------------------------------

    def assess_and_correlate(
        self,
        events: Optional[Union[IngestionResult, Iterable[Union[SecurityEvent, Dict[str, Any]]]]] = None,
        rule_alerts: Optional[Iterable[ThreatAlert]] = None,
        anomaly_findings: Optional[Iterable[AnomalyFinding]] = None,
    ) -> List[CorrelatedIncident]:
        """
        Correlate evidence and evaluate threat risk scores.
        
        Args:
            events: Normalized telemetry events.
            rule_alerts: Detected rule-based ThreatAlert findings.
            anomaly_findings: Detected machine-learning AnomalyFinding objects.
            
        Returns:
            Prioritized list of CorrelatedIncident findings sorted by risk score.
        """
        norm_events = self._normalize_events(events)
        alerts_list = list(rule_alerts or [])
        anomalies_list = list(anomaly_findings or [])

        # 1. Cluster evidence strictly by entity and temporal proximity
        clusters = self._cluster_evidence(norm_events, alerts_list, anomalies_list)

        incidents: List[CorrelatedIncident] = []

        # 2. Score and synthesize each cluster into an incident
        for cluster in clusters:
            incident = self._evaluate_cluster(cluster)
            if incident:
                incidents.append(incident)

        # 3. Prioritize: Sort descending by composite_risk_score, then confidence
        incidents.sort(
            key=lambda inc: (inc.composite_risk_score, 1 if inc.severity == RiskSeverity.CRITICAL.value else 0, inc.confidence),
            reverse=True,
        )

        return incidents

    # -----------------------------------------------------------------
    # Evidence Clustering
    # -----------------------------------------------------------------

    @staticmethod
    def _normalize_entity_type(etype: str) -> str:
        cleaned = str(etype or "").strip().lower()
        if cleaned in {"user", "username", "account", "actor"}:
            return "username"
        if cleaned in {"ip", "source_ip", "src_ip", "client_ip"}:
            return "source_ip"
        return "username"

    def _cluster_evidence(
        self,
        events: List[Tuple[Dict[str, Any], datetime]],
        alerts: List[ThreatAlert],
        anomalies: List[AnomalyFinding],
    ) -> List[EvidenceCluster]:
        """
        Group events and findings strictly by entity and time proximity.
        Unrelated entities and temporally distant events remain independent.
        """
        entity_buckets: Dict[str, List[Tuple[str, Any, datetime]]] = {}

        for ev, dt in events:
            user = str(ev.get("username") or "").strip()
            ip = str(ev.get("source_ip") or "").strip()
            if user:
                entity_buckets.setdefault(f"username:{user}", []).append(("event", (ev, dt), dt))
            if ip and ip != "127.0.0.1":
                entity_buckets.setdefault(f"source_ip:{ip}", []).append(("event", (ev, dt), dt))

        for alert in alerts:
            etype = self._normalize_entity_type(alert.entity_type)
            key = f"{etype}:{alert.entity_value.strip()}"
            dt = self._parse_dt(alert.timestamp)
            entity_buckets.setdefault(key, []).append(("alert", alert, dt))

        for af in anomalies:
            entity_val = str(af.entity or "").strip()
            etype = "source_ip" if self._is_valid_ip(entity_val) else "username"
            key = f"{etype}:{entity_val}"
            dt = self._parse_dt(af.timestamp)
            entity_buckets.setdefault(key, []).append(("anomaly", af, dt))

        # Temporal sub-clustering within each entity
        clusters: List[EvidenceCluster] = []
        window_seconds = self.config.correlation_window_minutes * 60.0

        for entity_key, items in entity_buckets.items():
            if not items:
                continue
            entity_type, entity_value = entity_key.split(":", 1)
            # Sort items chronologically
            items.sort(key=lambda x: x[2])

            current_cluster = EvidenceCluster(entity_type=entity_type, entity_value=entity_value)
            cluster_start_dt = items[0][2]

            for item_type, item_obj, item_dt in items:
                delta = (item_dt - cluster_start_dt).total_seconds()
                if delta <= window_seconds:
                    self._add_to_cluster(current_cluster, item_type, item_obj)
                else:
                    # Finalize current cluster only if it contains actionable findings
                    if current_cluster.rule_alerts or current_cluster.anomaly_findings:
                        clusters.append(current_cluster)
                    # Start new cluster
                    current_cluster = EvidenceCluster(entity_type=entity_type, entity_value=entity_value)
                    cluster_start_dt = item_dt
                    self._add_to_cluster(current_cluster, item_type, item_obj)

            if current_cluster.rule_alerts or current_cluster.anomaly_findings:
                clusters.append(current_cluster)

        return clusters

    @staticmethod
    def _add_to_cluster(cluster: EvidenceCluster, item_type: str, item_obj: Any) -> None:
        if item_type == "event":
            cluster.events.append(item_obj)
        elif item_type == "alert":
            if item_obj not in cluster.rule_alerts:
                cluster.rule_alerts.append(item_obj)
        elif item_type == "anomaly":
            if item_obj not in cluster.anomaly_findings:
                cluster.anomaly_findings.append(item_obj)

    # -----------------------------------------------------------------
    # Cluster Evaluation & Transparent Scoring
    # -----------------------------------------------------------------

    def _evaluate_cluster(self, cluster: EvidenceCluster) -> Optional[CorrelatedIncident]:
        """
        Evaluate risk factors, calculate composite score, assign severity,
        and construct an explainable CorrelatedIncident.
        """
        has_rules = len(cluster.rule_alerts) > 0
        has_anomalies = len(cluster.anomaly_findings) > 0

        # Discard clusters that contain neither rule detections nor anomalies
        if not has_rules and not has_anomalies:
            return None

        risk_factors: List[RiskFactor] = []
        score_accumulator: int = 0

        # -------------------------------------------------------------
        # 1. Base Score from Rule Findings
        # -------------------------------------------------------------
        max_rule_severity = "Low"
        if has_rules:
            # Check highest rule severity
            severities = [a.severity.title() for a in cluster.rule_alerts]
            if "Critical" in severities:
                max_rule_severity = "Critical"
                base_delta = self.config.rule_base_critical
            elif "High" in severities:
                max_rule_severity = "High"
                base_delta = self.config.rule_base_high
            elif "Medium" in severities:
                max_rule_severity = "Medium"
                base_delta = self.config.rule_base_medium
            else:
                max_rule_severity = "Low"
                base_delta = self.config.rule_base_low

            rule_titles = ", ".join(sorted(set(a.rule_name for a in cluster.rule_alerts)))
            score_accumulator += base_delta
            risk_factors.append(
                RiskFactor(
                    factor_name="Rule Evidence Baseline",
                    weight=0.50,
                    observed_evidence=f"Highest rule severity: {max_rule_severity} ({rule_titles})",
                    score_delta=base_delta,
                    explanation=f"Base risk established from confirmed deterministic signature match '{rule_titles}'.",
                )
            )

            # Multi-rule synergy boost
            unique_rules = set(a.rule_name for a in cluster.rule_alerts)
            if len(unique_rules) > 1:
                boost = self.config.multi_rule_boost
                score_accumulator += boost
                risk_factors.append(
                    RiskFactor(
                        factor_name="Multi-Rule Correlation",
                        weight=0.10,
                        observed_evidence=f"{len(unique_rules)} distinct rules triggered: {sorted(unique_rules)}",
                        score_delta=boost,
                        explanation="Compound risk elevated due to multiple distinct attack indicators matching the same entity.",
                    )
                )
        else:
            # ML Anomaly Only (No rule match)
            base_delta = self.config.anomaly_only_base
            score_accumulator += base_delta
            risk_factors.append(
                RiskFactor(
                    factor_name="Statistical Outlier Baseline",
                    weight=0.30,
                    observed_evidence=f"ML Anomaly detected without matching deterministic attack rules",
                    score_delta=base_delta,
                    explanation="Baseline risk derived strictly from statistical deviation identified by Isolation Forest.",
                )
            )

        # -------------------------------------------------------------
        # 2. Machine Learning Anomaly Score Contribution
        # -------------------------------------------------------------
        max_anomaly_score: Optional[float] = None
        if has_anomalies:
            max_anomaly_score = max(af.anomaly_score for af in cluster.anomaly_findings)
            if max_anomaly_score >= 0.70:
                anomaly_delta = self.config.anomaly_high_boost
            elif max_anomaly_score >= 0.50:
                anomaly_delta = self.config.anomaly_medium_boost
            else:
                anomaly_delta = self.config.anomaly_low_boost

            score_accumulator += anomaly_delta
            risk_factors.append(
                RiskFactor(
                    factor_name="Machine Learning Anomaly Score",
                    weight=0.20,
                    observed_evidence=f"Peak Isolation Forest anomaly score: {max_anomaly_score:.2f}",
                    score_delta=anomaly_delta,
                    explanation=f"Multidimensional statistical outlier score ({max_anomaly_score:.2f}) corroborated threat presence.",
                )
            )

        # -------------------------------------------------------------
        # 3. Entity & Asset Criticality
        # -------------------------------------------------------------
        is_privileged = False
        target_entity = cluster.entity_value.lower()
        if cluster.entity_type == "username" and target_entity in self.PRIVILEGED_USERS:
            is_privileged = True
        else:
            # Check events within cluster
            for ev, _ in cluster.events:
                if str(ev.get("username", "")).lower() in self.PRIVILEGED_USERS:
                    is_privileged = True
                    break

        if is_privileged:
            boost = self.config.privileged_entity_boost
            score_accumulator += boost
            risk_factors.append(
                RiskFactor(
                    factor_name="Privileged Identity Target",
                    weight=0.15,
                    observed_evidence=f"Target involves administrative/privileged identity: '{cluster.entity_value}'",
                    score_delta=boost,
                    explanation="Targeting high-privilege credentials increases blast radius and potential operational impact.",
                )
            )

        # -------------------------------------------------------------
        # 4. Network Origin
        # -------------------------------------------------------------
        is_external = False
        if cluster.entity_type == "source_ip" and self._is_external_ip(cluster.entity_value):
            is_external = True
        else:
            for ev, _ in cluster.events:
                if self._is_external_ip(str(ev.get("source_ip", ""))):
                    is_external = True
                    break

        if is_external:
            boost = self.config.external_ip_boost
            score_accumulator += boost
            risk_factors.append(
                RiskFactor(
                    factor_name="External Network Origin",
                    weight=0.05,
                    observed_evidence="Activity originates from untrusted external/public IP address",
                    score_delta=boost,
                    explanation="Ingress from public internet space elevates threat probability over internal traffic.",
                )
            )

        # -------------------------------------------------------------
        # 5. Attack Velocity & Event Count
        # -------------------------------------------------------------
        total_events = len(cluster.events)
        if total_events >= 5:
            boost = self.config.high_velocity_boost
            score_accumulator += boost
            risk_factors.append(
                RiskFactor(
                    factor_name="Event Velocity Burst",
                    weight=0.05,
                    observed_evidence=f"{total_events} events correlated in {self.config.correlation_window_minutes:.0f}m window",
                    score_delta=boost,
                    explanation="Sustained burst velocity indicates automated execution or focused operator activity.",
                )
            )

        # -------------------------------------------------------------
        # 6. Strict Non-Confirmation Constraint & Confidence
        # -------------------------------------------------------------
        # Requirement: Do not mark an incident confirmed based solely on an anomaly score!
        if not has_rules and has_anomalies:
            is_confirmed = False
            confirmation_status = "Unconfirmed Anomaly"
            confidence = 0.40
            confidence_level = ConfidenceLevel.LOW.value
            # Cap score so unconfirmed anomaly never reaches Critical or High
            composite_risk_score = min(55, score_accumulator)
        else:
            is_confirmed = True
            confirmation_status = "Corroborated Threat"
            if has_rules and has_anomalies:
                confidence = 0.95
                confidence_level = ConfidenceLevel.HIGH.value
            elif max_rule_severity in {"Critical", "High"}:
                confidence = 0.85
                confidence_level = ConfidenceLevel.HIGH.value
            else:
                confidence = 0.65
                confidence_level = ConfidenceLevel.MEDIUM.value
            composite_risk_score = min(100, max(0, score_accumulator))

        # -------------------------------------------------------------
        # 7. Severity Assignment (Separate from Confidence & Anomaly Score)
        # -------------------------------------------------------------
        if composite_risk_score >= self.config.critical_threshold:
            severity = RiskSeverity.CRITICAL.value
        elif composite_risk_score >= self.config.high_threshold:
            severity = RiskSeverity.HIGH.value
        elif composite_risk_score >= self.config.medium_threshold:
            severity = RiskSeverity.MEDIUM.value
        else:
            severity = RiskSeverity.LOW.value

        # Build transparent explanation narrative
        factor_summaries = "; ".join(f"{f.factor_name} (+{f.score_delta})" for f in risk_factors)
        risk_explanation = (
            f"Assigned {severity} severity (Composite Risk Score: {composite_risk_score}/100, "
            f"Confidence: {confidence:.2f} [{confidence_level}]). "
            f"Calculation breakdown: {factor_summaries}. Status: {confirmation_status}."
        )

        # Gather related IDs and deduplicated attributes
        related_ids: Set[str] = set()
        for ev, _ in cluster.events:
            if ev.get("fingerprint"):
                related_ids.add(ev["fingerprint"])
        for a in cluster.rule_alerts:
            related_ids.update(a.related_event_ids)
        for af in cluster.anomaly_findings:
            if af.event_fingerprint:
                related_ids.add(af.event_fingerprint)

        rule_names = sorted(set(a.rule_name for a in cluster.rule_alerts))
        mitre_tags = sorted(set(a.mitre_technique for a in cluster.rule_alerts))

        # Title construction
        if rule_names:
            title = f"{' + '.join(rule_names)} on {cluster.entity_value}"
        else:
            title = f"Unconfirmed Statistical Anomaly on {cluster.entity_value}"

        # Prescriptive safe defensive recommendations
        defensive_steps = self._generate_safe_recommendations(
            cluster.entity_type, cluster.entity_value, rule_names, is_confirmed
        )

        # Deterministic deduplication fingerprint
        start_iso = cluster.start_time.strftime("%Y-%m-%dT%H:%M:%SZ")
        end_iso = cluster.end_time.strftime("%Y-%m-%dT%H:%M:%SZ")
        raw_fp = f"{cluster.entity_type}|{cluster.entity_value}|{start_iso}|{end_iso}|{'-'.join(rule_names)}"
        fp = hashlib.sha256(raw_fp.encode("utf-8")).hexdigest()

        if fp in self.seen_incident_fingerprints:
            return None
        self.seen_incident_fingerprints.add(fp)

        self._incident_counter += 1
        incident_id = f"CS-INCIDENT-{self._incident_counter:04d}"

        return CorrelatedIncident(
            incident_id=incident_id,
            title=title,
            entity_type=cluster.entity_type,
            entity_value=cluster.entity_value,
            severity=severity,
            confidence=round(confidence, 2),
            confidence_level=confidence_level,
            anomaly_score=round(max_anomaly_score, 4) if max_anomaly_score is not None else None,
            composite_risk_score=composite_risk_score,
            is_confirmed=is_confirmed,
            confirmation_status=confirmation_status,
            first_seen=start_iso,
            last_seen=end_iso,
            event_count=max(len(related_ids), total_events, 1),
            related_event_ids=sorted(related_ids),
            triggered_rule_names=rule_names,
            mitre_techniques=mitre_tags,
            risk_breakdown=risk_factors,
            risk_explanation=risk_explanation,
            defensive_recommendations=defensive_steps,
            fingerprint=fp,
            metadata={
                "max_rule_severity": max_rule_severity,
                "is_privileged": is_privileged,
                "is_external": is_external,
            },
        )

    # -----------------------------------------------------------------
    # Safe Defensive Recommendations Generator
    # -----------------------------------------------------------------

    @staticmethod
    def _generate_safe_recommendations(
        entity_type: str, entity_value: str, rule_names: List[str], is_confirmed: bool
    ) -> List[str]:
        recommendations: List[str] = []

        if not is_confirmed:
            recommendations.append(
                f"Verify baseline activity for {entity_type} '{entity_value}'. Do NOT block access based solely on anomaly score."
            )
            recommendations.append("Review contextual audit logs to determine if authorized non-standard activity took place.")
            return recommendations

        if any("Success Following Repeated Failures" in r for r in rule_names):
            recommendations.append(
                f"Contact user '{entity_value}' immediately via out-of-band communication to verify session legitimacy."
            )
            recommendations.append("Terminate active web and SSH sessions for the account and enforce an immediate credential reset.")
            recommendations.append("Audit all administrative and API actions performed immediately following the successful login.")

        if any("Repeated Failed Logins" in r for r in rule_names):
            recommendations.append(f"Inspect authentication logs originating from '{entity_value}' for targeted usernames.")
            recommendations.append("Enforce temporary edge rate-limiting or challenge-response (CAPTCHA) on authentication ingress.")

        if any("Unusually High Login Frequency" in r for r in rule_names):
            recommendations.append("Inspect source telemetry for signatures of automated password spraying or credential stuffing tools.")
            recommendations.append("Temporarily restrict connection concurrency from the originating IP address.")

        if any("Suspicious Login Behavioral Shift" in r for r in rule_names):
            recommendations.append(f"Verify if user '{entity_value}' recently traveled or connected via an approved corporate VPN.")
            recommendations.append("Review IP threat intelligence reputation and autonomous system (ASN) metadata.")

        if not recommendations:
            recommendations.append(f"Audit recent telemetry for entity '{entity_value}' to determine operational context.")
            recommendations.append("Preserve relevant system logs for potential forensic timeline reconstruction.")

        return recommendations

    # -----------------------------------------------------------------
    # Helper Methods
    # -----------------------------------------------------------------

    def _normalize_events(
        self, events: Optional[Union[IngestionResult, Iterable[Union[SecurityEvent, Dict[str, Any]]]]]
    ) -> List[Tuple[Dict[str, Any], datetime]]:
        if events is None:
            return []
        if isinstance(events, IngestionResult):
            raw_input = events.events
        else:
            raw_input = events

        normalized: List[Tuple[Dict[str, Any], datetime]] = []
        for item in raw_input:
            if isinstance(item, SecurityEvent):
                d = item.to_dict()
            elif isinstance(item, dict):
                d = dict(item)
            else:
                continue

            dt = self._parse_dt(d.get("timestamp"))
            normalized.append((d, dt))
        return normalized

    @staticmethod
    def _parse_dt(ts_val: Any) -> datetime:
        if isinstance(ts_val, datetime):
            return ts_val if ts_val.tzinfo else ts_val.replace(tzinfo=timezone.utc)
        try:
            clean = str(ts_val).strip().replace("Z", "+00:00")
            dt = datetime.fromisoformat(clean)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except Exception:
            return datetime.now(timezone.utc)

    @staticmethod
    def _is_valid_ip(val: str) -> bool:
        try:
            ipaddress.ip_address(val.strip())
            return True
        except Exception:
            return False

    @classmethod
    def _is_external_ip(cls, val: str) -> bool:
        try:
            addr = ipaddress.ip_address(val.strip())
            if addr.is_loopback:
                return False
            # Check standard RFC 1918 private subnets
            private_networks = [
                ipaddress.ip_network("10.0.0.0/8"),
                ipaddress.ip_network("172.16.0.0/12"),
                ipaddress.ip_network("192.168.0.0/16"),
            ]
            return not any(addr in net for net in private_networks)
        except Exception:
            return False
