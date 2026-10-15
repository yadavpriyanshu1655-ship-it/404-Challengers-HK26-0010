/**
 * CyberShield AI — Benchmark Synthetic Telemetry & Ground Truth
 * Explicitly designated as synthetic sample benchmark data for ABCS-01.
 */

export const IS_SYNTHETIC_BENCHMARK = true;
export const DATA_DISCLAIMER = "Synthetic security telemetry generated for ABCS-01 algorithmic verification and benchmark evaluation.";

export const SYNTHETIC_DASHBOARD_STATS = {
  processed_events: 18,
  total_alerts: 5,
  open_alerts: 4,
  high_critical_alerts: 3,
  ml_anomaly_count: 2,
  severity_distribution: {
    Critical: 1,
    High: 2,
    Medium: 1,
    Low: 1,
  },
  status_distribution: {
    Open: 4,
    Investigating: 1,
    Resolved: 0,
    Dismissed: 0,
  },
  event_trend: [
    { date: '2026-10-09', count: 12 },
    { date: '2026-10-10', count: 18 },
    { date: '2026-10-11', count: 15 },
    { date: '2026-10-12', count: 24 },
    { date: '2026-10-13', count: 35 },
    { date: '2026-10-14', count: 48 },
    { date: '2026-10-15', count: 62 },
  ],
  top_source_ips: [
    { entity: '203.0.113.100', count: 4 },
    { entity: '198.51.100.45', count: 2 },
    { entity: '192.0.2.21', count: 2 },
    { entity: '192.168.1.50', count: 1 },
  ],
  top_targeted_users: [
    { entity: 'admin', count: 8 },
    { entity: 'root', count: 5 },
    { entity: 'bob', count: 3 },
    { entity: 'carol', count: 1 },
  ],
};

export const SYNTHETIC_ALERTS = [
  {
    id: 1,
    alert_id: "CS-INCIDENT-0001",
    timestamp: "2026-10-15T09:06:00Z",
    source_ip: "192.0.2.21",
    entity_type: "source_ip",
    entity_value: "192.0.2.21",
    category: "Success after repeated failures",
    severity: "Critical",
    risk_score: 95,
    confidence: 0.95,
    anomaly_score: 0.82,
    is_confirmed: true,
    description: "A successful login followed 5 consecutive failed authentications from 192.0.2.21 within a 5-minute window, strongly indicating password guessing compromise.",
    evidence: [
      "Rule triggered: Success Following Repeated Failures (observed: 5 failed preceding logins, threshold: 3).",
      "Affected target account: 'bob' via /auth/login.",
      "High ML anomaly score (0.82) confirms atypical authentication velocity and pattern.",
      "Earliest failure: 2026-10-15T09:01:00Z | Compromise success: 2026-10-15T09:06:00Z."
    ],
    recommendation: "Immediately terminate active session tokens for user 'bob', enforce out-of-band identity verification, revoke temporary credentials, and check egress activity.",
    mitre_technique: "T1110.001 - Brute Force: Password Guessing",
    status: "Open",
    fingerprint: "synth-inc-0001-success-after-fail",
    related_event_ids: ["fp_0901", "fp_0902", "fp_0903", "fp_0904", "fp_0905", "fp_0906"]
  },
  {
    id: 2,
    alert_id: "CS-INCIDENT-0002",
    timestamp: "2026-10-15T09:05:00Z",
    source_ip: "192.0.2.21",
    entity_type: "source_ip",
    entity_value: "192.0.2.21",
    category: "Brute-force login attempts",
    severity: "High",
    risk_score: 85,
    confidence: 0.88,
    anomaly_score: 0.74,
    is_confirmed: true,
    description: "5 failed authentications originated from source IP 192.0.2.21 within 4 minutes, exceeding brute-force security threshold.",
    evidence: [
      "Rule triggered: Repeated Failed Logins (observed: 5 failures, threshold: 5 within 10m).",
      "Target accounts targeted: 'bob'.",
      "Consistent rapid-fire retry interval averaging 60 seconds per attempt."
    ],
    recommendation: "Apply automated ingress rate-limiting at perimeter firewall for IP 192.0.2.21 and inspect threat intelligence reputations.",
    mitre_technique: "T1110.001 - Brute Force",
    status: "Investigating",
    fingerprint: "synth-inc-0002-bruteforce",
    related_event_ids: ["fp_0901", "fp_0902", "fp_0903", "fp_0904", "fp_0905"]
  },
  {
    id: 3,
    alert_id: "CS-INCIDENT-0003",
    timestamp: "2026-10-15T09:12:00Z",
    source_ip: "203.0.113.100",
    entity_type: "username",
    entity_value: "admin",
    category: "High login frequency burst",
    severity: "High",
    risk_score: 75,
    confidence: 0.82,
    anomaly_score: 0.68,
    is_confirmed: true,
    description: "Volumetric authentication burst detected: 12 login attempts in 1.5 minutes targeting administrative credentials.",
    evidence: [
      "Rule triggered: Unusually High Login Frequency (observed: 12 attempts, threshold: 10 in 2m).",
      "Execution rate exceeds human interaction threshold (> 0.13 req/sec).",
      "Originates from non-internal external IP 203.0.113.100."
    ],
    recommendation: "Implement adaptive CAPTCHA or exponential backoff on administrative login endpoint and review perimeter WAF policies.",
    mitre_technique: "T1110.003 - Password Spraying",
    status: "Open",
    fingerprint: "synth-inc-0003-high-frequency",
    related_event_ids: ["fp_admin_burst"]
  },
  {
    id: 4,
    alert_id: "CS-INCIDENT-0004",
    timestamp: "2026-10-15T03:15:00Z",
    source_ip: "192.168.1.10",
    entity_type: "username",
    entity_value: "alice",
    category: "Unusual login hours",
    severity: "Medium",
    risk_score: 52,
    confidence: 0.65,
    anomaly_score: 0.58,
    is_confirmed: true,
    description: "Authentication occurred at 03:15 UTC, deviating by 5.5 hours from established user behavioral baseline (standard hours: 08:00 - 18:00 UTC).",
    evidence: [
      "Baseline established with 15 prior historical logins.",
      "Observed time 03:15 UTC vs. established operating window.",
      "Authentication was successful but requires analyst verification."
    ],
    recommendation: "Verify off-hours activity with account owner out-of-band and verify whether travel or maintenance schedule was authorized.",
    mitre_technique: "T1078 - Valid Accounts",
    status: "Open",
    fingerprint: "synth-inc-0004-unusual-hours",
    related_event_ids: ["fp_alice_0315"]
  },
  {
    id: 5,
    alert_id: "CS-INCIDENT-0005",
    timestamp: "2026-10-15T09:20:00Z",
    source_ip: "198.51.100.45",
    entity_type: "username",
    entity_value: "carol",
    category: "Unconfirmed Statistical Anomaly on carol",
    severity: "Low",
    risk_score: 35,
    confidence: 0.40,
    anomaly_score: 0.79,
    is_confirmed: false,
    description: "Isolation Forest flagged multidimensional anomaly (unusual payload transfer + non-standard resource endpoint).",
    evidence: [
      "Isolation Forest calibrated score: 0.79 (outlier threshold: 0.50).",
      "Contributing factors: Elevated payload size (16,384 bytes) to sensitive resource /admin/export.",
      "Strict Non-Confirmation Rule: Statistical anomaly alone does not confirm malicious attack intent."
    ],
    recommendation: "Review data transfer destination and verify whether scheduled reporting service was executed.",
    mitre_technique: "T1078 - Defense Evasion",
    status: "Open",
    fingerprint: "synth-inc-0005-ml-outlier",
    related_event_ids: ["fp_carol_export"]
  }
];

export const SYNTHETIC_EVENTS = [
  { id: 1, timestamp: "2026-10-15T09:00:00Z", source_ip: "192.0.2.10", destination_ip: "10.0.0.1", username: "alice", event_type: "login", status: "success", resource: "/auth/login", payload_size: 128 },
  { id: 2, timestamp: "2026-10-15T09:01:00Z", source_ip: "192.0.2.21", destination_ip: "10.0.0.1", username: "bob", event_type: "login", status: "failed", resource: "/auth/login", payload_size: 128 },
  { id: 3, timestamp: "2026-10-15T09:02:00Z", source_ip: "192.0.2.21", destination_ip: "10.0.0.1", username: "bob", event_type: "login", status: "failed", resource: "/auth/login", payload_size: 128 },
  { id: 4, timestamp: "2026-10-15T09:03:00Z", source_ip: "192.0.2.21", destination_ip: "10.0.0.1", username: "bob", event_type: "login", status: "failed", resource: "/auth/login", payload_size: 128 },
  { id: 5, timestamp: "2026-10-15T09:04:00Z", source_ip: "192.0.2.21", destination_ip: "10.0.0.1", username: "bob", event_type: "login", status: "failed", resource: "/auth/login", payload_size: 128 },
  { id: 6, timestamp: "2026-10-15T09:05:00Z", source_ip: "192.0.2.21", destination_ip: "10.0.0.1", username: "bob", event_type: "login", status: "failed", resource: "/auth/login", payload_size: 128 },
  { id: 7, timestamp: "2026-10-15T09:06:00Z", source_ip: "192.0.2.21", destination_ip: "10.0.0.1", username: "bob", event_type: "login", status: "success", resource: "/auth/login", payload_size: 128 },
  { id: 8, timestamp: "2026-10-15T09:08:00Z", source_ip: "192.0.2.32", destination_ip: "10.0.0.1", username: "carol", event_type: "login", status: "success", resource: "/auth/login", payload_size: 128 },
  { id: 9, timestamp: "2026-10-15T09:09:00Z", source_ip: "203.0.113.100", destination_ip: "10.0.0.1", username: "admin", event_type: "login", status: "failed", resource: "/auth/login", payload_size: 128 },
  { id: 10, timestamp: "2026-10-15T09:10:00Z", source_ip: "203.0.113.100", destination_ip: "10.0.0.1", username: "admin", event_type: "login", status: "failed", resource: "/auth/login", payload_size: 128 },
  { id: 11, timestamp: "2026-10-15T09:11:00Z", source_ip: "203.0.113.100", destination_ip: "10.0.0.1", username: "admin", event_type: "login", status: "failed", resource: "/auth/login", payload_size: 128 },
  { id: 12, timestamp: "2026-10-15T09:12:00Z", source_ip: "203.0.113.100", destination_ip: "10.0.0.1", username: "admin", event_type: "login", status: "failed", resource: "/auth/login", payload_size: 128 },
  { id: 13, timestamp: "2026-10-15T09:20:00Z", source_ip: "198.51.100.45", destination_ip: "10.0.0.5", username: "carol", event_type: "file_access", status: "success", resource: "/admin/export", payload_size: 16384 },
];
