/**
 * CyberShield AI — Threat Configuration Constants
 * Official Problem: ABCS-01
 */

export const SEVERITY_CONFIG = {
  Critical: {
    label: 'Critical',
    bg: 'bg-red-500/10',
    border: 'border-red-500/30',
    text: 'text-red-400',
    badge: 'bg-red-500/20 text-red-300 border-red-500/30',
    dot: 'bg-red-500',
    color: '#ef4444',
    sla: '< 15 mins (Immediate)',
  },
  High: {
    label: 'High',
    bg: 'bg-orange-500/10',
    border: 'border-orange-500/30',
    text: 'text-orange-400',
    badge: 'bg-orange-500/20 text-orange-300 border-orange-500/30',
    dot: 'bg-orange-500',
    color: '#f97316',
    sla: '< 1 hour',
  },
  Medium: {
    label: 'Medium',
    bg: 'bg-yellow-500/10',
    border: 'border-yellow-500/30',
    text: 'text-yellow-400',
    badge: 'bg-yellow-500/20 text-yellow-300 border-yellow-500/30',
    dot: 'bg-yellow-500',
    color: '#eab308',
    sla: '< 4 hours',
  },
  Low: {
    label: 'Low',
    bg: 'bg-emerald-500/10',
    border: 'border-emerald-500/30',
    text: 'text-emerald-400',
    badge: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30',
    dot: 'bg-emerald-500',
    color: '#10b981',
    sla: 'Next business day',
  },
};

export const STATUS_CONFIG = {
  Open: {
    label: 'Open',
    badge: 'bg-amber-500/20 text-amber-300 border-amber-500/30',
    dot: 'bg-amber-400',
  },
  Investigating: {
    label: 'Investigating',
    badge: 'bg-blue-500/20 text-blue-300 border-blue-500/30',
    dot: 'bg-blue-400',
  },
  Resolved: {
    label: 'Resolved',
    badge: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30',
    dot: 'bg-emerald-400',
  },
  Dismissed: {
    label: 'Dismissed',
    badge: 'bg-slate-500/20 text-slate-400 border-slate-500/30',
    dot: 'bg-slate-400',
  },
};

export const DETECTION_RULES = [
  {
    name: 'Repeated Failed Logins',
    category: 'Brute-force login attempts',
    threshold: '≥ 5 failures in ≤ 10 mins',
    mitre: 'T1110.001 - Password Guessing',
    type: 'Rule-Based',
    severity: 'High',
  },
  {
    name: 'Success Following Repeated Failures',
    category: 'Compromised Account Takeover',
    threshold: '≥ 3 failures followed by success in ≤ 10 mins',
    mitre: 'T1110.001 - Password Guessing',
    type: 'Rule-Based',
    severity: 'Critical',
  },
  {
    name: 'Unusually High Login Frequency',
    category: 'Volumetric Spray Burst',
    threshold: '≥ 10 attempts in ≤ 2 mins',
    mitre: 'T1110.003 - Password Spraying',
    type: 'Rule-Based',
    severity: 'High',
  },
  {
    name: 'Unusual Login Hours',
    category: 'Behavioral Baseline Anomaly',
    threshold: '> 2 hours deviation from user profile',
    mitre: 'T1078 - Valid Accounts',
    type: 'Behavioral',
    severity: 'Medium',
  },
  {
    name: 'Suspicious Behavioral Shift',
    category: 'Unfamiliar Ingress Subnet',
    threshold: 'New external subnet for established account',
    mitre: 'T1078.003 - Local Accounts',
    type: 'Behavioral',
    severity: 'High',
  },
  {
    name: 'Isolation Forest Anomaly',
    category: 'Statistical Outlier Finding',
    threshold: 'Isolation tree contamination outlier',
    mitre: 'T1078 - Defense Evasion',
    type: 'Machine Learning',
    severity: 'Medium',
  },
];
