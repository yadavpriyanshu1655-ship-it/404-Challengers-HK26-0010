"""
CyberShield AI — Feature Engineering & Preprocessing Pipeline

Extracts, normalizes, and encodes meaningful telemetry features
from standardized security events for machine-learning anomaly detection.
"""

from __future__ import annotations

from datetime import datetime, timezone
import ipaddress
import math
from typing import Any, Dict, Iterable, List, Union

import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder, StandardScaler

from backend.models.event import SecurityEvent


class SecurityFeatureExtractor:
    """
    Transforms raw/normalized security events into a structured feature matrix
    suitable for Scikit-learn pipelines.
    """

    PRIVILEGED_USERS = {
        "root", "admin", "administrator", "system_svc", "daemon", "wheel", "superuser"
    }
    PRIVILEGED_RESOURCES = {
        "/etc/shadow", "/etc/passwd", "/root", "sudo", "/usr/bin/sudo",
        "/admin", "/api/admin", "/auth/keys", "/system/config"
    }

    NUMERIC_COLUMNS = [
        "hour_sin",
        "hour_cos",
        "day_of_week",
        "is_weekend",
        "log_payload_size",
        "is_failure",
        "is_privileged_user",
        "is_privileged_resource",
        "is_external_ip",
    ]

    CATEGORICAL_COLUMNS = [
        "event_type"
    ]

    @classmethod
    def is_external_ip(cls, ip_str: str) -> int:
        """Return 1 if IP is public/external, 0 if private/loopback/link-local."""
        try:
            addr = ipaddress.ip_address(ip_str.strip())
            return 0 if (addr.is_private or addr.is_loopback or addr.is_link_local) else 1
        except Exception:
            return 0

    @classmethod
    def parse_datetime(cls, ts_val: Any) -> datetime:
        """Parse varied timestamp into UTC datetime."""
        if isinstance(ts_val, datetime):
            return ts_val if ts_val.tzinfo else ts_val.replace(tzinfo=timezone.utc)
        clean = str(ts_val).strip().replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(clean)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except Exception:
            return datetime.now(timezone.utc)

    @classmethod
    def extract_single(cls, event: Union[SecurityEvent, Dict[str, Any]]) -> Dict[str, Any]:
        """Extract feature record from a single event."""
        if isinstance(event, SecurityEvent):
            d = event.to_dict()
        elif isinstance(event, dict):
            d = dict(event)
        else:
            d = {}

        dt = cls.parse_datetime(d.get("timestamp"))
        hour = dt.hour
        day_of_week = dt.weekday()
        is_weekend = 1 if day_of_week in (5, 6) else 0

        # Cyclical hour encoding
        hour_rad = 2 * math.pi * hour / 24.0
        hour_sin = math.sin(hour_rad)
        hour_cos = math.cos(hour_rad)

        # Log payload size
        try:
            raw_bytes = float(d.get("payload_size", 0) or 0)
            log_payload = math.log1p(max(0.0, raw_bytes))
        except (ValueError, TypeError):
            log_payload = 0.0

        # Status failure check
        status = str(d.get("status", "")).strip().lower()
        is_failure = 1 if status in {"failed", "failure", "denied", "error"} or status.startswith("fail") else 0

        # Privilege checks
        username = str(d.get("username", "")).strip().lower()
        is_privileged_user = 1 if username in cls.PRIVILEGED_USERS else 0

        resource = str(d.get("resource", "")).strip().lower()
        is_privileged_resource = 1 if any(p in resource for p in cls.PRIVILEGED_RESOURCES) else 0

        # External IP check
        src_ip = str(d.get("source_ip", "")).strip()
        is_external = cls.is_external_ip(src_ip)

        # Clean event type
        event_type = str(d.get("event_type", "unknown")).strip().lower()
        if not event_type:
            event_type = "unknown"

        return {
            "hour_sin": hour_sin,
            "hour_cos": hour_cos,
            "day_of_week": day_of_week,
            "is_weekend": is_weekend,
            "log_payload_size": log_payload,
            "is_failure": is_failure,
            "is_privileged_user": is_privileged_user,
            "is_privileged_resource": is_privileged_resource,
            "is_external_ip": is_external,
            "event_type": event_type,
            # Contextual identifiers preserved for findings
            "_fingerprint": d.get("fingerprint", ""),
            "_timestamp": d.get("timestamp", dt.strftime("%Y-%m-%dT%H:%M:%SZ")),
            "_entity": username or src_ip or "unknown",
            "_source_ip": src_ip,
        }

    @classmethod
    def extract_features(
        cls, events: Iterable[Union[SecurityEvent, Dict[str, Any]]]
    ) -> pd.DataFrame:
        """
        Extract feature DataFrame from an iterable of security events.
        """
        rows = [cls.extract_single(ev) for ev in events]
        if not rows:
            all_cols = cls.NUMERIC_COLUMNS + cls.CATEGORICAL_COLUMNS + ["_fingerprint", "_timestamp", "_entity", "_source_ip"]
            return pd.DataFrame(columns=all_cols)
        return pd.DataFrame(rows)

    @classmethod
    def build_preprocessor(cls) -> ColumnTransformer:
        """
        Construct a ColumnTransformer that scales continuous features
        and one-hot encodes categorical attributes without data leakage.
        """
        numeric_transformer = StandardScaler()
        categorical_transformer = OneHotEncoder(handle_unknown="ignore", sparse_output=False)

        preprocessor = ColumnTransformer(
            transformers=[
                ("num", numeric_transformer, cls.NUMERIC_COLUMNS),
                ("cat", categorical_transformer, cls.CATEGORICAL_COLUMNS),
            ]
        )
        return preprocessor
