"""
CyberShield AI — Security Event Schema & Ingestion Models

Defines standard schemas, data classes, and serialization models
for normalized enterprise security telemetry.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional
import pandas as pd


@dataclass
class SecurityEvent:
    """
    Normalized Security Event entity.
    
    Attributes:
        timestamp: Normalized ISO-8601 UTC timestamp string (e.g., '2026-10-15T09:00:00Z').
        source_ip: Validated source IPv4 or IPv6 address.
        destination_ip: Target/destination IP address (default '10.0.0.1' if not specified).
        username: Actor or subject identifier initiating the event.
        event_type: Normalized lowercase event category (e.g., 'login', 'file_access', 'sudo').
        status: Normalized event outcome ('success', 'failed', 'denied', 'error').
        resource: Target resource, URI endpoint, or affected artifact (default '/').
        payload_size: Transferred byte size or data payload length (default 0).
        fingerprint: Deterministic canonical SHA-256 hash or pipe-delimited composite key.
    """
    timestamp: str
    source_ip: str
    username: str
    event_type: str
    status: str
    destination_ip: str = "10.0.0.1"
    resource: str = "/"
    payload_size: int = 0
    fingerprint: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert the SecurityEvent instance into a standard dictionary."""
        return asdict(self)


@dataclass
class RejectedRow:
    """
    Record of a row that failed validation during ingestion.
    
    Attributes:
        line_number: Line number in the source CSV file (1-indexed header, data starting at 2).
        reason: Clear diagnostic message explaining the validation failure.
        raw_data: Raw dictionary or string representation of the rejected row.
    """
    line_number: int
    reason: str
    raw_data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class IngestionResult:
    """
    Structured outcome of a security log batch ingestion run.
    
    Attributes:
        total_rows: Total rows received in the input (accepted + rejected + duplicate).
        accepted_count: Number of successfully parsed, validated, and unique events.
        rejected_count: Number of rows discarded due to schema/type/format errors.
        duplicate_count: Number of duplicate records detected and suppressed.
        events: List of validated SecurityEvent objects.
        rejected_rows: List of RejectedRow diagnostic records.
        duplicates: List of duplicate SecurityEvent records detected.
        duration_ms: Processing time in milliseconds.
    """
    total_rows: int = 0
    accepted_count: int = 0
    rejected_count: int = 0
    duplicate_count: int = 0
    events: List[SecurityEvent] = field(default_factory=list)
    rejected_rows: List[RejectedRow] = field(default_factory=list)
    duplicates: List[SecurityEvent] = field(default_factory=list)
    duration_ms: float = 0.0

    def to_dataframe(self) -> pd.DataFrame:
        """
        Export accepted security events to a Pandas DataFrame.
        Returns an empty DataFrame with standard columns if no events were accepted.
        """
        if not self.events:
            return pd.DataFrame(columns=[
                "timestamp", "source_ip", "destination_ip", "username",
                "event_type", "status", "resource", "payload_size", "fingerprint"
            ])
        data = [event.to_dict() for event in self.events]
        df = pd.DataFrame(data)
        if not df.empty and "timestamp" in df.columns:
            df["datetime"] = pd.to_datetime(df["timestamp"], utc=True)
        return df

    def to_dict(self) -> Dict[str, Any]:
        """Convert the result into a JSON-serializable dictionary."""
        return {
            "total_rows": self.total_rows,
            "accepted_count": self.accepted_count,
            "rejected_count": self.rejected_count,
            "duplicate_count": self.duplicate_count,
            "events": [e.to_dict() for e in self.events],
            "rejected_rows": [r.to_dict() for r in self.rejected_rows],
            "duplicates": [d.to_dict() for d in self.duplicates],
            "duration_ms": round(self.duration_ms, 2),
        }
