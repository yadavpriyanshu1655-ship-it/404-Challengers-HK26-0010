"""
Unit and integration tests for CyberShield AI Security Log Ingestion.

Covers:
- Valid file and string ingestion.
- Empty file and header-only CSV handling.
- Column alias resolution and missing column validation.
- Timestamp normalization across multiple formats.
- Safe rejection of missing values, malformed timestamps, and invalid IPs.
- In-batch and cross-batch duplicate detection.
- Invalid input handling (binary data, non-existent files).
- Pandas DataFrame export and ingestion.
- Strict absence of attack classifications during ingestion.
"""

from datetime import datetime
import io
from pathlib import Path
import tempfile
import pytest
import pandas as pd

from backend.ingestion import (
    EmptyFileError,
    IngestionError,
    InvalidFileError,
    MissingColumnError,
    SecurityLogIngestion,
)
from backend.models.event import IngestionResult, RejectedRow, SecurityEvent


@pytest.fixture
def ingestion_engine() -> SecurityLogIngestion:
    """Fixture providing a fresh ingestion engine with isolated deduplication state."""
    return SecurityLogIngestion(deduplicate=True, raise_on_empty=True, raise_on_invalid=True)


@pytest.fixture
def synthetic_logs_path() -> Path:
    """Path to the synthetic benchmark log dataset."""
    path = Path(__file__).resolve().parent.parent / "data" / "synthetic_logs.csv"
    assert path.exists(), f"Synthetic logs not found at {path}"
    return path


# =====================================================================
# 1. Valid Ingestion Tests
# =====================================================================

def test_valid_csv_file_ingestion(ingestion_engine: SecurityLogIngestion, synthetic_logs_path: Path):
    """Verify that a valid, well-formed CSV file is fully parsed and accepted."""
    result = ingestion_engine.process_file(synthetic_logs_path)
    
    assert isinstance(result, IngestionResult)
    assert result.total_rows == 25
    assert result.accepted_count == 25
    assert result.rejected_count == 0
    assert result.duplicate_count == 0
    assert len(result.events) == 25
    assert result.duration_ms > 0

    first_event = result.events[0]
    assert first_event.username == "alice"
    assert first_event.source_ip == "192.168.1.10"
    assert first_event.event_type == "login"
    assert first_event.status == "success"
    assert first_event.timestamp.endswith("Z")
    assert len(first_event.fingerprint) == 64  # SHA-256


def test_export_to_pandas_dataframe(ingestion_engine: SecurityLogIngestion, synthetic_logs_path: Path):
    """Verify that accepted events seamlessly convert to a Pandas DataFrame."""
    result = ingestion_engine.process_file(synthetic_logs_path)
    df = result.to_dataframe()

    assert isinstance(df, pd.DataFrame)
    assert len(df) == 25
    assert "timestamp" in df.columns
    assert "datetime" in df.columns
    assert "source_ip" in df.columns
    assert "fingerprint" in df.columns
    assert pd.api.types.is_datetime64_any_dtype(df["datetime"])


def test_process_from_pandas_dataframe(ingestion_engine: SecurityLogIngestion):
    """Verify direct ingestion from an in-memory Pandas DataFrame."""
    raw_df = pd.DataFrame([
        {"timestamp": "2026-10-15T12:00:00Z", "source_ip": "10.0.0.5", "username": "admin", "event_type": "login", "status": "success"},
        {"timestamp": "2026-10-15T12:01:00Z", "source_ip": "10.0.0.6", "username": "user", "event_type": "logout", "status": "success"},
    ])
    result = ingestion_engine.process_dataframe(raw_df)
    assert result.total_rows == 2
    assert result.accepted_count == 2
    assert result.rejected_count == 0


# =====================================================================
# 2. Empty & Header-Only Handling
# =====================================================================

def test_empty_file_raises_empty_file_error(ingestion_engine: SecurityLogIngestion):
    """Verify that a 0-byte file raises EmptyFileError when raise_on_empty is True."""
    with tempfile.NamedTemporaryFile(suffix=".csv") as tmp:
        with pytest.raises(EmptyFileError):
            ingestion_engine.process_file(tmp.name)


def test_empty_file_without_raise(synthetic_logs_path: Path):
    """Verify safe empty file handling when raise_on_empty is False."""
    engine = SecurityLogIngestion(raise_on_empty=False)
    with tempfile.NamedTemporaryFile(suffix=".csv") as tmp:
        result = engine.process_file(tmp.name)
        assert result.total_rows == 0
        assert result.accepted_count == 0
        assert result.rejected_count == 0


def test_empty_string_input(ingestion_engine: SecurityLogIngestion):
    """Verify empty or whitespace-only CSV string raises EmptyFileError."""
    with pytest.raises(EmptyFileError):
        ingestion_engine.process_csv_string("   \n\t  ")


def test_header_only_csv(ingestion_engine: SecurityLogIngestion):
    """Verify that a CSV containing only valid headers returns 0 total events cleanly."""
    csv_data = "timestamp,source_ip,username,event_type,status\n"
    result = ingestion_engine.process_csv_string(csv_data)
    assert result.total_rows == 0
    assert result.accepted_count == 0
    assert result.rejected_count == 0
    assert result.duplicate_count == 0


# =====================================================================
# 3. Missing Columns & Column Alias Resolution
# =====================================================================

def test_missing_required_column_raises(ingestion_engine: SecurityLogIngestion):
    """Verify that omitting an essential column header raises MissingColumnError."""
    # Omitted 'username'
    bad_csv = "timestamp,source_ip,event_type,status\n2026-10-15T09:00:00Z,192.168.1.1,login,success"
    with pytest.raises(MissingColumnError) as exc_info:
        ingestion_engine.process_csv_string(bad_csv)
    assert "username" in str(exc_info.value)


def test_column_alias_mapping(ingestion_engine: SecurityLogIngestion):
    """Verify that varied header aliases (e.g., time, src_ip, user, action, result) resolve correctly."""
    aliased_csv = (
        "time,src_ip,user,action,result,target,bytes\n"
        "2026-10-15T14:30:00Z,172.16.0.100,svc_backup,backup_job,success,/mnt/storage,20480\n"
    )
    result = ingestion_engine.process_csv_string(aliased_csv)
    assert result.total_rows == 1
    assert result.accepted_count == 1
    event = result.events[0]
    assert event.timestamp == "2026-10-15T14:30:00Z"
    assert event.source_ip == "172.16.0.100"
    assert event.username == "svc_backup"
    assert event.event_type == "backup_job"
    assert event.status == "success"
    assert event.resource == "/mnt/storage"
    assert event.payload_size == 20480


# =====================================================================
# 4. Timestamp Normalization & Malformed Timestamp Handling
# =====================================================================

def test_timestamp_normalization_formats(ingestion_engine: SecurityLogIngestion):
    """Verify normalization of ISO-8601 with offset, space-separated, and numeric epoch."""
    csv_data = (
        "timestamp,source_ip,username,event_type,status\n"
        "2026-10-15 10:00:00,10.0.0.1,alice,login,success\n"
        "2026-10-15T15:30:00+05:30,10.0.0.2,bob,login,success\n"
        "1792058400,10.0.0.3,charlie,login,success\n"
    )
    result = ingestion_engine.process_csv_string(csv_data)
    assert result.accepted_count == 3
    for ev in result.events:
        assert ev.timestamp.endswith("Z")
        # Ensure parsable by ISO-8601
        dt = datetime.fromisoformat(ev.timestamp.replace("Z", "+00:00"))
        assert dt.tzinfo is not None


def test_malformed_timestamp_rejected_safely(ingestion_engine: SecurityLogIngestion):
    """Verify that rows with unparseable timestamps are safely rejected without failing the batch."""
    csv_data = (
        "timestamp,source_ip,username,event_type,status\n"
        "INVALID_DATE_STRING,10.0.0.1,alice,login,success\n"
        "2026-10-15T09:00:00Z,10.0.0.2,bob,login,success\n"
    )
    result = ingestion_engine.process_csv_string(csv_data)
    assert result.total_rows == 2
    assert result.accepted_count == 1
    assert result.rejected_count == 1
    assert result.events[0].username == "bob"
    
    rejected = result.rejected_rows[0]
    assert rejected.line_number == 2
    assert "timestamp" in rejected.reason.lower()


# =====================================================================
# 5. Missing Values & Invalid IP Handling
# =====================================================================

def test_missing_values_rejected_safely(ingestion_engine: SecurityLogIngestion):
    """Verify safe rejection when required values are empty strings or missing."""
    csv_data = (
        "timestamp,source_ip,username,event_type,status\n"
        "2026-10-15T09:00:00Z,10.0.0.1,,login,success\n"               # Missing username
        "2026-10-15T09:01:00Z,,bob,login,success\n"                    # Missing IP
        "2026-10-15T09:02:00Z,10.0.0.3,charlie,,success\n"             # Missing event_type
        "2026-10-15T09:03:00Z,10.0.0.4,david,login,\n"                 # Missing status
        "2026-10-15T09:04:00Z,10.0.0.5,elena,login,success\n"          # Valid
    )
    result = ingestion_engine.process_csv_string(csv_data)
    assert result.total_rows == 5
    assert result.accepted_count == 1
    assert result.rejected_count == 4
    assert result.events[0].username == "elena"


def test_invalid_ip_rejected(ingestion_engine: SecurityLogIngestion):
    """Verify that invalid IPv4/IPv6 addresses are rejected."""
    csv_data = (
        "timestamp,source_ip,username,event_type,status\n"
        "2026-10-15T09:00:00Z,999.999.999.999,alice,login,success\n"  # Invalid octet
        "2026-10-15T09:01:00Z,not-an-ip,bob,login,success\n"          # Not an IP
        "2026-10-15T09:02:00Z,2001:db8::1,charlie,login,success\n"    # Valid IPv6
    )
    result = ingestion_engine.process_csv_string(csv_data)
    assert result.total_rows == 3
    assert result.accepted_count == 1
    assert result.rejected_count == 2
    assert result.events[0].source_ip == "2001:db8::1"


def test_negative_payload_size_rejected(ingestion_engine: SecurityLogIngestion):
    """Verify that negative payload sizes are rejected."""
    csv_data = (
        "timestamp,source_ip,username,event_type,status,payload_size\n"
        "2026-10-15T09:00:00Z,10.0.0.1,alice,login,success,-500\n"
    )
    result = ingestion_engine.process_csv_string(csv_data)
    assert result.rejected_count == 1
    assert "negative" in result.rejected_rows[0].reason.lower()


# =====================================================================
# 6. Duplicate Record Detection
# =====================================================================

def test_duplicate_records_within_single_file(ingestion_engine: SecurityLogIngestion):
    """Verify duplicate detection and counting within a single CSV batch."""
    csv_data = (
        "timestamp,source_ip,username,event_type,status\n"
        "2026-10-15T09:00:00Z,10.0.0.1,alice,login,success\n"
        "2026-10-15T09:00:00Z,10.0.0.1,alice,login,success\n"  # Exact Duplicate
        "2026-10-15T09:05:00Z,10.0.0.1,alice,login,success\n"  # Distinct timestamp
    )
    result = ingestion_engine.process_csv_string(csv_data)
    assert result.total_rows == 3
    assert result.accepted_count == 2
    assert result.duplicate_count == 1
    assert result.rejected_count == 0
    assert len(result.duplicates) == 1
    assert result.duplicates[0].fingerprint == result.events[0].fingerprint


def test_cross_batch_deduplication(ingestion_engine: SecurityLogIngestion):
    """Verify deduplication state is maintained across sequential batch calls."""
    csv_batch_1 = (
        "timestamp,source_ip,username,event_type,status\n"
        "2026-10-15T09:00:00Z,10.0.0.1,alice,login,success\n"
    )
    csv_batch_2 = (
        "timestamp,source_ip,username,event_type,status\n"
        "2026-10-15T09:00:00Z,10.0.0.1,alice,login,success\n"  # Already seen in batch 1
        "2026-10-15T09:01:00Z,10.0.0.2,bob,login,success\n"
    )
    res1 = ingestion_engine.process_csv_string(csv_batch_1)
    assert res1.accepted_count == 1
    assert res1.duplicate_count == 0

    res2 = ingestion_engine.process_csv_string(csv_batch_2)
    assert res2.total_rows == 2
    assert res2.accepted_count == 1
    assert res2.duplicate_count == 1
    assert res2.events[0].username == "bob"


# =====================================================================
# 7. Invalid Inputs & Edge Cases
# =====================================================================

def test_nonexistent_file_raises(ingestion_engine: SecurityLogIngestion):
    """Verify that passing a non-existent file path raises InvalidFileError."""
    with pytest.raises(InvalidFileError):
        ingestion_engine.process_file("non_existent_file_xyz123.csv")


def test_binary_null_bytes_rejected(ingestion_engine: SecurityLogIngestion):
    """Verify that corrupt or binary files with null bytes are rejected."""
    binary_content = "timestamp,source_ip,username,event_type,status\n\x00\x00\x00corrupt"
    with pytest.raises(InvalidFileError):
        ingestion_engine.process_csv_string(binary_content)


def test_file_buffer_stream_ingestion(ingestion_engine: SecurityLogIngestion):
    """Verify ingesting from an in-memory io.StringIO buffer."""
    buf = io.StringIO(
        "timestamp,source_ip,username,event_type,status\n"
        "2026-10-15T09:00:00Z,192.168.1.1,admin,login,success\n"
    )
    result = ingestion_engine.process_file(buf)
    assert result.accepted_count == 1
    assert result.events[0].username == "admin"


# =====================================================================
# 8. Strict Ingestion Principle: No Attack Classification
# =====================================================================

def test_no_attack_classification_during_ingestion(ingestion_engine: SecurityLogIngestion, synthetic_logs_path: Path):
    """
    Requirement Check:
    Verify that ingestion produces clean, normalized telemetry WITHOUT
    classifying events as attacks, assigning threat scores, or flagging malicious intent.
    """
    result = ingestion_engine.process_file(synthetic_logs_path)
    for event in result.events:
        d = event.to_dict()
        assert "is_attack" not in d
        assert "threat_score" not in d
        assert "attack_type" not in d
        assert "severity" not in d
        assert "malicious" not in d
        # Ensure only official telemetry fields exist
        assert set(d.keys()) == {
            "timestamp", "source_ip", "destination_ip", "username",
            "event_type", "status", "resource", "payload_size", "fingerprint"
        }
