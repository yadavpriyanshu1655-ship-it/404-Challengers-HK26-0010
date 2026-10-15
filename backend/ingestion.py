"""
CyberShield AI — Security Log Ingestion Engine

Reusable, standalone Python module for ingesting, validating, normalizing,
and deduplicating enterprise security logs from CSV files, streams, and DataFrames.

Features:
- Schema enforcement & flexible column alias resolution.
- Timestamps normalized to ISO-8601 UTC ('YYYY-MM-DDTHH:MM:SSZ').
- Strict IP address (IPv4/IPv6) validation.
- Safe rejection of malformed or missing-field rows without aborting the batch.
- Deterministic SHA-256 fingerprinting and duplicate detection.
- Comprehensive metrics: total, accepted, rejected, and duplicate counts.
- Zero attack classification: strictly maintains clean, normalized telemetry.
- Native Pandas integration for data pipelines and analytics.
"""

from __future__ import annotations

import csv
from datetime import datetime, timezone
import hashlib
import io
import ipaddress
from pathlib import Path
import time
from typing import Any, Dict, Iterable, List, Optional, Set, Union

import pandas as pd

from backend.models.event import IngestionResult, RejectedRow, SecurityEvent


# =====================================================================
# Domain Exceptions
# =====================================================================

class IngestionError(Exception):
    """Base exception for all security log ingestion errors."""
    pass


class EmptyFileError(IngestionError):
    """Raised when an uploaded log file or string contains 0 bytes or only whitespace."""
    pass


class InvalidFileError(IngestionError):
    """Raised when the input is not a valid CSV or has unreadable encoding/formatting."""
    pass


class MissingColumnError(IngestionError):
    """Raised when essential required schema columns cannot be resolved."""
    pass


# =====================================================================
# Ingestion Engine
# =====================================================================

class SecurityLogIngestion:
    """
    High-performance, standalone security telemetry ingestion processor.
    
    Provides validation, normalization, and deduplication for CSV files,
    in-memory buffers, and Pandas DataFrames.
    """

    # Comprehensive column alias dictionary allowing flexible telemetry schemas
    COLUMN_ALIASES: Dict[str, List[str]] = {
        "timestamp": [
            "timestamp", "time", "datetime", "event_time", "@timestamp",
            "date", "log_time", "created_at"
        ],
        "source_ip": [
            "source_ip", "src_ip", "ip", "client_ip", "ip_address",
            "source_address", "host_ip", "srcip"
        ],
        "destination_ip": [
            "destination_ip", "dest_ip", "dst_ip", "server_ip",
            "target_ip", "target_address", "dstip"
        ],
        "username": [
            "username", "user", "account", "user_name", "user_id",
            "login_id", "actor", "account_name"
        ],
        "event_type": [
            "event_type", "event", "action", "type", "activity",
            "event_name", "method", "command"
        ],
        "status": [
            "status", "result", "outcome", "action_result", "state", "disposition"
        ],
        "resource": [
            "resource", "uri", "url", "endpoint", "path",
            "target", "service", "destination_resource"
        ],
        "payload_size": [
            "payload_size", "bytes", "size", "bytes_sent",
            "content_length", "length", "packet_size"
        ],
    }

    REQUIRED_FIELDS: List[str] = [
        "timestamp", "source_ip", "username", "event_type", "status"
    ]

    def __init__(
        self,
        deduplicate: bool = True,
        existing_fingerprints: Optional[Set[str]] = None,
        raise_on_empty: bool = True,
        raise_on_invalid: bool = True,
    ):
        """
        Initialize the Security Log Ingestion engine.
        
        Args:
            deduplicate: If True, identifies and suppresses duplicate event records.
            existing_fingerprints: Optional set of pre-existing fingerprints for cross-batch deduplication.
            raise_on_empty: If True, raises EmptyFileError when input is empty. If False, returns empty IngestionResult.
            raise_on_invalid: If True, raises InvalidFileError on unparseable inputs. If False, returns IngestionResult with error.
        """
        self.deduplicate = deduplicate
        self.seen_fingerprints: Set[str] = set(existing_fingerprints or [])
        self.raise_on_empty = raise_on_empty
        self.raise_on_invalid = raise_on_invalid

    def reset_deduplication(self) -> None:
        """Clear the in-memory deduplication cache."""
        self.seen_fingerprints.clear()

    # -----------------------------------------------------------------
    # Normalization & Validation Helpers
    # -----------------------------------------------------------------

    @staticmethod
    def normalize_ip(value: Any) -> str:
        """
        Validate and format an IPv4 or IPv6 address.
        Strips surrounding whitespace and handles optional trailing port numbers.
        
        Raises:
            ValueError: If the input is not a valid IP address.
        """
        if not value:
            raise ValueError("IP address is missing or empty")
        raw = str(value).strip()
        # Handle host:port syntax (e.g. 192.168.1.1:8080)
        if ":" in raw and not (raw.startswith("[") or raw.count(":") > 1):
            raw = raw.split(":", 1)[0].strip()
        elif raw.startswith("[") and "]" in raw:
            raw = raw[1:raw.index("]")].strip()
            
        try:
            parsed = ipaddress.ip_address(raw)
            return str(parsed)
        except ValueError:
            raise ValueError(f"Invalid IP address format: '{value}'")

    @staticmethod
    def normalize_timestamp(value: Any) -> str:
        """
        Parse and normalize varied timestamp representations into ISO-8601 UTC.
        
        Supports:
        - ISO-8601 strings (with Z, offsets, or naive UTC assumption).
        - Common SQL / Syslog string formats ('YYYY-MM-DD HH:MM:SS').
        - Epoch Unix timestamps (integer or float seconds).
        
        Returns:
            String formatted as 'YYYY-MM-DDTHH:MM:SSZ'
            
        Raises:
            ValueError: If the timestamp cannot be reliably parsed.
        """
        if value is None or (isinstance(value, str) and not value.strip()):
            raise ValueError("Timestamp is missing or empty")

        # 1. Numeric Epoch
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            try:
                # If milliseconds (e.g. 13-digit epoch)
                ts = float(value)
                if ts > 1e11:
                    ts = ts / 1000.0
                dt = datetime.fromtimestamp(ts, tz=timezone.utc)
                return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
            except Exception as e:
                raise ValueError(f"Invalid epoch timestamp: '{value}' ({e})")

        raw = str(value).strip()
        
        # Check numeric string epoch
        try:
            num = float(raw)
            if num > 1e11:
                num = num / 1000.0
            dt = datetime.fromtimestamp(num, tz=timezone.utc)
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            pass

        # 2. ISO 8601 string
        try:
            iso_candidate = raw.replace("Z", "+00:00")
            dt = datetime.fromisoformat(iso_candidate)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            else:
                dt = dt.astimezone(timezone.utc)
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            pass

        # 3. Pandas / Flexible Parser Fallback
        try:
            ts_parsed = pd.to_datetime(raw, utc=True)
            if pd.isna(ts_parsed):
                raise ValueError("Parsed as NaT")
            dt = ts_parsed.to_pydatetime()
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            raise ValueError(f"Malformed or unparseable timestamp: '{value}'")

    @classmethod
    def resolve_field_aliases(cls, headers: Iterable[str]) -> Dict[str, str]:
        """
        Map CSV header column names to canonical schema attributes.
        
        Returns:
            Dictionary mapping canonical field -> matched header name in file.
        """
        cleaned_headers = {str(h).strip().lower(): str(h).strip() for h in headers if h}
        resolved: Dict[str, str] = {}
        
        for canonical, aliases in cls.COLUMN_ALIASES.items():
            for alias in aliases:
                if alias in cleaned_headers:
                    resolved[canonical] = cleaned_headers[alias]
                    break
        return resolved

    @classmethod
    def compute_fingerprint(
        cls,
        timestamp: str,
        source_ip: str,
        destination_ip: str,
        username: str,
        event_type: str,
        status: str,
        resource: str,
        payload_size: int,
    ) -> str:
        """
        Generate a deterministic SHA-256 fingerprint for duplicate detection.
        """
        canonical_str = (
            f"{timestamp}|{source_ip}|{destination_ip}|{username}|"
            f"{event_type}|{status}|{resource}|{payload_size}"
        )
        return hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()

    # -----------------------------------------------------------------
    # Row Processing
    # -----------------------------------------------------------------

    def process_row(
        self,
        raw_row: Dict[str, Any],
        header_map: Dict[str, str],
        line_number: int,
    ) -> Union[SecurityEvent, RejectedRow]:
        """
        Validate, normalize, and transform a single log row.
        
        Returns:
            SecurityEvent on success, or RejectedRow on validation failure.
        """
        extracted: Dict[str, Any] = {}
        for canonical, header_key in header_map.items():
            extracted[canonical] = raw_row.get(header_key)

        # 1. Check required fields presence
        missing = [f for f in self.REQUIRED_FIELDS if extracted.get(f) is None or str(extracted[f]).strip() == ""]
        if missing:
            return RejectedRow(
                line_number=line_number,
                reason=f"Missing required field(s): {', '.join(missing)}",
                raw_data=raw_row,
            )

        # 2. Normalize Timestamp
        try:
            norm_ts = self.normalize_timestamp(extracted["timestamp"])
        except ValueError as exc:
            return RejectedRow(
                line_number=line_number,
                reason=str(exc),
                raw_data=raw_row,
            )

        # 3. Validate Source IP
        try:
            norm_src_ip = self.normalize_ip(extracted["source_ip"])
        except ValueError as exc:
            return RejectedRow(
                line_number=line_number,
                reason=f"Invalid source_ip: {exc}",
                raw_data=raw_row,
            )

        # 4. Destination IP (Optional)
        dest_val = extracted.get("destination_ip")
        if dest_val and str(dest_val).strip():
            try:
                norm_dest_ip = self.normalize_ip(dest_val)
            except ValueError as exc:
                return RejectedRow(
                    line_number=line_number,
                    reason=f"Invalid destination_ip: {exc}",
                    raw_data=raw_row,
                )
        else:
            norm_dest_ip = "10.0.0.1"

        # 5. Username
        norm_user = str(extracted["username"]).strip()
        if not norm_user:
            return RejectedRow(
                line_number=line_number,
                reason="Username cannot be empty or whitespace",
                raw_data=raw_row,
            )

        # 6. Event Type & Status (Normalized to lowercase)
        norm_event_type = str(extracted["event_type"]).strip().lower()
        norm_status = str(extracted["status"]).strip().lower()
        if not norm_event_type:
            return RejectedRow(
                line_number=line_number,
                reason="Event type cannot be empty",
                raw_data=raw_row,
            )
        if not norm_status:
            return RejectedRow(
                line_number=line_number,
                reason="Status cannot be empty",
                raw_data=raw_row,
            )

        # 7. Resource (Optional)
        res_val = extracted.get("resource")
        norm_resource = str(res_val).strip() if res_val and str(res_val).strip() else "/"

        # 8. Payload Size (Optional integer)
        size_val = extracted.get("payload_size")
        norm_payload_size = 0
        if size_val is not None and str(size_val).strip():
            try:
                parsed_size = int(float(str(size_val).strip()))
                if parsed_size < 0:
                    return RejectedRow(
                        line_number=line_number,
                        reason=f"Payload size cannot be negative: '{size_val}'",
                        raw_data=raw_row,
                    )
                norm_payload_size = parsed_size
            except ValueError:
                return RejectedRow(
                    line_number=line_number,
                    reason=f"Payload size must be an integer: '{size_val}'",
                    raw_data=raw_row,
                )

        # 9. Compute Deterministic Fingerprint
        fp = self.compute_fingerprint(
            norm_ts, norm_src_ip, norm_dest_ip, norm_user,
            norm_event_type, norm_status, norm_resource, norm_payload_size
        )

        return SecurityEvent(
            timestamp=norm_ts,
            source_ip=norm_src_ip,
            destination_ip=norm_dest_ip,
            username=norm_user,
            event_type=norm_event_type,
            status=norm_status,
            resource=norm_resource,
            payload_size=norm_payload_size,
            fingerprint=fp,
        )

    # -----------------------------------------------------------------
    # Primary Ingestion Methods
    # -----------------------------------------------------------------

    def process_csv_string(self, content: str) -> IngestionResult:
        """
        Ingest and validate security logs provided as a raw CSV string.
        """
        start_time = time.perf_counter()
        if content is None or not content.strip():
            if self.raise_on_empty:
                raise EmptyFileError("Input CSV content is empty or contains only whitespace")
            return IngestionResult(duration_ms=(time.perf_counter() - start_time) * 1000)

        # Validate basic delimiter and reading
        try:
            # Check for binary null bytes
            if "\x00" in content:
                raise InvalidFileError("Input contains null bytes (binary or corrupt data)")

            sample = content[:4096]
            sniffer = csv.Sniffer()
            delimiter = ","
            try:
                dialect = sniffer.sniff(sample, delimiters=",;\t|")
                delimiter = dialect.delimiter
            except Exception:
                delimiter = ","

            reader = csv.DictReader(io.StringIO(content), delimiter=delimiter)
        except IngestionError:
            raise
        except Exception as exc:
            if self.raise_on_invalid:
                raise InvalidFileError(f"Could not parse CSV content: {exc}")
            result = IngestionResult(duration_ms=(time.perf_counter() - start_time) * 1000)
            result.rejected_rows.append(RejectedRow(line_number=1, reason=f"CSV parse error: {exc}", raw_data={}))
            result.rejected_count = 1
            result.total_rows = 1
            return result

        if not reader.fieldnames:
            if self.raise_on_empty:
                raise EmptyFileError("CSV has no header row or columns defined")
            return IngestionResult(duration_ms=(time.perf_counter() - start_time) * 1000)

        # Resolve column aliases
        header_map = self.resolve_field_aliases(reader.fieldnames)
        missing_required = [f for f in self.REQUIRED_FIELDS if f not in header_map]
        if missing_required:
            msg = f"Missing required column headers: {', '.join(missing_required)}. Available: {list(reader.fieldnames)}"
            if self.raise_on_invalid:
                raise MissingColumnError(msg)
            result = IngestionResult(duration_ms=(time.perf_counter() - start_time) * 1000)
            result.rejected_rows.append(RejectedRow(line_number=1, reason=msg, raw_data={}))
            result.rejected_count = 1
            result.total_rows = 1
            return result

        accepted: List[SecurityEvent] = []
        rejected: List[RejectedRow] = []
        duplicates: List[SecurityEvent] = []
        total_rows = 0

        # Process each row
        for line_no, raw_row in enumerate(reader, start=2):
            total_rows += 1
            processed = self.process_row(raw_row, header_map, line_number=line_no)
            
            if isinstance(processed, RejectedRow):
                rejected.append(processed)
            else:
                # Deduplication check
                if self.deduplicate and processed.fingerprint in self.seen_fingerprints:
                    duplicates.append(processed)
                else:
                    if self.deduplicate:
                        self.seen_fingerprints.add(processed.fingerprint)
                    accepted.append(processed)

        elapsed_ms = (time.perf_counter() - start_time) * 1000
        return IngestionResult(
            total_rows=total_rows,
            accepted_count=len(accepted),
            rejected_count=len(rejected),
            duplicate_count=len(duplicates),
            events=accepted,
            rejected_rows=rejected,
            duplicates=duplicates,
            duration_ms=elapsed_ms,
        )

    def process_file(
        self,
        file_path_or_buffer: Union[str, Path, io.IOBase],
        encoding: str = "utf-8-sig",
    ) -> IngestionResult:
        """
        Ingest and validate security logs from a file path or file-like buffer.
        
        Args:
            file_path_or_buffer: Path to the CSV file or an open file-like IO object.
            encoding: Text encoding (defaults to 'utf-8-sig' to seamlessly strip BOM).
        """
        start_time = time.perf_counter()

        # Handle file paths
        if isinstance(file_path_or_buffer, (str, Path)):
            path = Path(file_path_or_buffer)
            if not path.exists():
                if self.raise_on_invalid:
                    raise InvalidFileError(f"Log file does not exist: {path}")
                return IngestionResult(duration_ms=(time.perf_counter() - start_time) * 1000)
            
            # Check empty file (0 bytes)
            try:
                if path.stat().st_size == 0:
                    if self.raise_on_empty:
                        raise EmptyFileError(f"File is 0 bytes: {path}")
                    return IngestionResult(duration_ms=(time.perf_counter() - start_time) * 1000)

                with path.open("r", encoding=encoding, errors="replace") as f:
                    content = f.read()
            except IngestionError:
                raise
            except Exception as exc:
                if self.raise_on_invalid:
                    raise InvalidFileError(f"Failed to read file '{path}': {exc}")
                result = IngestionResult(duration_ms=(time.perf_counter() - start_time) * 1000)
                result.rejected_rows.append(RejectedRow(line_number=0, reason=str(exc), raw_data={}))
                result.rejected_count = 1
                result.total_rows = 1
                return result

        # Handle buffer / file-like object
        elif hasattr(file_path_or_buffer, "read"):
            try:
                raw = file_path_or_buffer.read()
                if isinstance(raw, bytes):
                    content = raw.decode(encoding, errors="replace")
                else:
                    content = str(raw)
            except Exception as exc:
                if self.raise_on_invalid:
                    raise InvalidFileError(f"Failed to read buffer: {exc}")
                result = IngestionResult(duration_ms=(time.perf_counter() - start_time) * 1000)
                result.rejected_rows.append(RejectedRow(line_number=0, reason=str(exc), raw_data={}))
                result.rejected_count = 1
                result.total_rows = 1
                return result
        else:
            if self.raise_on_invalid:
                raise InvalidFileError(f"Unsupported input type: {type(file_path_or_buffer)}")
            return IngestionResult(duration_ms=(time.perf_counter() - start_time) * 1000)

        return self.process_csv_string(content)

    def process_dataframe(self, df: pd.DataFrame) -> IngestionResult:
        """
        Process and validate an existing Pandas DataFrame of security telemetry.
        """
        start_time = time.perf_counter()
        if df is None or df.empty:
            if self.raise_on_empty:
                raise EmptyFileError("DataFrame is empty")
            return IngestionResult(duration_ms=(time.perf_counter() - start_time) * 1000)

        # Convert DataFrame to CSV buffer to leverage uniform parser & aliases
        buf = io.StringIO()
        df.to_csv(buf, index=False)
        buf.seek(0)
        return self.process_csv_string(buf.getvalue())
