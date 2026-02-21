"""
parser.py - Windows Security EVTX Log Parser

Parses binary EVTX files and extracts structured event data.
Each record is normalized into a flat dict for downstream detection logic.

Supported event types:
    4625 - Failed logon (brute-force indicator)
    4720 - User account created (persistence indicator)
    4728 - Member added to global security group (privilege escalation)
    4732 - Member added to local security group (privilege escalation)
    4688 - New process created (execution / encoded command indicator)
"""

import xml.etree.ElementTree as ET
import logging
from pathlib import Path
from datetime import datetime
from typing import Generator

import Evtx.Evtx as evtx

logger = logging.getLogger(__name__)

# Windows Security event IDs relevant to threat detection.
# Scoping parse to only these IDs avoids processing noise events.
MONITORED_EVENT_IDS = {4625, 4720, 4728, 4732, 4688}

# XML namespace used in Windows Event Log schema
NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


def parse_evtx(filepath: str) -> Generator[dict, None, None]:
    """
    Parse an EVTX file and yield normalized event dicts.

    Args:
        filepath: Path to the .evtx file.

    Yields:
        dict with keys: event_id, timestamp, event_data (dict of named fields).

    Raises:
        FileNotFoundError: If the EVTX file does not exist.
        RuntimeError: If the file cannot be parsed.
    """
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"EVTX file not found: {filepath}")

    logger.info("Parsing EVTX file: %s", filepath)
    record_count = 0
    error_count = 0

    try:
        with evtx.Evtx(str(path)) as log:
            for record in log.records():
                try:
                    parsed = _parse_record(record)
                    if parsed is not None:
                        record_count += 1
                        yield parsed
                except Exception as e:
                    # Malformed records should not halt the entire parse.
                    # SOC tooling must be resilient to partial corruption.
                    error_count += 1
                    logger.debug("Skipping malformed record: %s", e)
    except Exception as e:
        raise RuntimeError(f"Failed to parse EVTX file: {e}") from e

    logger.info(
        "Parsing complete: %d relevant records extracted, %d errors skipped",
        record_count,
        error_count,
    )


def _parse_record(record) -> dict | None:
    """
    Parse a single EVTX record from its XML representation.

    Returns None for records whose Event ID is not in MONITORED_EVENT_IDS
    (we skip them early to avoid unnecessary XML traversal).
    """
    xml_str = record.xml()
    root = ET.fromstring(xml_str)

    # --- Extract System-level fields ---
    system = root.find(f"{NS}System")
    if system is None:
        return None

    event_id_elem = system.find(f"{NS}EventID")
    if event_id_elem is None:
        return None

    try:
        event_id = int(event_id_elem.text)
    except (ValueError, TypeError):
        return None

    # Early exit for non-monitored events — performance optimization
    if event_id not in MONITORED_EVENT_IDS:
        return None

    # Parse timestamp from TimeCreated element
    time_created = system.find(f"{NS}TimeCreated")
    timestamp_str = time_created.get("SystemTime", "") if time_created is not None else ""
    timestamp = _parse_timestamp(timestamp_str)

    computer_elem = system.find(f"{NS}Computer")
    computer = computer_elem.text if computer_elem is not None else "UNKNOWN"

    # --- Extract EventData fields into a flat dict ---
    event_data = _extract_event_data(root)

    return {
        "event_id": event_id,
        "timestamp": timestamp,
        "computer": computer,
        "event_data": event_data,
        "raw_xml": xml_str,
    }


def _extract_event_data(root: ET.Element) -> dict:
    """
    Extract all named Data elements from the EventData section.

    Windows Security events store per-event fields as:
        <EventData>
            <Data Name="TargetUserName">jdoe</Data>
            ...
        </EventData>

    We flatten these into {"TargetUserName": "jdoe", ...}.
    """
    event_data = {}
    ed_elem = root.find(f"{NS}EventData")
    if ed_elem is None:
        return event_data

    for data_elem in ed_elem.findall(f"{NS}Data"):
        name = data_elem.get("Name", "")
        value = data_elem.text or ""
        if name:
            event_data[name] = value

    return event_data


def _parse_timestamp(ts_str: str) -> str:
    """
    Normalize a Windows SystemTime string to ISO 8601 format.

    Windows EVTX timestamps can appear in multiple formats:
        2024-01-15T08:30:00.1234567Z
        2024-01-15 08:30:00

    We normalize to: 2024-01-15T08:30:00 (no fractional seconds).
    Returning a string (not datetime) keeps the data JSON-serializable.
    """
    if not ts_str:
        return "UNKNOWN"

    # Strip sub-second precision and trailing Z for consistent parsing
    clean = ts_str.replace("Z", "").split(".")[0]

    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            dt = datetime.strptime(clean, fmt)
            return dt.strftime("%Y-%m-%dT%H:%M:%S")
        except ValueError:
            continue

    logger.debug("Unparseable timestamp: %s", ts_str)
    return ts_str  # Return raw string rather than failing
