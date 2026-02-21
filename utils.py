"""
utils.py - Utility Functions

Handles:
    - Loading MITRE ATT&CK mappings from mitre_mapping.json
    - Enriching alerts with MITRE technique metadata
    - Severity ordering and statistics
    - Writing alerts.json and incident_report.txt output files
"""

import json
import logging
from pathlib import Path
from datetime import datetime

logger = logging.getLogger(__name__)

# Severity ordering for sorting alerts (highest first).
# SOC analysts triage CRITICAL → HIGH → MEDIUM → LOW.
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

# Resolve mitre_mapping.json relative to this file so the tool works
# regardless of the caller's working directory.
_PROJECT_DIR = Path(__file__).resolve().parent
DEFAULT_MITRE_PATH = _PROJECT_DIR / "mitre_mapping.json"


def load_mitre_mapping(path: Path = DEFAULT_MITRE_PATH) -> dict:
    """
    Load the MITRE ATT&CK mapping file.

    Returns:
        dict keyed by detection rule name (e.g. "brute_force") with
        technique_id, technique_name, tactic, description, url.
    """
    if not path.exists():
        logger.warning("MITRE mapping file not found at %s — enrichment disabled", path)
        return {}

    with open(path, "r", encoding="utf-8") as f:
        mapping = json.load(f)

    logger.info("Loaded MITRE mapping with %d technique entries", len(mapping))
    return mapping


def enrich_alerts(alerts: list[dict], mitre_map: dict) -> list[dict]:
    """
    Attach MITRE ATT&CK metadata to each alert based on its mitre_key.

    This gives SOC analysts immediate context for escalation and
    report writing without manual technique lookup.
    """
    for alert in alerts:
        key = alert.get("mitre_key", "")
        technique = mitre_map.get(key, {})
        alert["mitre"] = {
            "technique_id": technique.get("technique_id", "N/A"),
            "technique_name": technique.get("technique_name", "N/A"),
            "tactic": technique.get("tactic", "N/A"),
            "url": technique.get("url", ""),
        }

    return alerts


def sort_alerts(alerts: list[dict]) -> list[dict]:
    """Sort alerts by severity (CRITICAL first), then by timestamp."""
    return sorted(
        alerts,
        key=lambda a: (
            SEVERITY_ORDER.get(a.get("severity", "INFO"), 99),
            a.get("timestamp", ""),
        ),
    )


def severity_stats(alerts: list[dict]) -> dict[str, int]:
    """Return a count of alerts per severity level."""
    stats: dict[str, int] = {}
    for alert in alerts:
        sev = alert.get("severity", "UNKNOWN")
        stats[sev] = stats.get(sev, 0) + 1
    return stats


# ---------------------------------------------------------------------------
# Output writers
# ---------------------------------------------------------------------------

def write_alerts_json(alerts: list[dict], output_path: Path) -> None:
    """
    Write the full alert list to a JSON file.

    This is the machine-readable output intended for SIEM ingestion,
    ticketing integration, or downstream automation.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(alerts, f, indent=2, default=str)

    logger.info("Wrote %d alerts to %s", len(alerts), output_path)


def write_incident_report(
    alerts: list[dict],
    output_path: Path,
    evtx_file: str,
    total_events_parsed: int,
) -> None:
    """
    Generate a human-readable incident report in plain text.

    Format follows a simplified SOC incident report template:
        - Executive summary
        - Statistics
        - Per-alert detail blocks
        - Recommendations

    This is the artifact a Tier-1 analyst would attach to a ticket.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    stats = severity_stats(alerts)
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    lines = []
    lines.append("=" * 72)
    lines.append("  WINDOWS SECURITY LOG - INCIDENT REPORT")
    lines.append("=" * 72)
    lines.append("")
    lines.append(f"  Generated : {now}")
    lines.append(f"  Source     : {evtx_file}")
    lines.append(f"  Events     : {total_events_parsed} relevant records parsed")
    lines.append(f"  Alerts     : {len(alerts)} total detections")
    lines.append("")

    # --- Severity breakdown ---
    lines.append("-" * 72)
    lines.append("  SEVERITY BREAKDOWN")
    lines.append("-" * 72)
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        count = stats.get(sev, 0)
        if count > 0:
            lines.append(f"    {sev:<10} : {count}")
    lines.append("")

    # --- Alert details ---
    lines.append("-" * 72)
    lines.append("  ALERT DETAILS")
    lines.append("-" * 72)

    for i, alert in enumerate(alerts, 1):
        mitre = alert.get("mitre", {})
        lines.append("")
        lines.append(f"  [{i}] {alert.get('detection', 'Unknown Detection')}")
        lines.append(f"      Severity  : {alert.get('severity', 'N/A')}")
        lines.append(f"      Timestamp : {alert.get('timestamp', alert.get('time_window_start', 'N/A'))}")
        lines.append(f"      Computer  : {alert.get('computer', 'N/A')}")
        lines.append(f"      MITRE     : {mitre.get('technique_id', 'N/A')} - {mitre.get('technique_name', 'N/A')}")
        lines.append(f"      Tactic    : {mitre.get('tactic', 'N/A')}")
        lines.append(f"      Detail    : {alert.get('description', 'N/A')}")

    lines.append("")
    lines.append("-" * 72)
    lines.append("  RECOMMENDATIONS")
    lines.append("-" * 72)
    lines.append("")

    if stats.get("CRITICAL", 0) > 0:
        lines.append("  [!] CRITICAL findings require IMMEDIATE investigation.")
        lines.append("      - Isolate affected hosts if active compromise is suspected.")
        lines.append("      - Preserve forensic evidence before remediation.")
        lines.append("")

    if stats.get("HIGH", 0) > 0:
        lines.append("  [!] HIGH findings should be triaged within 4 hours.")
        lines.append("      - Correlate with SIEM for additional context.")
        lines.append("      - Verify with asset owners whether activity is authorized.")
        lines.append("")

    lines.append("  General:")
    lines.append("      - Review all flagged accounts for unauthorized access.")
    lines.append("      - Validate group membership changes against change tickets.")
    lines.append("      - Block or investigate source IPs associated with brute-force.")
    lines.append("      - Search for lateral movement indicators on affected hosts.")
    lines.append("")
    lines.append("=" * 72)
    lines.append("  END OF REPORT")
    lines.append("=" * 72)
    lines.append("")

    report_text = "\n".join(lines)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(report_text)

    logger.info("Wrote incident report to %s", output_path)
