#!/usr/bin/env python3
"""
detection_engine.py - Windows Security Log Threat Detection Engine

Main entry point.  Orchestrates:
    1. CLI argument parsing
    2. EVTX log parsing (parser.py)
    3. Threat detection (detectors.py)
    4. MITRE ATT&CK enrichment (utils.py)
    5. Report generation (alerts.json + incident_report.txt)

Usage:
    python detection_engine.py --file security_logs.evtx
    python detection_engine.py --file logs.evtx --output ./results --verbose
"""

import argparse
import json
import logging
import sys
from pathlib import Path

from parser import parse_evtx
from detectors import run_all_detectors
from utils import (
    load_mitre_mapping,
    enrich_alerts,
    sort_alerts,
    severity_stats,
    write_alerts_json,
    write_incident_report,
)


def setup_logging(verbose: bool = False) -> None:
    """Configure root logger for console output."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)-8s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def build_cli() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="detection_engine",
        description=(
            "Windows Security Log Threat Detection Engine\n"
            "Parses EVTX logs and detects suspicious activity "
            "mapped to MITRE ATT&CK techniques."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--file", "-f",
        required=True,
        help="Path to the Windows Security EVTX log file.",
    )
    parser.add_argument(
        "--output", "-o",
        default="output",
        help="Directory for output files (default: ./output).",
    )
    parser.add_argument(
        "--mitre-map", "-m",
        default=None,
        help="Path to custom mitre_mapping.json (default: bundled file).",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose/debug logging.",
    )
    parser.add_argument(
        "--json-input",
        action="store_true",
        help="Treat --file as a JSON array of pre-parsed events (for testing).",
    )

    return parser


def main() -> int:
    """
    Main execution flow — mirrors a SOC analyst's triage workflow:
        Ingest → Parse → Detect → Enrich → Prioritize → Report
    """
    args = build_cli().parse_args()
    setup_logging(args.verbose)
    logger = logging.getLogger("detection_engine")

    evtx_path = Path(args.file)
    output_dir = Path(args.output)

    # --- Validate input ---
    if not evtx_path.exists():
        logger.error("EVTX file not found: %s", evtx_path)
        return 1

    if not str(evtx_path).lower().endswith(".evtx"):
        logger.warning("File does not have .evtx extension — proceeding anyway")

    # --- 1. Parse ---
    logger.info("=" * 60)
    logger.info("Starting threat detection scan")
    logger.info("=" * 60)
    logger.info("Input file: %s", evtx_path)

    if args.json_input:
        # Test mode: read pre-parsed events from JSON file
        with open(evtx_path, "r", encoding="utf-8") as f:
            events = json.load(f)
        logger.info("Loaded %d events from JSON test file", len(events))
    else:
        events = list(parse_evtx(str(evtx_path)))
    logger.info("Parsed %d relevant security events", len(events))

    if not events:
        logger.warning("No monitored events found in the log file.")
        return 0

    # --- 2. Detect ---
    alerts = run_all_detectors(events)

    if not alerts:
        logger.info("No threats detected. Clean scan.")
        return 0

    # --- 3. Enrich with MITRE ATT&CK context ---
    mitre_path = Path(args.mitre_map) if args.mitre_map else None
    if mitre_path:
        mitre_map = load_mitre_mapping(mitre_path)
    else:
        mitre_map = load_mitre_mapping()

    alerts = enrich_alerts(alerts, mitre_map)

    # --- 4. Prioritize ---
    alerts = sort_alerts(alerts)

    # --- 5. Report ---
    alerts_path = output_dir / "alerts.json"
    report_path = output_dir / "incident_report.txt"

    write_alerts_json(alerts, alerts_path)
    write_incident_report(alerts, report_path, str(evtx_path), len(events))

    # --- Console summary ---
    stats = severity_stats(alerts)
    logger.info("=" * 60)
    logger.info("SCAN COMPLETE — %d alert(s) generated", len(alerts))
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        count = stats.get(sev, 0)
        if count:
            logger.info("  %s: %d", sev, count)
    logger.info("Output:")
    logger.info("  Alerts JSON    : %s", alerts_path.resolve())
    logger.info("  Incident Report: %s", report_path.resolve())
    logger.info("=" * 60)

    return 0


if __name__ == "__main__":
    sys.exit(main())
