# Windows Threat Detection Engine – Correlation-Based Log Analysis with MITRE ATT&CK Mapping

A production-grade command-line tool that parses Windows Security EVTX logs and detects suspicious activities mapped to MITRE ATT&CK techniques.

Built for SOC analysts, incident responders, and security engineers who need fast, offline triage of Windows event logs.

## Detection Capabilities

| Detection | Event ID | MITRE ATT&CK | Severity |
|---|---|---|---|
| Brute-force login attempts | 4625 | T1110 - Brute Force | HIGH |
| Suspicious account creation | 4720 | T1136 - Create Account | HIGH |
| Privilege escalation (group modification) | 4728 / 4732 | T1098 - Account Manipulation | CRITICAL |
| Encoded PowerShell execution | 4688 | T1059.001 - PowerShell | CRITICAL |
| Suspicious process lineage (LOLBin abuse) | 4688 | T1055 - Process Injection | HIGH |
| Execution from temp directories | 4688 | T1059 - Command and Scripting Interpreter | MEDIUM |

## Project Structure

```
win-threat-detector/
├── detection_engine.py      # Main CLI entry point
├── parser.py                # EVTX log parsing logic
├── detectors.py             # Threat detection rules
├── utils.py                 # MITRE enrichment, report generation
├── mitre_mapping.json       # MITRE ATT&CK technique mappings
├── generate_sample_logs.py  # Test data generator
├── requirements.txt         # Python dependencies
├── sample_logs/             # Directory for EVTX / test files
└── output/                  # Generated reports (alerts.json, incident_report.txt)
```

## Quick Start

### Prerequisites

- Python 3.10+
- pip

### Installation

```bash
git clone https://github.com/<your-username>/win-threat-detector.git
cd win-threat-detector
pip install -r requirements.txt
```

### Usage

**Scan a real EVTX file:**
```bash
python detection_engine.py --file security_logs.evtx
```

**Scan with custom output directory:**
```bash
python detection_engine.py --file security_logs.evtx --output ./results
```

**Verbose mode (debug logging):**
```bash
python detection_engine.py --file security_logs.evtx --verbose
```

**Test with sample data (no EVTX file needed):**
```bash
python generate_sample_logs.py
python detection_engine.py --file sample_logs/sample_events.json --json-input
```

### Output

The tool generates two files in the output directory:

- **`alerts.json`** — Machine-readable alert data with full MITRE ATT&CK context. Suitable for SIEM ingestion or ticketing integration.
- **`incident_report.txt`** — Human-readable incident report following SOC triage format. Includes severity breakdown, per-alert details, and response recommendations.

## Detection Logic

### Brute-Force Detection
Correlates Event ID 4625 (failed logon) records using a sliding time window. Triggers when 5+ failed logins target the same account within 10 minutes. Machine accounts (ending with `$`) are excluded to reduce noise. Source IPs are collected for analyst context.

### Account Creation
Flags all Event ID 4720 (user account created) events. Severity is elevated to HIGH when the creating account is not a system service account (SYSTEM, LOCALSERVICE, NETWORKSERVICE).

### Privilege Escalation
Monitors Event IDs 4728/4732 for membership changes to sensitive groups (Administrators, Domain Admins, Enterprise Admins, etc.). Any addition to these groups generates a CRITICAL alert.

### Encoded PowerShell
Detects Event ID 4688 (process creation) with PowerShell processes using `-EncodedCommand` (or abbreviations like `-enc`, `-e`) with Base64 payloads. This is the primary technique adversaries use to evade command-line logging.

### Process Anomalies
Two sub-detections:
1. **Suspicious process lineage** — Known LOLBins (cmd.exe, powershell.exe, etc.) spawned by unusual parents (Office apps, browsers) indicating macro exploitation.
2. **Temp directory execution** — Processes running from `%TEMP%` or `AppData\Local\Temp`, a common malware dropper pattern.

## Customization

### Tuning Thresholds
Edit the constants at the top of `detectors.py`:
- `BRUTE_FORCE_THRESHOLD` — Number of failed logins to trigger (default: 5)
- `BRUTE_FORCE_WINDOW_MINUTES` — Time window size (default: 10)
- `SENSITIVE_GROUPS` — Set of group names to monitor
- `SUSPICIOUS_PROCESSES` — LOLBin process names
- `ANOMALOUS_PARENTS` — Parent processes that shouldn't spawn LOLBins

### Adding New Detectors
1. Add a new function in `detectors.py` following the existing pattern
2. Add the function to the `detectors` list in `run_all_detectors()`
3. Add a corresponding entry in `mitre_mapping.json`

## Getting Real EVTX Files

Export Windows Security logs via:
```powershell
wevtutil epl Security C:\path\to\security_logs.evtx
```

Or copy from: `C:\Windows\System32\winevt\Logs\Security.evtx`

## Sample Output

Each alert in `alerts.json` includes detection context and MITRE ATT&CK enrichment:

```json
{
  "detection": "Brute-Force Login Attempt",
  "severity": "HIGH",
  "target_user": "admin",
  "failed_count": 5,
  "time_window_start": "2026-02-20T14:00:00",
  "time_window_end": "2026-02-20T14:02:00",
  "source_ips": ["192.168.1.100", "10.0.0.55"],
  "mitre": {
    "technique_id": "T1110",
    "technique_name": "Brute Force",
    "tactic": "Credential Access"
  }
}
```
