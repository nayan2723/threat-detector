"""
detectors.py - Threat Detection Rules

Each detector function receives a list of parsed event dicts and returns
a list of alert dicts.  Alerts carry enough context for a SOC analyst to
triage without re-reading the raw log.

Detection categories:
    1. Brute-force login attempts (4625 correlation)
    2. Suspicious account creation (4720)
    3. Privilege escalation via group modification (4728 / 4732)
    4. Encoded PowerShell execution (4688)
    5. Process creation anomalies (4688)
"""

import re
import logging
from datetime import datetime, timedelta
from collections import defaultdict

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configurable thresholds
# ---------------------------------------------------------------------------

# Number of failed logins from the same account within the time window
# that triggers a brute-force alert.  NIST 800-53 AC-7 recommends
# lockout after 3-5 consecutive failures; we alert at 5 to reduce
# false positives while still catching real attacks.
BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW_MINUTES = 10

# Sensitive local/domain groups whose modification warrants an alert.
# Adding a user to any of these is a classic privilege-escalation move.
SENSITIVE_GROUPS = {
    "administrators",
    "domain admins",
    "enterprise admins",
    "schema admins",
    "account operators",
    "backup operators",
    "server operators",
    "remote desktop users",
}

# Processes that are commonly abused by adversaries for living-off-the-land
# (LOLBin) execution.  Presence alone isn't malicious, but combined with
# unusual parent processes or encoded arguments it is highly suspicious.
SUSPICIOUS_PROCESSES = {
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "regsvr32.exe",
    "rundll32.exe",
    "certutil.exe",
    "bitsadmin.exe",
    "msiexec.exe",
    "wmic.exe",
    "psexec.exe",
}

# Parent processes that should almost never spawn the above LOLBins.
# If they do, it is a strong indicator of exploitation (e.g. Office macro
# spawning cmd.exe → T1204.002 User Execution: Malicious File).
ANOMALOUS_PARENTS = {
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "outlook.exe",
    "iexplore.exe",
    "msedge.exe",
    "chrome.exe",
    "firefox.exe",
    "notepad.exe",
    "explorer.exe",
    "svchost.exe",
}


def _ts(event: dict) -> datetime:
    """Convert an event's ISO timestamp string to a datetime for comparison."""
    try:
        return datetime.strptime(event["timestamp"], "%Y-%m-%dT%H:%M:%S")
    except (ValueError, KeyError):
        return datetime.min


# ===========================
# 1. Brute-Force Detection
# ===========================

def detect_brute_force(events: list[dict]) -> list[dict]:
    """
    Correlate repeated failed logins (4625) for the same target account
    within a sliding time window.

    SOC logic:
        - Group 4625 events by TargetUserName.
        - Sort each group chronologically.
        - Slide a window of BRUTE_FORCE_WINDOW_MINUTES across the timeline.
        - If the count inside any window >= threshold, fire an alert.
    """
    alerts = []
    failed_logins: dict[str, list[dict]] = defaultdict(list)

    for event in events:
        if event["event_id"] == 4625:
            target_user = event["event_data"].get("TargetUserName", "UNKNOWN")
            # Filter out machine accounts (end with $) — they generate
            # routine auth noise and are rarely brute-force targets.
            if target_user.endswith("$"):
                continue
            failed_logins[target_user].append(event)

    for username, attempts in failed_logins.items():
        attempts.sort(key=_ts)
        timestamps = [_ts(e) for e in attempts]

        # Sliding window: advance start pointer while window exceeds size
        start = 0
        for end in range(len(timestamps)):
            while (timestamps[end] - timestamps[start]) > timedelta(
                minutes=BRUTE_FORCE_WINDOW_MINUTES
            ):
                start += 1

            window_count = end - start + 1
            if window_count >= BRUTE_FORCE_THRESHOLD:
                # Collect source IPs for analyst context
                window_events = attempts[start : end + 1]
                source_ips = {
                    e["event_data"].get("IpAddress", "N/A") for e in window_events
                }

                alerts.append({
                    "detection": "Brute-Force Login Attempt",
                    "mitre_key": "brute_force",
                    "severity": "HIGH",
                    "target_user": username,
                    "failed_count": window_count,
                    "time_window_start": attempts[start]["timestamp"],
                    "time_window_end": attempts[end]["timestamp"],
                    "source_ips": list(source_ips),
                    "computer": attempts[start].get("computer", "UNKNOWN"),
                    "description": (
                        f"{window_count} failed logins for '{username}' within "
                        f"{BRUTE_FORCE_WINDOW_MINUTES} minutes from IPs: "
                        f"{', '.join(source_ips)}"
                    ),
                })
                # Only report once per user per window cluster — advance past it
                break

    logger.info("Brute-force detector: %d alerts", len(alerts))
    return alerts


# ===========================
# 2. Account Creation
# ===========================

def detect_account_creation(events: list[dict]) -> list[dict]:
    """
    Flag every 4720 (user account created) event.

    In most environments, account creation is infrequent and performed
    through ticketed workflows.  Any out-of-band creation deserves
    analyst review — especially if the SubjectUserName is not a known
    provisioning service account.
    """
    alerts = []

    for event in events:
        if event["event_id"] == 4720:
            ed = event["event_data"]
            new_user = ed.get("TargetUserName", "UNKNOWN")
            created_by = ed.get("SubjectUserName", "UNKNOWN")

            # Severity is CRITICAL if the creator is not SYSTEM or a
            # well-known service account pattern.
            severity = "MEDIUM"
            if created_by.upper() not in ("SYSTEM", "LOCALSERVICE", "NETWORKSERVICE"):
                severity = "HIGH"

            alerts.append({
                "detection": "New User Account Created",
                "mitre_key": "account_creation",
                "severity": severity,
                "new_user": new_user,
                "created_by": created_by,
                "timestamp": event["timestamp"],
                "computer": event.get("computer", "UNKNOWN"),
                "description": (
                    f"Account '{new_user}' created by '{created_by}' "
                    f"on {event.get('computer', 'UNKNOWN')} at {event['timestamp']}"
                ),
            })

    logger.info("Account creation detector: %d alerts", len(alerts))
    return alerts


# ===========================
# 3. Privilege Escalation
# ===========================

def detect_privilege_escalation(events: list[dict]) -> list[dict]:
    """
    Detect when a member is added to a sensitive security group
    (4728 = global group, 4732 = local group).

    Adding users to Administrators / Domain Admins outside of change
    windows is a hallmark of post-compromise privilege escalation.
    """
    alerts = []

    for event in events:
        if event["event_id"] in (4728, 4732):
            ed = event["event_data"]
            group_name = ed.get("TargetUserName", "UNKNOWN")
            member = ed.get("MemberName", ed.get("MemberSid", "UNKNOWN"))
            changed_by = ed.get("SubjectUserName", "UNKNOWN")
            group_type = "global" if event["event_id"] == 4728 else "local"

            # Only alert on sensitive groups to avoid noise from routine
            # group management (e.g. adding users to "Print Operators").
            if group_name.lower() not in SENSITIVE_GROUPS:
                continue

            alerts.append({
                "detection": "Privilege Escalation - Group Modification",
                "mitre_key": "privilege_escalation_group",
                "severity": "CRITICAL",
                "group_name": group_name,
                "group_type": group_type,
                "member_added": member,
                "changed_by": changed_by,
                "timestamp": event["timestamp"],
                "computer": event.get("computer", "UNKNOWN"),
                "description": (
                    f"'{member}' added to sensitive {group_type} group "
                    f"'{group_name}' by '{changed_by}' at {event['timestamp']}"
                ),
            })

    logger.info("Privilege escalation detector: %d alerts", len(alerts))
    return alerts


# ===========================
# 4. Encoded PowerShell
# ===========================

# Regex to match Base64-encoded command flags used to bypass logging.
# Adversaries use -EncodedCommand (-enc, -e, -ec) to obfuscate payloads.
_ENCODED_CMD_RE = re.compile(
    r"(?i)-(?:encoded(?:command)?|enc?|ec)\s+[A-Za-z0-9+/=]{20,}"
)


def detect_encoded_powershell(events: list[dict]) -> list[dict]:
    """
    Flag 4688 (process creation) events where the command line contains
    a Base64-encoded PowerShell command.

    Encoded commands are the #1 technique adversaries use to evade
    command-line logging and static detection.  Legitimate admin scripts
    rarely use -EncodedCommand in production.
    """
    alerts = []

    for event in events:
        if event["event_id"] != 4688:
            continue

        ed = event["event_data"]
        cmdline = ed.get("CommandLine", "")
        process = ed.get("NewProcessName", "").lower()

        # Only check PowerShell processes
        if "powershell" not in process and "pwsh" not in process:
            continue

        if _ENCODED_CMD_RE.search(cmdline):
            alerts.append({
                "detection": "Encoded PowerShell Execution",
                "mitre_key": "encoded_powershell",
                "severity": "CRITICAL",
                "username": ed.get("SubjectUserName", "UNKNOWN"),
                "process": ed.get("NewProcessName", "UNKNOWN"),
                "command_line": cmdline,
                "parent_process": ed.get("ParentProcessName", "UNKNOWN"),
                "timestamp": event["timestamp"],
                "computer": event.get("computer", "UNKNOWN"),
                "description": (
                    f"Encoded PowerShell detected on {event.get('computer', 'UNKNOWN')} "
                    f"by user '{ed.get('SubjectUserName', 'UNKNOWN')}' at {event['timestamp']}"
                ),
            })

    logger.info("Encoded PowerShell detector: %d alerts", len(alerts))
    return alerts


# ===========================
# 5. Process Anomalies
# ===========================

def detect_process_anomalies(events: list[dict]) -> list[dict]:
    """
    Flag 4688 events with suspicious process/parent-process combinations.

    Two sub-checks:
        a) Known LOLBin spawned by an anomalous parent (e.g. WINWORD.EXE
           → cmd.exe) — strong indicator of macro-based initial access.
        b) Any process from a user-writable temp directory — common for
           malware droppers that write to %TEMP% and execute.
    """
    alerts = []

    for event in events:
        if event["event_id"] != 4688:
            continue

        ed = event["event_data"]
        new_proc = ed.get("NewProcessName", "").lower()
        parent_proc = ed.get("ParentProcessName", "").lower()
        proc_basename = new_proc.rsplit("\\", 1)[-1] if "\\" in new_proc else new_proc
        parent_basename = (
            parent_proc.rsplit("\\", 1)[-1] if "\\" in parent_proc else parent_proc
        )
        cmdline = ed.get("CommandLine", "")

        # (a) LOLBin spawned from anomalous parent
        if proc_basename in SUSPICIOUS_PROCESSES and parent_basename in ANOMALOUS_PARENTS:
            alerts.append({
                "detection": "Suspicious Process Lineage",
                "mitre_key": "process_anomaly",
                "severity": "HIGH",
                "username": ed.get("SubjectUserName", "UNKNOWN"),
                "process": new_proc,
                "parent_process": parent_proc,
                "command_line": cmdline,
                "timestamp": event["timestamp"],
                "computer": event.get("computer", "UNKNOWN"),
                "description": (
                    f"Suspicious child process '{proc_basename}' spawned by "
                    f"'{parent_basename}' on {event.get('computer', 'UNKNOWN')} "
                    f"at {event['timestamp']}"
                ),
            })

        # (b) Execution from temp / user-writable directories
        temp_indicators = ("\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\")
        if any(indicator in new_proc for indicator in temp_indicators):
            alerts.append({
                "detection": "Process Execution from Temp Directory",
                "mitre_key": "suspicious_process",
                "severity": "MEDIUM",
                "username": ed.get("SubjectUserName", "UNKNOWN"),
                "process": new_proc,
                "parent_process": parent_proc,
                "command_line": cmdline,
                "timestamp": event["timestamp"],
                "computer": event.get("computer", "UNKNOWN"),
                "description": (
                    f"Process '{new_proc}' executed from temp directory "
                    f"on {event.get('computer', 'UNKNOWN')} at {event['timestamp']}"
                ),
            })

    logger.info("Process anomaly detector: %d alerts", len(alerts))
    return alerts


# ===========================
# Aggregator
# ===========================

def run_all_detectors(events: list[dict]) -> list[dict]:
    """
    Execute every detection rule and return a merged, de-duplicated alert list.

    This is the single entry point the engine calls — new detectors only
    need to be added to the `detectors` list below.
    """
    detectors = [
        detect_brute_force,
        detect_account_creation,
        detect_privilege_escalation,
        detect_encoded_powershell,
        detect_process_anomalies,
    ]

    all_alerts = []
    for detector in detectors:
        try:
            all_alerts.extend(detector(events))
        except Exception as e:
            # A single detector failure must not prevent other detectors
            # from running — defense in depth for the tool itself.
            logger.error("Detector '%s' failed: %s", detector.__name__, e)

    logger.info("Total alerts generated: %d", len(all_alerts))
    return all_alerts
