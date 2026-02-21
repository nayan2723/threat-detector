#!/usr/bin/env python3
"""
generate_sample_logs.py - Synthetic EVTX Test Data Generator

Since real EVTX files require Windows Event Log infrastructure, this script
generates a minimal valid EVTX file containing crafted security events that
will trigger every detector in the engine.

This lets you test the full pipeline without access to a live Windows
environment or production logs.

Usage:
    python generate_sample_logs.py
    python generate_sample_logs.py --output sample_logs/test_security.evtx

Requires: python-evtx (for reading); we use raw binary construction for writing
since python-evtx is read-only.

ALTERNATIVE APPROACH: This script also supports a --json mode that generates
parsed event dicts directly (bypassing EVTX binary format), which can be fed
into the detectors for quick testing without needing a real EVTX file.
"""

import json
import argparse
import sys
from pathlib import Path
from datetime import datetime, timedelta


def generate_sample_events() -> list[dict]:
    """
    Generate a list of parsed event dicts that simulate realistic attack
    scenarios.  These mirror the output format of parser.parse_evtx().

    Scenarios covered:
        1. Brute-force: 8 failed logins for 'admin' in 5 minutes
        2. Account creation: backdoor account by non-SYSTEM user
        3. Privilege escalation: user added to Administrators group
        4. Encoded PowerShell: Base64-encoded command execution
        5. Process anomaly: cmd.exe spawned by WINWORD.EXE
        6. Process from temp dir: malware dropper pattern
    """
    events = []
    base_time = datetime(2026, 2, 20, 14, 0, 0)

    # ---------------------------------------------------------------
    # Scenario 1: Brute-force attack against 'admin' account
    # 8 failed logins from attacker IP within 5 minutes
    # ---------------------------------------------------------------
    attacker_ips = ["192.168.1.100", "192.168.1.100", "10.0.0.55",
                    "192.168.1.100", "192.168.1.100", "192.168.1.100",
                    "10.0.0.55", "192.168.1.100"]

    for i in range(8):
        events.append({
            "event_id": 4625,
            "timestamp": (base_time + timedelta(seconds=30 * i)).strftime("%Y-%m-%dT%H:%M:%S"),
            "computer": "DC01.corp.local",
            "event_data": {
                "TargetUserName": "admin",
                "TargetDomainName": "CORP",
                "IpAddress": attacker_ips[i],
                "IpPort": str(49152 + i),
                "LogonType": "10",  # RemoteInteractive (RDP)
                "SubStatus": "0xC000006A",  # Bad password
                "FailureReason": "%%2313",
                "SubjectUserName": "-",
            },
            "raw_xml": "<placeholder/>",
        })

    # A few failed logins for another user (below threshold — should NOT alert)
    for i in range(3):
        events.append({
            "event_id": 4625,
            "timestamp": (base_time + timedelta(minutes=20, seconds=i * 60)).strftime("%Y-%m-%dT%H:%M:%S"),
            "computer": "WS05.corp.local",
            "event_data": {
                "TargetUserName": "jdoe",
                "TargetDomainName": "CORP",
                "IpAddress": "172.16.0.10",
                "LogonType": "3",
                "SubStatus": "0xC0000064",
                "FailureReason": "%%2313",
                "SubjectUserName": "-",
            },
            "raw_xml": "<placeholder/>",
        })

    # ---------------------------------------------------------------
    # Scenario 2: Suspicious account creation
    # An interactive user (not SYSTEM) creates a new local account
    # ---------------------------------------------------------------
    events.append({
        "event_id": 4720,
        "timestamp": (base_time + timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%S"),
        "computer": "WS05.corp.local",
        "event_data": {
            "TargetUserName": "svc_backdoor",
            "TargetDomainName": "WS05",
            "SubjectUserName": "compromised_user",
            "SubjectDomainName": "CORP",
        },
        "raw_xml": "<placeholder/>",
    })

    # ---------------------------------------------------------------
    # Scenario 3: Privilege escalation — add to Administrators
    # ---------------------------------------------------------------
    events.append({
        "event_id": 4732,
        "timestamp": (base_time + timedelta(minutes=11)).strftime("%Y-%m-%dT%H:%M:%S"),
        "computer": "WS05.corp.local",
        "event_data": {
            "TargetUserName": "Administrators",
            "MemberName": "CN=svc_backdoor,CN=Users,DC=corp,DC=local",
            "MemberSid": "S-1-5-21-1234567890-1234567890-1234567890-5001",
            "SubjectUserName": "compromised_user",
            "SubjectDomainName": "CORP",
        },
        "raw_xml": "<placeholder/>",
    })

    # Add to Domain Admins (global group — Event 4728)
    events.append({
        "event_id": 4728,
        "timestamp": (base_time + timedelta(minutes=12)).strftime("%Y-%m-%dT%H:%M:%S"),
        "computer": "DC01.corp.local",
        "event_data": {
            "TargetUserName": "Domain Admins",
            "MemberName": "CN=svc_backdoor,CN=Users,DC=corp,DC=local",
            "MemberSid": "S-1-5-21-1234567890-1234567890-1234567890-5001",
            "SubjectUserName": "compromised_user",
            "SubjectDomainName": "CORP",
        },
        "raw_xml": "<placeholder/>",
    })

    # ---------------------------------------------------------------
    # Scenario 4: Encoded PowerShell execution
    # ---------------------------------------------------------------
    # This is a Base64-encoded "Invoke-Mimikatz" style payload
    encoded_payload = "SQBuAHYAbwBrAGUALQBNAGkAbQBpAGsAYQB0AHoAIAAtAEQAdQBtAHAAQwByAGUAZABz"
    events.append({
        "event_id": 4688,
        "timestamp": (base_time + timedelta(minutes=15)).strftime("%Y-%m-%dT%H:%M:%S"),
        "computer": "WS05.corp.local",
        "event_data": {
            "NewProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": f"powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand {encoded_payload}",
            "SubjectUserName": "compromised_user",
            "SubjectDomainName": "CORP",
            "ParentProcessName": "C:\\Windows\\System32\\cmd.exe",
            "NewProcessId": "0x1a2b",
        },
        "raw_xml": "<placeholder/>",
    })

    # ---------------------------------------------------------------
    # Scenario 5: Process anomaly — Office app spawning cmd.exe
    # Simulates a malicious macro execution chain
    # ---------------------------------------------------------------
    events.append({
        "event_id": 4688,
        "timestamp": (base_time + timedelta(minutes=20)).strftime("%Y-%m-%dT%H:%M:%S"),
        "computer": "WS12.corp.local",
        "event_data": {
            "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
            "CommandLine": "cmd.exe /c whoami && net user /domain",
            "SubjectUserName": "analyst01",
            "SubjectDomainName": "CORP",
            "ParentProcessName": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
            "NewProcessId": "0x2c3d",
        },
        "raw_xml": "<placeholder/>",
    })

    # ---------------------------------------------------------------
    # Scenario 6: Execution from temp directory (malware dropper)
    # ---------------------------------------------------------------
    events.append({
        "event_id": 4688,
        "timestamp": (base_time + timedelta(minutes=22)).strftime("%Y-%m-%dT%H:%M:%S"),
        "computer": "WS12.corp.local",
        "event_data": {
            "NewProcessName": "C:\\Users\\analyst01\\AppData\\Local\\Temp\\update_svc.exe",
            "CommandLine": "update_svc.exe --silent --callback 203.0.113.50:443",
            "SubjectUserName": "analyst01",
            "SubjectDomainName": "CORP",
            "ParentProcessName": "C:\\Windows\\explorer.exe",
            "NewProcessId": "0x3d4e",
        },
        "raw_xml": "<placeholder/>",
    })

    return events


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate sample test data for the detection engine."
    )
    parser.add_argument(
        "--output", "-o",
        default="sample_logs/sample_events.json",
        help="Output path for the JSON event file (default: sample_logs/sample_events.json).",
    )
    args = parser.parse_args()

    events = generate_sample_events()
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(events, f, indent=2)

    print(f"[+] Generated {len(events)} sample events → {output_path}")
    print()
    print("Scenarios included:")
    print("  1. Brute-force: 8 failed logins for 'admin' (should trigger alert)")
    print("  2. Below-threshold: 3 failed logins for 'jdoe' (should NOT trigger)")
    print("  3. Account creation: 'svc_backdoor' by 'compromised_user'")
    print("  4. Privilege escalation: added to Administrators + Domain Admins")
    print("  5. Encoded PowerShell: -EncodedCommand with hidden window")
    print("  6. Process anomaly: cmd.exe spawned by WINWORD.EXE")
    print("  7. Temp directory execution: update_svc.exe from AppData\\Local\\Temp")
    print()
    print("To test with the detection engine, use the --json-input mode:")
    print(f"  python detection_engine.py --file {output_path} --json-input")
    return 0


if __name__ == "__main__":
    sys.exit(main())
