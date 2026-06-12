from detectors import detect_account_creation, detect_privilege_escalation


def test_detect_account_creation():
    events = [
        {
            "event_id": 4720,
            "timestamp": "2026-06-12T10:00:00",
            "computer": "DC01",
            "event_data": {"TargetUserName": "hacker", "SubjectUserName": "admin"},
        },
        {
            "event_id": 4720,
            "timestamp": "2026-06-12T10:05:00",
            "computer": "DC01",
            "event_data": {
                "TargetUserName": "svc_account",
                "SubjectUserName": "SYSTEM",
            },
        },
    ]
    alerts = detect_account_creation(events)
    assert len(alerts) == 2
    assert alerts[0]["severity"] == "HIGH"  # admin created hacker
    assert alerts[1]["severity"] == "MEDIUM"  # SYSTEM created svc_account


def test_detect_privilege_escalation():
    events = [
        {
            "event_id": 4728,
            "timestamp": "2026-06-12T10:00:00",
            "computer": "DC01",
            "event_data": {
                "TargetUserName": "Administrators",
                "MemberName": "hacker",
                "SubjectUserName": "admin",
            },
        },
        {
            "event_id": 4728,
            "timestamp": "2026-06-12T10:05:00",
            "computer": "DC01",
            "event_data": {
                "TargetUserName": "Print Operators",
                "MemberName": "printer_guy",
                "SubjectUserName": "admin",
            },
        },
    ]
    alerts = detect_privilege_escalation(events)
    assert len(alerts) == 1
    assert alerts[0]["severity"] == "CRITICAL"
    assert alerts[0]["group_name"] == "Administrators"
    assert alerts[0]["member_added"] == "hacker"
