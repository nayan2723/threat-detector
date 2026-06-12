from utils import sort_alerts, severity_stats, enrich_alerts


def test_severity_stats():
    alerts = [
        {"severity": "CRITICAL"},
        {"severity": "HIGH"},
        {"severity": "CRITICAL"},
        {"severity": "LOW"},
    ]
    stats = severity_stats(alerts)
    assert stats["CRITICAL"] == 2
    assert stats["HIGH"] == 1
    assert stats["LOW"] == 1
    assert stats.get("MEDIUM", 0) == 0


def test_sort_alerts():
    alerts = [
        {"severity": "LOW", "timestamp": "2026-06-12T10:00:00"},
        {"severity": "CRITICAL", "timestamp": "2026-06-12T10:05:00"},
        {"severity": "HIGH", "timestamp": "2026-06-12T10:02:00"},
        {"severity": "CRITICAL", "timestamp": "2026-06-12T09:00:00"},
    ]
    sorted_alerts = sort_alerts(alerts)
    assert sorted_alerts[0]["severity"] == "CRITICAL"
    assert sorted_alerts[0]["timestamp"] == "2026-06-12T09:00:00"
    assert sorted_alerts[1]["severity"] == "CRITICAL"
    assert sorted_alerts[2]["severity"] == "HIGH"
    assert sorted_alerts[3]["severity"] == "LOW"


def test_enrich_alerts():
    alerts = [{"mitre_key": "brute_force"}]
    mitre_map = {
        "brute_force": {
            "technique_id": "T1110",
            "technique_name": "Brute Force",
            "tactic": "Credential Access",
        }
    }
    enriched = enrich_alerts(alerts, mitre_map)
    assert enriched[0]["mitre"]["technique_id"] == "T1110"
    assert enriched[0]["mitre"]["tactic"] == "Credential Access"
