"""
soar/tests/test_placeholder.py — Placeholder test stubs for Task 6

Run with:
    cd soar && python -m pytest tests/ -v

Each test is currently skipped — students replace pytest.skip() calls
with real assertions as they implement the corresponding features.
"""

import pytest


def test_alert_deduplication():
    """
    Submitting an alert with the same alert_id a second time must return 409.

    TODO (Task 6):
        1. Create a test Flask client from the app factory.
        2. POST a valid alert payload to /api/alerts.
        3. POST the same payload again.
        4. Assert the second response has status code 409.
        5. Assert the response body contains {"error": "duplicate alert_id"} or similar.
    """
    pytest.skip("TODO: implement")


def test_ioc_enrichment_high_score():
    """
    An alert whose source IP has a reputation score > 70 must result in
    the incident being created with severity 'high'.

    TODO (Task 6):
        1. Patch _get_ioc_score to return 85 for a given IP.
        2. Submit an alert with severity 'low' but that IP as source_ip.
        3. Query GET /api/incidents/<id>.
        4. Assert incident severity == 'high'.
    """
    pytest.skip("TODO: implement")


def test_critical_asset_severity_upgrade():
    """
    An alert targeting a destination IP flagged as 'critical' in assets.json
    must have its severity upgraded by one level.

    TODO (Task 6):
        1. Submit an alert with severity 'medium' and destination_ip 10.0.0.15
           (the DB server, which is 'critical' in assets.json).
        2. Fetch the resulting incident.
        3. Assert incident severity == 'high' (one level up from 'medium').
    """
    pytest.skip("TODO: implement")


def test_veris_classification_stored():
    """
    Closing an incident with a VERIS payload must persist the classification.

    TODO (Task 6):
        1. Create an incident (via a POST /api/alerts).
        2. POST /api/incidents/<id>/close with a full VERIS payload.
        3. GET /api/incidents/<id> and parse the response.
        4. Assert veris_classification is a non-null dict.
        5. Assert the top-level VERIS keys (actor, action, asset, attribute) are present.
    """
    pytest.skip("TODO: implement")


def test_mttd_calculation():
    """
    MTTD (Mean Time to Detect) must be computed as the delta between the
    alert timestamp and the incident detection_time, expressed in hours.

    TODO (Task 6):
        1. Create an alert with a specific timestamp (e.g. 2 hours ago).
        2. Let the playbook create an incident; verify detection_time is set.
        3. Close the incident.
        4. Assert mttd_hours ≈ 2.0  (within a small tolerance).
    """
    pytest.skip("TODO: implement")
