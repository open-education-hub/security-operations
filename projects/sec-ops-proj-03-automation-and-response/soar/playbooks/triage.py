"""
soar/playbooks/triage.py — Automated Alert Triage Playbook

This playbook is triggered automatically for every new alert received by the
SOAR API (Task 2).  Students implement each step below.

Playbook steps
--------------
1. IOC Enrichment   — look up the source IP in the local mock reputation DB
2. Asset Lookup     — check destination IP against the asset inventory
3. Deduplication    — merge into an existing open incident if one exists for
                      the same source IP within the last 2 hours
4. Auto-ticket      — assign priority (P1/P2/P3) based on final severity
5. Notification     — write a log entry for P1 incidents
"""

import json
import os
import datetime
import uuid

# ---------------------------------------------------------------------------
# Paths to supporting data files (populated by the Docker volume mount)
# ---------------------------------------------------------------------------
IOC_DB_PATH = os.environ.get("IOC_DB_PATH", "/data/ioc_db.json")
ASSETS_DB_PATH = os.environ.get("ASSETS_DB_PATH", "/data/assets.json")
NOTIFICATIONS_LOG = os.environ.get(
    "NOTIFICATIONS_LOG", "/app/soar/notifications/p1_alerts.log"
)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_triage(alert_data: dict, db) -> str:
    """
    Execute the full triage playbook for a new alert.

    Args:
        alert_data: Validated alert dict (keys: alert_id, timestamp,
                    rule_name, severity, source_ip, destination_ip,
                    destination_port, raw_log).
        db:         The soar.database module (provides fetch_one, fetch_all,
                    execute_query).

    Returns:
        str: The incident_id that was created or updated.

    TODO (Task 2) — implement each step in order:
        Step 1  → call _get_ioc_score() and adjust severity
        Step 2  → call _get_asset_criticality() and upgrade severity if needed
        Step 3  → call _find_existing_incident() to check for deduplication
        Step 4  → call _create_incident() or link to existing one
        Step 5  → assign priority; if P1, write to notifications log
    """

    # -----------------------------------------------------------------------
    # Step 1: IOC Enrichment
    # -----------------------------------------------------------------------
    # TODO: Load /data/ioc_db.json (see _load_json helper below).
    # TODO: Call _get_ioc_score(alert_data["source_ip"], ioc_db).
    # TODO: If score > 70  → severity = "high"
    #       If score 40-70 → severity = "medium"
    #       Otherwise      → keep alert_data["severity"]
    ioc_db = _load_json(IOC_DB_PATH)
    severity = alert_data.get("severity", "low")
    # TODO: replace the line below with the enrichment logic
    ioc_score = _get_ioc_score(alert_data.get("source_ip", ""), ioc_db)  # noqa: F841

    # -----------------------------------------------------------------------
    # Step 2: Asset Lookup
    # -----------------------------------------------------------------------
    # TODO: Load /data/assets.json.
    # TODO: Call _get_asset_criticality(alert_data["destination_ip"], assets_db).
    # TODO: If criticality is "critical" or "high", upgrade severity by one level.
    #       Severity ladder (low → medium → high → critical).
    assets_db = _load_json(ASSETS_DB_PATH)
    if not isinstance(assets_db, list):
        assets_db = []
    # TODO: replace the line below with the asset criticality logic
    asset_criticality = _get_asset_criticality(  # noqa: F841
        alert_data.get("destination_ip", ""), assets_db
    )

    # -----------------------------------------------------------------------
    # Step 3: Deduplication
    # -----------------------------------------------------------------------
    # TODO: Query the incidents table for any open incident with the same
    #       source_ip created within the last 2 hours.
    # TODO: If one exists, link this alert to it (UPDATE alerts SET incident_id)
    #       and return the existing incident_id without creating a new ticket.
    incident_id = None  # will be set in Step 4

    # -----------------------------------------------------------------------
    # Step 4: Auto-ticket creation
    # -----------------------------------------------------------------------
    # TODO: If no existing incident was found in Step 3, call _create_incident().
    # TODO: Determine priority:
    #         severity == "critical" or "high" → P1
    #         severity == "medium"             → P2
    #         severity == "low"                → P3
    if incident_id is None:
        incident_id = _create_incident(alert_data, severity, db)

    # -----------------------------------------------------------------------
    # Step 5: Notification for P1 incidents
    # -----------------------------------------------------------------------
    # TODO: If priority == P1, append a line to NOTIFICATIONS_LOG:
    #   [<timestamp>] P1 ALERT: <incident_id> — <rule_name> from <source_ip>
    #   targeting <destination hostname or IP>
    # TODO: Also insert a row into the notifications table via db.execute_query().

    return incident_id


# ---------------------------------------------------------------------------
# Private helper stubs
# ---------------------------------------------------------------------------

def _load_json(path: str):
    """Load and return a JSON file, or an empty dict/list on error."""
    try:
        with open(path) as fh:
            return json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _get_ioc_score(ip: str, ioc_db: dict) -> int:
    """
    Look up *ip* in the IOC reputation database.

    Args:
        ip:     IP address string to look up.
        ioc_db: Dict loaded from /data/ioc_db.json — keys are IP strings,
                values are dicts with at least a "score" field (0-100).

    Returns:
        int: Reputation score (0 = clean, 100 = highly malicious).
             Returns 0 if the IP is not found.

    TODO (Task 2 — Step 1):
        Return ioc_db[ip]["score"] if ip is in ioc_db, else 0.
    """
    # TODO: implement IOC score lookup
    return 0


def _get_asset_criticality(ip: str, assets_db: list) -> str:
    """
    Look up the criticality rating of the destination asset.

    Args:
        ip:         Destination IP address.
        assets_db:  List loaded from /data/assets.json — each item is a dict
                    with at least "ip" and "criticality" fields.

    Returns:
        str: One of "critical", "high", "medium", "low".
             Returns "low" if the IP is not found in the inventory.

    TODO (Task 2 — Step 2):
        Iterate over assets_db, find the entry whose "ip" matches,
        return its "criticality".  Return "low" if not found.
    """
    # TODO: implement asset criticality lookup
    return "low"


def _find_existing_incident(source_ip: str, db) -> str | None:
    """
    Check for an open incident with the same source IP within the last 2 hours.

    Args:
        source_ip: Source IP from the new alert.
        db:        The soar.database module.

    Returns:
        str | None: incident_id of the existing incident, or None.

    TODO (Task 2 — Step 3):
        Use db.fetch_one() with a SQL query that checks:
            status IN ('open', 'investigating')
            AND source_ip = ?
            AND created_at >= datetime('now', '-2 hours')
    """
    # TODO: implement deduplication check
    return None


def _create_incident(alert_data: dict, severity: str, db) -> str:
    """
    Create a new incident record in the database and link the triggering alert.

    Args:
        alert_data: The alert dict.
        severity:   Final severity after enrichment.
        db:         The soar.database module.

    Returns:
        str: The newly generated incident_id (format: INC-YYYY-NNNNNN).

    TODO (Task 2 — Step 4):
        1. Generate a unique incident_id, e.g.:
               year = datetime.datetime.utcnow().year
               seq  = str(uuid.uuid4().int)[:6]
               incident_id = f"INC-{year}-{seq}"
        2. Build a title from the rule_name and source_ip.
        3. INSERT into incidents (incident_id, status, severity, source_ip,
               title, detection_time).
        4. UPDATE alerts SET incident_id = ? WHERE alert_id = ?.
        5. Return incident_id.
    """
    # TODO: implement incident creation
    year = datetime.datetime.utcnow().year
    seq = str(uuid.uuid4().int)[:6]
    incident_id = f"INC-{year}-{seq}"
    return incident_id
