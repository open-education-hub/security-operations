"""
soar/app.py — SOAR API Flask Application

This is the main entry point for the SOAR REST API.
Students implement each route stub to complete the project tasks.
"""

from flask import Flask, request, jsonify

# ---------------------------------------------------------------------------
# Imports — students will need these when implementing the routes
# ---------------------------------------------------------------------------
from soar.database import init_db
from soar.playbooks.triage import run_triage  # noqa: F401  (used in Task 1)


def create_app():
    """Application factory."""
    app = Flask(__name__)

    # -----------------------------------------------------------------------
    # Initialise the SQLite database on first startup.
    # The schema is defined in soar/database.py — do NOT recreate tables here.
    # -----------------------------------------------------------------------
    init_db()

    # -----------------------------------------------------------------------
    # Task 1 — Alert Ingestion
    # POST /api/alerts
    # -----------------------------------------------------------------------
    @app.route("/api/alerts", methods=["POST"])
    def ingest_alert():
        """
        Receive a new alert from the SIEM.

        Expected JSON body:
            {
                "alert_id": "SIEM-2024-003421",
                "timestamp": "2024-03-15T10:23:41Z",
                "rule_name": "HTTP Brute Force",
                "severity": "medium",
                "source_ip": "185.220.101.42",
                "destination_ip": "10.0.0.15",
                "destination_port": 443,
                "raw_log": "..."
            }

        Returns:
            201  {"incident_id": "INC-2024-001", "status": "created"}
            400  {"error": "missing required field: <field>"}
            409  {"error": "duplicate alert_id"}

        TODO (Task 1):
            1. Validate that all required fields are present.
            2. Check for duplicate alert_id in the alerts table (return 409 if found).
            3. Persist the alert to the database.
            4. Call run_triage(alert_data, db) to trigger the triage playbook.
            5. Return the incident_id and status.
        """
        # TODO: implement this endpoint
        return jsonify({"status": "not implemented"}), 501

    # -----------------------------------------------------------------------
    # Task 3 — Incident Lifecycle: List incidents
    # GET /api/incidents
    # -----------------------------------------------------------------------
    @app.route("/api/incidents", methods=["GET"])
    def list_incidents():
        """
        List all incidents, with optional query-string filters:
            ?status=open|investigating|contained|closed
            ?severity=critical|high|medium|low
            ?from=YYYY-MM-DD
            ?to=YYYY-MM-DD

        Returns:
            200  {"incidents": [...], "total": N}

        TODO (Task 3):
            1. Parse optional query-string filters from request.args.
            2. Build a dynamic SQL query with WHERE clauses for each filter.
            3. Return all matching incidents as a JSON list.
        """
        # TODO: implement this endpoint
        return jsonify({"status": "not implemented"}), 501

    # -----------------------------------------------------------------------
    # Task 3 — Incident Lifecycle: Get single incident
    # GET /api/incidents/<id>
    # -----------------------------------------------------------------------
    @app.route("/api/incidents/<incident_id>", methods=["GET"])
    def get_incident(incident_id):
        """
        Return full details for a single incident, including:
            - Incident fields
            - All associated alerts
            - All analyst notes

        Returns:
            200  {"incident": {...}, "alerts": [...], "notes": [...]}
            404  {"error": "incident not found"}

        TODO (Task 3):
            1. Fetch the incident row by incident_id.
            2. Fetch all alerts whose incident_id matches.
            3. Fetch all notes for the incident.
            4. Return combined JSON.
        """
        # TODO: implement this endpoint
        return jsonify({"status": "not implemented"}), 501

    # -----------------------------------------------------------------------
    # Task 3 — Incident Lifecycle: Update status
    # PATCH /api/incidents/<id>/status
    # -----------------------------------------------------------------------
    @app.route("/api/incidents/<incident_id>/status", methods=["PATCH"])
    def update_incident_status(incident_id):
        """
        Transition an incident to the next status.

        Valid transitions:  open → investigating → contained → closed
        (Use POST /close for the final closed transition with VERIS data.)

        Expected JSON body:
            {"status": "investigating"}

        Returns:
            200  {"incident_id": "...", "status": "investigating"}
            400  {"error": "invalid status transition"}
            404  {"error": "incident not found"}

        TODO (Task 3):
            1. Validate the requested status value.
            2. Enforce the allowed transition order.
            3. Update the incidents table; record contained_time if status == 'contained'.
            4. Return updated incident.
        """
        # TODO: implement this endpoint
        return jsonify({"status": "not implemented"}), 501

    # -----------------------------------------------------------------------
    # Task 3 — Incident Lifecycle: Add analyst notes
    # POST /api/incidents/<id>/notes
    # -----------------------------------------------------------------------
    @app.route("/api/incidents/<incident_id>/notes", methods=["POST"])
    def add_incident_note(incident_id):
        """
        Append a timestamped analyst note to an incident.

        Expected JSON body:
            {"analyst": "alice", "note": "Started investigation, isolating host."}

        Returns:
            201  {"note_id": N, "incident_id": "...", "timestamp": "..."}
            404  {"error": "incident not found"}

        TODO (Task 3):
            1. Verify the incident exists.
            2. Insert a row into incident_notes with the current UTC timestamp.
            3. Return the new note metadata.
        """
        # TODO: implement this endpoint
        return jsonify({"status": "not implemented"}), 501

    # -----------------------------------------------------------------------
    # Task 3 — Incident Lifecycle: Close incident with VERIS
    # POST /api/incidents/<id>/close
    # -----------------------------------------------------------------------
    @app.route("/api/incidents/<incident_id>/close", methods=["POST"])
    def close_incident(incident_id):
        """
        Close an incident and store VERIS classification + resolution.

        Expected JSON body:
            {
                "resolution": "Blocked source IP, no breach confirmed",
                "veris": {
                    "actor": {"external": {"variety": ["Unknown"]}},
                    "action": {"hacking": {"variety": ["Brute-force"], "vector": ["Web application"]}},
                    "asset": {"assets": [{"variety": "S - Web application"}]},
                    "attribute": {"confidentiality": {"data_disclosed": "No"}}
                }
            }

        Returns:
            200  {"incident_id": "...", "status": "closed", "mttr_hours": X.X}
            400  {"error": "veris field required"}
            404  {"error": "incident not found"}

        TODO (Task 3 / Task 4):
            1. Validate the request body contains 'veris' and 'resolution'.
            2. Set status = 'closed', record closed_time.
            3. Compute mttr_hours = (closed_time - detection_time) in hours.
            4. Serialise the VERIS dict to JSON and store in veris_classification column.
            5. Return final incident state.
        """
        # TODO: implement this endpoint
        return jsonify({"status": "not implemented"}), 501

    # -----------------------------------------------------------------------
    # Task 5 — Metrics API
    # GET /api/metrics
    # -----------------------------------------------------------------------
    @app.route("/api/metrics", methods=["GET"])
    def get_metrics():
        """
        Return aggregated SOC metrics for the last 30 days.

        Response schema:
            {
                "period": "last_30_days",
                "total_alerts": 342,
                "total_incidents": 47,
                "false_positive_rate": 0.31,
                "mttd_hours": 3.2,
                "mttr_hours": 14.7,
                "open_incidents": 5,
                "by_severity": {"critical": 2, "high": 12, "medium": 28, "low": 5},
                "by_status": {"open": 5, "investigating": 3, "contained": 1, "closed": 38}
            }

        TODO (Task 5):
            1. Query the alerts table: COUNT(*) for total_alerts.
            2. Query the incidents table: COUNT(*), AVG(mttd_hours), AVG(mttr_hours).
            3. Compute false_positive_rate = closed incidents with no breach / total closed.
               (Hint: parse veris_classification JSON; check attribute.confidentiality.data_disclosed == "No")
            4. Build by_severity and by_status breakdowns using GROUP BY queries.
            5. Return the metrics dict.
        """
        # TODO: implement this endpoint
        return jsonify({"status": "not implemented"}), 501

    return app


# ---------------------------------------------------------------------------
# Application entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=7000, debug=True)
