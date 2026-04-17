# Solution Guide — Project 03: Automation and Response

> **Instructor use only. Do not distribute to students before submission.**

---

## Architecture Overview

The complete SOAR system consists of:

* **Flask API** (`soar/app.py`) — receives alerts and exposes incident management endpoints
* **SQLite database** — stores alerts, incidents, VERIS classifications
* **Triage playbook** (`soar/playbooks/triage.py`) — runs automatically on each alert
* **VERIS report generator** (`soar/reports/veris_report.py`) — weekly summary
* **Metrics endpoint** — aggregates KPIs from the database

---

## Task 1: Alert Ingestion — Reference Implementation

```python
# soar/api/alerts.py
from flask import request, jsonify
from soar.database import db, Alert, Incident
from soar.playbooks.triage import run_triage
import datetime

REQUIRED_FIELDS = ['alert_id', 'timestamp', 'rule_name', 'severity', 'source_ip']

def register_routes(app):

    @app.route('/api/alerts', methods=['POST'])
    def ingest_alert():
        data = request.get_json()
        if not data:
            return jsonify({"error": "Request body must be JSON"}), 400

        missing = [f for f in REQUIRED_FIELDS if f not in data]
        if missing:
            return jsonify({"error": f"Missing fields: {missing}"}), 400

        # Deduplication
        existing = Alert.query.filter_by(alert_id=data['alert_id']).first()
        if existing:
            return jsonify({"error": "Alert already exists", "incident_id": existing.incident_id}), 409

        # Create alert
        alert = Alert(
            alert_id=data['alert_id'],
            timestamp=datetime.datetime.fromisoformat(data['timestamp'].replace('Z', '+00:00')),
            rule_name=data['rule_name'],
            severity=data['severity'],
            source_ip=data['source_ip'],
            destination_ip=data.get('destination_ip'),
            destination_port=data.get('destination_port'),
            raw_log=data.get('raw_log', '')
        )
        db.session.add(alert)
        db.session.flush()  # get alert.id without committing

        # Run triage playbook
        incident = run_triage(alert, data)
        alert.incident_id = incident.incident_id

        db.session.commit()
        return jsonify({"incident_id": incident.incident_id, "status": "created"}), 201
```

**Common student errors:**

* Not returning 409 for duplicate alert IDs
* Running triage synchronously but blocking the response (acceptable for this project; async is a stretch)
* Not flushing before accessing `alert.id`

---

## Task 2: Triage Playbook — Reference Implementation

```python
# soar/playbooks/triage.py
import json
import datetime
import os
from soar.database import db, Incident

with open('/data/ioc_db.json') as f:
    IOC_DB = json.load(f)

with open('/data/assets.json') as f:
    ASSETS = {a['ip']: a for a in json.load(f)['assets']}

SEVERITY_RANK = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
SEVERITY_NAMES = {1: 'low', 2: 'medium', 3: 'high', 4: 'critical'}

def run_triage(alert, data):
    severity = data.get('severity', 'medium').lower()
    rank = SEVERITY_RANK.get(severity, 2)

    # Step 1: IOC Enrichment
    ioc_entry = IOC_DB.get(alert.source_ip)
    if ioc_entry:
        score = ioc_entry.get('score', 0)
        if score > 70:
            rank = max(rank, SEVERITY_RANK['high'])
        elif score >= 40:
            rank = max(rank, SEVERITY_RANK['medium'])

    # Step 2: Critical Asset Check
    dest_asset = ASSETS.get(alert.destination_ip)
    if dest_asset and dest_asset.get('critical', False):
        rank = min(rank + 1, 4)  # upgrade one level, cap at critical

    final_severity = SEVERITY_NAMES[rank]

    # Step 3: Deduplication — find existing open incident for this source IP
    cutoff = datetime.datetime.utcnow() - datetime.timedelta(hours=2)
    existing = Incident.query.filter(
        Incident.source_ip == alert.source_ip,
        Incident.status.in_(['open', 'investigating']),
        Incident.created_at >= cutoff
    ).first()

    if existing:
        # Add alert to existing incident
        existing.alert_count += 1
        existing.updated_at = datetime.datetime.utcnow()
        return existing

    # Step 4: Create new incident
    priority = 'P1' if final_severity in ('high', 'critical') else ('P2' if final_severity == 'medium' else 'P3')
    incident_id = f"INC-{datetime.datetime.utcnow().strftime('%Y')}-{_next_id()}"
    incident = Incident(
        incident_id=incident_id,
        title=data['rule_name'],
        severity=final_severity,
        priority=priority,
        source_ip=alert.source_ip,
        destination_ip=alert.destination_ip,
        status='open',
        alert_count=1,
        created_at=datetime.datetime.utcnow(),
        updated_at=datetime.datetime.utcnow()
    )
    db.session.add(incident)

    # Step 5: P1 Notification
    if priority == 'P1':
        _write_p1_notification(incident, alert)

    return incident

def _next_id():
    count = Incident.query.count()
    return str(count + 1).zfill(4)

def _write_p1_notification(incident, alert):
    log_dir = 'soar/notifications'
    os.makedirs(log_dir, exist_ok=True)
    with open(f'{log_dir}/p1_alerts.log', 'a') as f:
        line = (f"[{datetime.datetime.utcnow().isoformat()}Z] P1 ALERT: {incident.incident_id} — "
                f"{incident.title} from {alert.source_ip} targeting {alert.destination_ip}\n")
        f.write(line)
```

**Key grading points:**

* IOC score thresholds must be ≥70 for HIGH, not strictly >70 (borderline — accept either)
* Asset criticality must upgrade severity (not just flag it)
* Deduplication window is 2 hours — check both `source_ip` AND `open/investigating` status
* P1 notification must include incident ID, rule name, source IP, and destination

---

## Task 3: Incident Lifecycle — Key Implementation Notes

```python
# soar/api/incidents.py — key endpoints

@app.route('/api/incidents/<incident_id>/status', methods=['PATCH'])
def update_status(incident_id):
    data = request.get_json()
    new_status = data.get('status')

    VALID_TRANSITIONS = {
        'open': ['investigating'],
        'investigating': ['contained', 'closed'],
        'contained': ['closed'],
        'closed': []
    }

    incident = Incident.query.filter_by(incident_id=incident_id).first_or_404()

    if new_status not in VALID_TRANSITIONS[incident.status]:
        return jsonify({"error": f"Invalid transition from {incident.status} to {new_status}"}), 400

    old_status = incident.status
    incident.status = new_status
    incident.updated_at = datetime.datetime.utcnow()

    if new_status == 'closed':
        incident.closed_at = datetime.datetime.utcnow()
        incident.mttr_hours = (incident.closed_at - incident.created_at).total_seconds() / 3600

    db.session.commit()
    return jsonify({"incident_id": incident_id, "old_status": old_status, "new_status": new_status})
```

**Important**: Students should enforce status transition rules (cannot go from `open` to `closed` without going through `investigating`).
Accept implementations that enforce this.

**MTTR calculation**: Measured from `incident.created_at` (when the alert arrived = detection time) to `incident.closed_at`.
Students sometimes use `status='investigating'` as the start — deduct points if the definition is inconsistent.

---

## Task 4: VERIS Report — Reference Output

```python
# soar/reports/veris_report.py
import json
import sqlite3
from collections import Counter
from datetime import datetime, timedelta

def bar(pct, width=20):
    filled = int(pct * width)
    return '|' * filled + ' ' * (width - filled)

def generate_report(db_path='/data/incidents.db', days=7):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    since = (datetime.utcnow() - timedelta(days=days)).isoformat()
    cursor.execute("SELECT veris_classification FROM incidents WHERE status='closed' AND closed_at > ?", (since,))
    rows = cursor.fetchall()

    total = len(rows)
    actors = Counter()
    actions = Counter()
    assets_ctr = Counter()

    for row in rows:
        if not row[0]:
            continue
        veris = json.loads(row[0])
        for category in veris.get('actor', {}):
            actors[category.capitalize()] += 1
        for category in veris.get('action', {}):
            actions[category.capitalize()] += 1
        for asset in veris.get('asset', {}).get('assets', []):
            assets_ctr[asset.get('variety', 'Unknown')] += 1

    # Format report
    report_lines = [
        f"WEEKLY SOC SUMMARY — Week of {(datetime.utcnow() - timedelta(days=days)).strftime('%Y-%m-%d')}",
        "=" * 50,
        f"Total Incidents: {total}",
        "",
        "Actor Categories:",
    ]
    for actor, count in actors.most_common():
        pct = count / total if total else 0
        report_lines.append(f"  {actor:<12} {bar(pct)}  {pct*100:.0f}%  ({count})")

    report_lines.extend(["", "Top Action Varieties:"])
    for i, (action, count) in enumerate(actions.most_common(3), 1):
        pct = count / total if total else 0
        report_lines.append(f"  {i}. {action:<20} {bar(pct, 12)}  {pct*100:.0f}%  ({count})")

    return "\n".join(report_lines)
```

---

## Task 5: Metrics Endpoint — Expected Implementation

```python
@app.route('/api/metrics')
def get_metrics():
    # Calculate from last 30 days
    cutoff = (datetime.utcnow() - timedelta(days=30)).isoformat()

    total_alerts = Alert.query.filter(Alert.timestamp >= cutoff).count()
    total_incidents = Incident.query.filter(Incident.created_at >= cutoff).count()
    closed = Incident.query.filter(Incident.status == 'closed', Incident.closed_at >= cutoff).all()

    mttr = sum(i.mttr_hours for i in closed if i.mttr_hours) / len(closed) if closed else 0

    # False positive rate: alerts that were attached to incidents closed as FP
    # Simplified: incidents closed with resolution containing 'false positive'
    fp_count = Incident.query.filter(
        Incident.resolution.ilike('%false positive%'),
        Incident.closed_at >= cutoff
    ).count()
    fpr = fp_count / total_incidents if total_incidents else 0

    return jsonify({
        "period": "last_30_days",
        "total_alerts": total_alerts,
        "total_incidents": total_incidents,
        "false_positive_rate": round(fpr, 2),
        "mttd_hours": 0,   # MTTD requires external detection timestamp; 0 if not available
        "mttr_hours": round(mttr, 1),
        "open_incidents": Incident.query.filter_by(status='open').count(),
        ...
    })
```

**Note for graders**: MTTD calculation requires knowing when the attack *started* (before the alert).
In this simplified environment, students cannot calculate MTTD from the data available — accept MTTD = 0 or an explanation that MTTD requires an additional data field.

---

## Task 6: Testing — Expected Test Cases

```python
# tests/test_triage.py
def test_high_ioc_score_upgrades_severity():
    alert = Mock(source_ip='185.220.101.42', destination_ip='10.0.0.1')
    # IOC DB has 185.220.101.42 with score 95
    result = run_triage(alert, {'severity': 'low', ...})
    assert result.severity == 'high'

def test_critical_asset_upgrades_severity():
    alert = Mock(source_ip='1.2.3.4', destination_ip='10.0.0.5')
    # Asset DB has 10.0.0.5 as critical=True
    result = run_triage(alert, {'severity': 'medium', ...})
    assert result.severity in ('high', 'critical')

def test_duplicate_alert_returns_409():
    with app.test_client() as client:
        payload = {'alert_id': 'TEST-001', ...}
        client.post('/api/alerts', json=payload)
        r = client.post('/api/alerts', json=payload)
        assert r.status_code == 409

def test_veris_classification_stored():
    # Close an incident with VERIS payload
    # Query database and verify veris_classification field is stored as JSON
    ...

def test_mttr_calculated_on_close():
    # Open incident, transition to closed
    # Verify mttr_hours > 0 and is a reasonable value
    ...
```

---

## Common Issues and Point Deductions

| Issue | Deduction |
|-------|-----------|
| Triage playbook not running automatically on alert ingest | -10 |
| No deduplication (same alert ID accepted twice) | -5 |
| Critical asset check missing | -5 |
| Status transitions not enforced (can jump from open to closed) | -5 |
| VERIS classification not stored in database | -5 |
| MTTR never populated | -5 |
| Fewer than 3 unit tests | -5 |
| No API documentation in README | -3 |
