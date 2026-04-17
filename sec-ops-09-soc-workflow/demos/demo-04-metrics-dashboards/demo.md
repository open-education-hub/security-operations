# Demo 04 — SOC Metrics and Dashboards

## Overview

This demo builds a live SOC metrics dashboard using **Grafana** and a Python script that simulates realistic SOC alert and incident data.
Students will see how operational metrics are visualized and learn how to interpret them.

**Duration:** 40 minutes

**Difficulty:** Beginner

**Tools:** Docker, Grafana, Prometheus, Python (metrics generator)

---

## Setup

### Docker Compose

```yaml
# docker-compose.yml
version: "3.8"

services:
  prometheus:
    image: prom/prometheus:latest
    container_name: soc-prometheus
    volumes:
      - ./prometheus/prometheus.yml:/etc/prometheus/prometheus.yml
    ports:
      - "9090:9090"
    networks:
      - metrics-net

  grafana:
    image: grafana/grafana:latest
    container_name: soc-grafana
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=socadmin
      - GF_USERS_ALLOW_SIGN_UP=false
    volumes:
      - grafana-data:/var/lib/grafana
      - ./grafana/dashboards:/var/lib/grafana/dashboards
      - ./grafana/provisioning:/etc/grafana/provisioning
    depends_on:
      - prometheus
    networks:
      - metrics-net

  # SOC metrics exporter (Python custom exporter)
  soc-metrics:
    image: python:3.11-slim
    container_name: soc-metrics-exporter
    command: sh -c "pip install prometheus_client -q && python /app/soc_exporter.py"
    volumes:
      - ./soc_exporter:/app
    ports:
      - "8000:8000"
    networks:
      - metrics-net

networks:
  metrics-net:
    driver: bridge

volumes:
  grafana-data:
```

### Prometheus configuration

```yaml
# prometheus/prometheus.yml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: "soc-metrics"
    static_configs:
      - targets: ["soc-metrics:8000"]
```

### SOC Metrics Exporter

```python
# soc_exporter/soc_exporter.py
"""
SOC Metrics Prometheus Exporter
Simulates realistic SOC metrics for dashboard demo
"""

import time
import random
import math
from prometheus_client import start_http_server, Gauge, Counter, Histogram

# --- Define Metrics ---

# Current state metrics (Gauges)
open_tickets = Gauge('soc_open_tickets', 'Number of open tickets', ['severity'])
sla_breaches = Gauge('soc_sla_breaches', 'Number of active SLA breaches', ['severity'])
analyst_workload = Gauge('soc_analyst_workload', 'Open tickets per analyst', ['tier'])
false_positive_rate = Gauge('soc_false_positive_rate', 'Current false positive rate (0-1)')
detection_coverage = Gauge('soc_detection_coverage_percent', 'ATT&CK technique coverage %')

# Time metrics (Gauges in seconds)
mttd_seconds = Gauge('soc_mttd_seconds', 'Mean Time to Detect (seconds)', ['severity'])
mttr_seconds = Gauge('soc_mttr_seconds', 'Mean Time to Respond (seconds)', ['severity'])
mtta_seconds = Gauge('soc_mtta_seconds', 'Mean Time to Acknowledge (seconds)', ['severity'])

# Cumulative metrics (Counters)
alerts_total = Counter('soc_alerts_total', 'Total alerts generated', ['severity', 'source'])
true_positives_total = Counter('soc_true_positives_total', 'Total confirmed true positives')
false_positives_total = Counter('soc_false_positives_total', 'Total false positives')
blocked_threats_total = Counter('soc_blocked_threats_total', 'Total threats blocked by automation')

# Distribution metrics (Histograms)
investigation_duration = Histogram(
    'soc_investigation_duration_seconds',
    'Time spent investigating per ticket',
    buckets=[300, 600, 1800, 3600, 7200, 14400, 28800]
)

# --- Simulation State ---

class SOCState:
    def __init__(self):
        # Base values (realistic for a mid-size enterprise SOC)
        self.base_open_critical = 3
        self.base_open_high = 12
        self.base_open_medium = 28
        self.base_open_low = 45

        self.base_mttd_critical = 900    # 15 min
        self.base_mttd_high = 2700       # 45 min
        self.base_mttd_medium = 7200     # 2 hours

        self.base_mttr_critical = 7200   # 2 hours
        self.base_mttr_high = 18000      # 5 hours
        self.base_mttr_medium = 57600    # 16 hours

        self.base_fp_rate = 0.34
        self.base_coverage = 38.0
        self.tick = 0

state = SOCState()

def update_metrics():
    """Update all metrics with realistic fluctuations."""
    state.tick += 1
    t = state.tick

    # Simulate time-of-day patterns (more alerts during business hours)
    hour_of_day = (t % 96) / 4  # cycle every 24 simulated hours
    business_hours_factor = 1.0 + 0.6 * math.sin(math.pi * (hour_of_day - 6) / 12) if 6 <= hour_of_day <= 18 else 1.0

    # Open tickets with noise
    open_tickets.labels(severity='critical').set(
        max(0, state.base_open_critical + random.randint(-1, 2))
    )
    open_tickets.labels(severity='high').set(
        max(0, int(state.base_open_high * business_hours_factor + random.randint(-3, 3)))
    )
    open_tickets.labels(severity='medium').set(
        max(0, int(state.base_open_medium * business_hours_factor + random.randint(-5, 8)))
    )
    open_tickets.labels(severity='low').set(
        max(0, int(state.base_open_low + random.randint(-5, 10)))
    )

    # SLA breaches (typically 2-5% of high/critical)
    sla_breaches.labels(severity='critical').set(random.choice([0, 0, 0, 1, 1]))
    sla_breaches.labels(severity='high').set(random.randint(0, 3))
    sla_breaches.labels(severity='medium').set(random.randint(0, 6))

    # Analyst workload (Tier 1: 8-15 tickets, Tier 2: 3-7)
    analyst_workload.labels(tier='tier1').set(
        max(1, int(10 * business_hours_factor + random.randint(-2, 3)))
    )
    analyst_workload.labels(tier='tier2').set(
        max(1, random.randint(3, 7))
    )

    # FP rate varies 25-45%
    fp_noise = 0.02 * math.sin(t * 0.1) + random.uniform(-0.03, 0.03)
    false_positive_rate.set(max(0.1, min(0.7, state.base_fp_rate + fp_noise)))

    # Detection coverage improves slowly over time
    coverage_drift = min(0.5, t * 0.001)  # Slow improvement
    detection_coverage.set(min(95, state.base_coverage + coverage_drift + random.uniform(-0.5, 0.5)))

    # MTTD with fluctuation
    for sev, base in [("critical", state.base_mttd_critical),
                      ("high", state.base_mttd_high),
                      ("medium", state.base_mttd_medium)]:
        mttd_seconds.labels(severity=sev).set(
            max(60, base + random.randint(-300, 600))
        )
        mttr_seconds.labels(severity=sev).set(
            max(300, base * 6 + random.randint(-1800, 3600))
        )
        mtta_seconds.labels(severity=sev).set(
            max(30, base * 0.3 + random.randint(-60, 120))
        )

    # Accumulate alerts (realistic rates)
    new_alerts_critical = random.choices([0, 1, 2], weights=[0.7, 0.25, 0.05])[0]
    new_alerts_high = random.choices([0, 1, 2, 3], weights=[0.4, 0.3, 0.2, 0.1])[0]
    new_alerts_medium = random.randint(2, 8) if business_hours_factor > 1.2 else random.randint(1, 4)
    new_alerts_low = random.randint(3, 15)

    for source in ["siem", "edr", "ids"]:
        alerts_total.labels(severity='critical', source=source).inc(
            random.choices([0, 1], weights=[0.85, 0.15])[0]
        )
        alerts_total.labels(severity='high', source=source).inc(
            random.choices([0, 1, 2], weights=[0.5, 0.35, 0.15])[0]
        )
        alerts_total.labels(severity='medium', source=source).inc(
            random.randint(0, 3)
        )

    # TP/FP split
    total_new = new_alerts_critical + new_alerts_high + new_alerts_medium + new_alerts_low
    fp_count = int(total_new * state.base_fp_rate)
    tp_count = total_new - fp_count
    true_positives_total.inc(max(0, tp_count))
    false_positives_total.inc(max(0, fp_count))

    # Blocked threats (automation handles ~30% of all threats)
    blocked_threats_total.inc(random.choices([0, 1, 2], weights=[0.6, 0.3, 0.1])[0])

    # Sample investigation duration
    if random.random() < 0.3:
        sev = random.choice(["critical", "high", "medium", "low"])
        base_duration = {"critical": 5400, "high": 3600, "medium": 1800, "low": 900}[sev]
        investigation_duration.observe(max(300, base_duration + random.randint(-1800, 3600)))

if __name__ == "__main__":
    print("SOC Metrics Exporter starting on port 8000")
    print("Metrics available at http://localhost:8000/metrics")
    start_http_server(8000)

    while True:
        update_metrics()
        time.sleep(15)  # Update every 15 seconds
```

### Start everything

```console
mkdir -p prometheus soc_exporter grafana/provisioning/datasources grafana/provisioning/dashboards
# Create files as shown above

docker compose up -d
# Wait 30 seconds

# Verify metrics are flowing
curl http://localhost:8000/metrics | grep soc_
```

---

## Part 1: Explore Prometheus (10 minutes)

Open http://localhost:9090

**Run these queries in the expression browser:**

```promql
# Current open tickets by severity
soc_open_tickets

# MTTD for critical alerts (in minutes)
soc_mttd_seconds{severity="critical"} / 60

# False positive rate as percentage
soc_false_positive_rate * 100

# Total alerts in last 5 minutes
increase(soc_alerts_total[5m])

# Alert rate per minute
rate(soc_alerts_total[1m]) * 60

# True positive rate
rate(soc_true_positives_total[5m]) /
(rate(soc_true_positives_total[5m]) + rate(soc_false_positives_total[5m]))
```

---

## Part 2: Build a Grafana Dashboard (20 minutes)

Open http://localhost:3000 (admin / socadmin)

### Add Prometheus data source

1. Go to **Configuration** → **Data Sources** → **Add data source**
1. Select **Prometheus**
1. URL: `http://prometheus:9090`
1. Click **Save & Test**

### Create the dashboard

Click **+** → **Dashboard** → **Add new panel**

**Panel 1: Open Tickets by Severity (Stat panels)**

Create 4 stat panels:

| Panel Title | Query | Color |
|-------------|-------|-------|
| Critical Open | `soc_open_tickets{severity="critical"}` | Red |
| High Open | `soc_open_tickets{severity="high"}` | Orange |
| SLA Breaches | `sum(soc_sla_breaches)` | Red |
| FP Rate | `soc_false_positive_rate * 100` | Yellow |

**Panel 2: MTTD Over Time (Time series)**

```promql
soc_mttd_seconds / 60
```

* Legend: `{{severity}}`
* Y-axis unit: `minutes`
* Title: `Mean Time to Detect (minutes)`

**Panel 3: Alert Volume (Bar gauge)**

```promql
increase(soc_alerts_total[1m])
```

* Title: `Alert Rate (per minute)`

**Panel 4: Detection Coverage (Gauge)**

```promql
soc_detection_coverage_percent
```

* Min: 0, Max: 100
* Thresholds: 0=red, 40=yellow, 70=green
* Title: `MITRE ATT&CK Coverage %`

**Panel 5: Analyst Workload (Stat)**

```promql
soc_analyst_workload
```

* Title: `Open Tickets per Analyst`

---

## Part 3: Interpret the Dashboard (10 minutes)

**Discussion questions for the class:**

1. **The FP rate is 34%. Is this acceptable? What would you do?**
   * Industry average is 40–60%, so 34% is decent but improvable
   * Run a rule review sprint targeting top FP-generating rules
   * Target: < 20%

1. **MTTD for critical alerts is 15 minutes. Our SLA is 1 hour. Are we safe?**
   * Yes for detection, but remember: SLA includes acknowledge + investigate + respond
   * Need to track the full chain

1. **ATT&CK coverage is at 38%. What does this mean operationally?**
   * 62% of attacker techniques have no detection coverage
   * Prioritize high-frequency, high-impact techniques (Initial Access, Execution, Persistence)
   * Build a detection engineering roadmap

1. **Open critical tickets: 3. What would trigger escalation to management?**
   * Any critical ticket approaching SLA deadline
   * Critical ticket involving data exfiltration or ransomware
   * Multiple critical tickets from same attacker (coordinated attack)

---

## Cleanup

```console
docker compose down -v
```
