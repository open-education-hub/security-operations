#!/usr/bin/env python3
"""
SOC Metrics Exporter for Demo 04
Generates simulated SOC metrics for Prometheus scraping.
"""
import time
import random
from prometheus_client import start_http_server, Gauge, Counter, Histogram

# Gauges
alert_queue_depth = Gauge('soc_alert_queue_depth', 'Current open alerts in queue', ['severity'])
mttd_hours = Gauge('soc_mttd_hours', 'Mean time to detect (hours)')
mttr_hours = Gauge('soc_mttr_hours', 'Mean time to respond (hours)', ['severity'])
fp_rate = Gauge('soc_false_positive_rate', 'False positive rate (0-1)')
sla_compliance = Gauge('soc_sla_compliance_rate', 'SLA compliance rate (0-1)', ['severity'])

# Counters
alerts_total = Counter('soc_alerts_total', 'Total alerts processed', ['severity', 'outcome'])

def generate_metrics():
    """Simulate realistic SOC metrics with some variance."""
    while True:
        # Alert queue depths
        alert_queue_depth.labels(severity='p1').set(random.randint(0, 2))
        alert_queue_depth.labels(severity='p2').set(random.randint(2, 8))
        alert_queue_depth.labels(severity='p3').set(random.randint(10, 40))
        alert_queue_depth.labels(severity='p4').set(random.randint(30, 100))

        # MTTD: typically 4-8 hours for well-tuned SOC
        mttd_hours.set(round(random.uniform(3.5, 8.0), 2))

        # MTTR by severity
        mttr_hours.labels(severity='p1').set(round(random.uniform(0.5, 2.5), 2))
        mttr_hours.labels(severity='p2').set(round(random.uniform(1.5, 4.0), 2))
        mttr_hours.labels(severity='p3').set(round(random.uniform(3.0, 8.0), 2))
        mttr_hours.labels(severity='p4').set(round(random.uniform(12.0, 30.0), 2))

        # False positive rate (70-85% is common in real environments)
        fp_rate.set(round(random.uniform(0.70, 0.85), 3))

        # SLA compliance rates
        sla_compliance.labels(severity='p1').set(round(random.uniform(0.95, 1.0), 3))
        sla_compliance.labels(severity='p2').set(round(random.uniform(0.88, 0.98), 3))
        sla_compliance.labels(severity='p3').set(round(random.uniform(0.85, 0.96), 3))
        sla_compliance.labels(severity='p4').set(round(random.uniform(0.90, 0.99), 3))

        # Increment counters with simulated new alerts
        for _ in range(random.randint(0, 3)):
            severity = random.choices(['p1', 'p2', 'p3', 'p4'], weights=[1, 5, 20, 74])[0]
            outcome = random.choices(['true_positive', 'false_positive', 'benign_tp'],
                                     weights=[10, 75, 15])[0]
            alerts_total.labels(severity=severity, outcome=outcome).inc()

        time.sleep(15)

if __name__ == '__main__':
    start_http_server(8000)
    print("SOC metrics exporter started on :8000")
    generate_metrics()
