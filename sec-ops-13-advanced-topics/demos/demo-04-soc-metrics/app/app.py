#!/usr/bin/env python3
"""
SOC Metrics Dashboard — Flask web app
"""
import json
from flask import Flask, render_template
from data_generator import generate_metrics

app = Flask(__name__)

@app.route("/")
def dashboard():
    metrics = generate_metrics()
    return render_template("dashboard.html", metrics=metrics, metrics_json=json.dumps(metrics))

@app.route("/api/metrics")
def api_metrics():
    from flask import jsonify
    return jsonify(generate_metrics())

if __name__ == "__main__":
    print("[SOC Dashboard] Starting at http://localhost:5050")
    app.run(host="0.0.0.0", port=5050, debug=False)
