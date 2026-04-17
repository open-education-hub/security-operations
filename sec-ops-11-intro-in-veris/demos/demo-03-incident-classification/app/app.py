#!/usr/bin/env python3
"""
Demo 03: VERIS Incident Classification Web App
Flask app presenting incident scenarios for student VERIS coding practice.
"""
import json
import os
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)
SCENARIOS_PATH = os.path.join(os.path.dirname(__file__), "scenarios.json")

with open(SCENARIOS_PATH) as f:
    SCENARIOS = json.load(f)


@app.route("/")
def index():
    return render_template("index.html", scenarios=SCENARIOS, total=len(SCENARIOS))


@app.route("/api/scenario/<int:scenario_id>")
def get_scenario(scenario_id):
    for s in SCENARIOS:
        if s["id"] == scenario_id:
            return jsonify(s)
    return jsonify({"error": "Scenario not found"}), 404


@app.route("/api/check", methods=["POST"])
def check_answer():
    """Accept student's VERIS classification and provide feedback."""
    data = request.get_json()
    scenario_id = data.get("scenario_id")
    student_answer = data.get("answer", {})

    scenario = next((s for s in SCENARIOS if s["id"] == scenario_id), None)
    if not scenario:
        return jsonify({"error": "Invalid scenario"}), 400

    correct = scenario["answer"]
    feedback = []

    # Check actor
    student_actors = set(student_answer.get("actor", {}).keys())
    correct_actors = set(correct.get("actor", {}).keys())
    if student_actors == correct_actors:
        feedback.append({"field": "Actor", "correct": True, "message": "Actor type correct!"})
    else:
        feedback.append({"field": "Actor", "correct": False,
                         "message": f"Expected {correct_actors}, got {student_actors}"})

    # Check action categories
    student_actions = set(student_answer.get("action", {}).keys())
    correct_actions = set(correct.get("action", {}).keys())
    if student_actions == correct_actions:
        feedback.append({"field": "Action", "correct": True, "message": "Action categories correct!"})
    else:
        feedback.append({"field": "Action", "correct": False,
                         "message": f"Expected {correct_actions}, got {student_actions}"})

    score = sum(1 for f in feedback if f["correct"])
    return jsonify({
        "score": score,
        "max_score": len(feedback),
        "feedback": feedback,
        "explanation": scenario["explanation"]
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
