#!/usr/bin/env python3
"""Mock EDR API for containment demonstration."""
from flask import Flask, jsonify, request
import datetime

app = Flask(__name__)
devices = {
    "host-finance-ws-042": {"hostname": "finance-ws-042", "status": "normal", "isolated": False},
    "host-finance-ws-041": {"hostname": "finance-ws-041", "status": "normal", "isolated": False},
}
events = []

@app.route("/api/devices/<device_id>", methods=["GET"])
def get_device(device_id):
    if device_id in devices:
        return jsonify(devices[device_id])
    return jsonify({"error": "Device not found"}), 404

@app.route("/api/devices/actions", methods=["POST"])
def device_action():
    data = request.json
    action = data.get("action")
    device_id = data.get("device_id")
    if device_id not in devices:
        return jsonify({"error": "Device not found"}), 404
    if action == "contain":
        devices[device_id]["isolated"] = True
        devices[device_id]["status"] = "isolated"
        devices[device_id]["isolated_at"] = datetime.datetime.utcnow().isoformat() + "Z"
        events.append({"action": "contain", "device": device_id, "time": devices[device_id]["isolated_at"]})
        return jsonify({"success": True, "message": f"Device {device_id} isolated", "device": devices[device_id]})
    elif action == "lift_containment":
        devices[device_id]["isolated"] = False
        devices[device_id]["status"] = "normal"
        return jsonify({"success": True, "message": f"Containment lifted for {device_id}"})
    return jsonify({"error": "Unknown action"}), 400

@app.route("/api/events", methods=["GET"])
def get_events():
    return jsonify(events)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
