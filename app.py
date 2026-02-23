"""
NetPort Scanner — Flask Web Interface
Run with: python app.py
Then visit: http://localhost:5000
"""

import threading
import json
import time
import uuid
from flask import Flask, render_template, request, jsonify, send_file
from scanner import run_scan, export_json, export_csv
import os

app = Flask(__name__)
app.secret_key = "netport-scanner-secret"

# In-memory job store: { job_id: { status, progress, results } }
jobs = {}
jobs_lock = threading.Lock()

REPORTS_DIR = "reports"
os.makedirs(REPORTS_DIR, exist_ok=True)


def _run_scan_job(job_id, host, port_range, threads, timeout):
    """Background thread that performs the scan and updates job state."""
    with jobs_lock:
        jobs[job_id]["status"] = "running"
        jobs[job_id]["open_ports_live"] = []

    def on_progress(scanned, total, result):
        with jobs_lock:
            jobs[job_id]["progress"] = round(scanned / total * 100, 1)
            jobs[job_id]["scanned"] = scanned
            jobs[job_id]["total"] = total
            if result["state"] == "open":
                jobs[job_id]["open_ports_live"].append(result)

    results = run_scan(
        host=host,
        port_range=port_range,
        max_threads=threads,
        timeout=timeout,
        progress_callback=on_progress,
    )

    with jobs_lock:
        if "error" in results:
            jobs[job_id]["status"] = "error"
            jobs[job_id]["error"] = results["error"]
        else:
            jobs[job_id]["status"] = "complete"
            jobs[job_id]["results"] = results
            # Save JSON report automatically
            path = os.path.join(REPORTS_DIR, f"scan_{job_id}.json")
            export_json(results, path)
            jobs[job_id]["report_json"] = path


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def start_scan():
    data = request.json or {}
    host = data.get("host", "").strip()
    if not host:
        return jsonify({"error": "Host is required"}), 400

    try:
        range_str = data.get("range", "1-1024")
        parts = range_str.split("-")
        port_range = (int(parts[0]), int(parts[1]))
    except Exception:
        return jsonify({"error": "Invalid port range. Use format: start-end"}), 400

    threads = min(int(data.get("threads", 200)), 500)
    timeout = float(data.get("timeout", 1.0))

    job_id = str(uuid.uuid4())[:8]
    with jobs_lock:
        jobs[job_id] = {
            "job_id": job_id,
            "host": host,
            "status": "queued",
            "progress": 0,
            "scanned": 0,
            "total": port_range[1] - port_range[0] + 1,
            "open_ports_live": [],
            "results": None,
        }

    t = threading.Thread(
        target=_run_scan_job,
        args=(job_id, host, port_range, threads, timeout),
        daemon=True,
    )
    t.start()

    return jsonify({"job_id": job_id})


@app.route("/api/status/<job_id>")
def job_status(job_id):
    with jobs_lock:
        job = jobs.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    # Return a safe copy
    return jsonify({
        "job_id": job_id,
        "status": job["status"],
        "progress": job.get("progress", 0),
        "scanned": job.get("scanned", 0),
        "total": job.get("total", 0),
        "open_ports_live": job.get("open_ports_live", []),
        "results": job.get("results"),
        "error": job.get("error"),
    })


@app.route("/api/export/<job_id>/<fmt>")
def export_report(job_id, fmt):
    with jobs_lock:
        job = jobs.get(job_id)

    if not job or job["status"] != "complete":
        return jsonify({"error": "Scan not complete"}), 400

    results = job["results"]
    path = os.path.join(REPORTS_DIR, f"scan_{job_id}.{fmt}")

    if fmt == "json":
        export_json(results, path)
        return send_file(path, as_attachment=True, download_name=f"scan_{job_id}.json")
    elif fmt == "csv":
        export_csv(results, path)
        return send_file(path, as_attachment=True, download_name=f"scan_{job_id}.csv")
    else:
        return jsonify({"error": "Invalid format"}), 400


if __name__ == "__main__":
    print("\n🔍 NetPort Scanner Web Interface")
    print("   Visit http://localhost:5000\n")
    app.run(debug=True, host="0.0.0.0", port=5000)
