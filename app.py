from flask import Flask, render_template, request, redirect, url_for, send_file, jsonify
from pathlib import Path
import threading
import uuid
import os

from src.agents.scan_agent import run_scan
from src.agents.poc_agent import fetch_poc
from src.agents.exploit_agent import run_exploit
from src.agents.report_agent import generate_report


app = Flask(__name__, template_folder="templates", static_folder="static")

jobs = {}


def run_job(job_id: str, target: str, use_authorize: bool):
    try:
        work_dir = Path("reports")
        work_dir.mkdir(exist_ok=True)
        artifacts = {}

        scan_json = run_scan(target, work_dir)
        artifacts["scan_json"] = str(scan_json)

        poc_info = fetch_poc(scan_json, work_dir)
        artifacts["poc"] = poc_info

        exploit_log = run_exploit(target, poc_info, work_dir, authorize=use_authorize)
        artifacts["exploit_log"] = str(exploit_log)

        report_md, report_pdf = generate_report(target, artifacts, work_dir)
        jobs[job_id] = {"status": "completed", "report_md": str(report_md), "report_pdf": str(report_pdf), "artifacts": artifacts}
    except Exception as e:
        jobs[job_id] = {"status": "failed", "error": str(e)}


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/start")
def start():
    target = request.form.get("target", "").strip()
    authorize = request.form.get("authorize", "off") == "on"
    job_id = str(uuid.uuid4())
    jobs[job_id] = {"status": "running"}
    t = threading.Thread(target=run_job, args=(job_id, target, authorize), daemon=True)
    t.start()
    return redirect(url_for("status", job_id=job_id))


@app.get("/status/<job_id>")
def status(job_id: str):
    job = jobs.get(job_id)
    if not job:
        return render_template("status.html", job_id=job_id, status="not_found")
    return render_template("status.html", job_id=job_id, status=job.get("status"), job=job)


@app.get("/download/<job_id>/<fmt>")
def download(job_id: str, fmt: str):
    job = jobs.get(job_id)
    if not job or job.get("status") != "completed":
        return "Not ready", 404
    key = "report_pdf" if fmt == "pdf" else "report_md"
    path = Path(job.get(key, ""))
    if not path.exists():
        return "File missing", 404
    return send_file(path, as_attachment=True)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)))


