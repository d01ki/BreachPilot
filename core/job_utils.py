"""
Job utilities and status management
"""
import json as _json
import time
from pathlib import Path


def _persist_meta(job_id: str, meta: dict):
    """Persist job metadata to disk"""
    job_dir = Path("reports") / job_id
    job_dir.mkdir(parents=True, exist_ok=True)
    (job_dir / "meta.json").write_text(_json.dumps(meta, indent=2))


def _update_job_status(jobs: dict, job_id: str, phase: str, status: str = "running", **kwargs):
    """Update job status with additional metadata"""
    if job_id not in jobs:
        jobs[job_id] = {}
    
    jobs[job_id].update({
        "status": status,
        "phase": phase,
        "last_update": time.time(),
        **kwargs
    })
    _persist_meta(job_id, jobs[job_id])