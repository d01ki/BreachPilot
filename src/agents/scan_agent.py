from pathlib import Path
import json
import subprocess


def run_scan(target: str, work_dir: Path) -> Path:
    """Run Nmap scan (basic) and save JSON-like output.
    Returns path to scan.json.
    """
    scan_path = work_dir / "scan.json"
    result = {
        "target": target,
        "services": {},
    }
    # Minimal: TCP 88/135/389/445 probing via nmap if available
    try:
        cmd = ["nmap", "-Pn", "-p", "88,135,389,445", "-sS", target]
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        result["nmap_raw"] = out.stdout
        # naive parse
        services = {}
        for line in out.stdout.splitlines():
            if "/tcp" in line and ("open" in line or "closed" in line):
                parts = line.split()
                if parts:
                    port = parts[0].split("/")[0]
                    state = parts[1] if len(parts) > 1 else "unknown"
                    services[port] = state
        result["services"] = services
    except Exception as e:
        result["error"] = str(e)

    scan_path.write_text(json.dumps(result, indent=2))
    return scan_path


