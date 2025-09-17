from pathlib import Path
import json
import subprocess
import datetime

try:
    import nmap  # python-nmap
except Exception:  # pragma: no cover
    nmap = None


def _run_nmap_subprocess(target: str) -> dict:
    """Fallback to subprocess nmap with service/version and selective NSE scripts."""
    # Try to include useful scripts if present; nmap will ignore unknown scripts
    cmd = [
        "nmap", "-Pn", "-sS", "-sV",
        "-p", "88,135,389,445",
        "--script", "smb-protocols,ldap-rootdse",
        target,
    ]
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    return {"raw": out.stdout}


def _run_nmap_python(target: str) -> dict:
    scanner = nmap.PortScanner()
    args = "-Pn -sS -sV -p 88,135,389,445 --script smb-protocols,ldap-rootdse"
    scanner.scan(target, arguments=args)
    return scanner._scan_result  # type: ignore[attr-defined]


def _normalize_nmap_result(raw: dict) -> dict:
    """Normalize nmap result (either from python-nmap or subprocess raw)."""
    normalized = {
        "target": None,
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "ports": [],
        "inferences": {},
        "raw": None,
    }

    if "raw" in raw:
        # Subprocess path: keep raw and attempt light extraction
        normalized["raw"] = raw["raw"]
        lines = raw["raw"].splitlines()
        for ln in lines:
            if "/tcp" in ln and ("open" in ln or "closed" in ln):
                parts = ln.split()
                if not parts:
                    continue
                port = parts[0].split("/")[0]
                state = parts[1] if len(parts) > 1 else "unknown"
                name = parts[2] if len(parts) > 2 else ""
                normalized["ports"].append({
                    "port": int(port),
                    "proto": "tcp",
                    "state": state,
                    "service": name,
                })
        return normalized

    # python-nmap path
    normalized["raw"] = raw
    hosts = raw.get("scan", {})
    for addr, host in hosts.items():
        normalized["target"] = addr
        tcp = host.get("tcp", {})
        for port, data in sorted(tcp.items()):
            normalized["ports"].append({
                "port": int(port),
                "proto": "tcp",
                "state": data.get("state"),
                "service": data.get("name"),
                "product": data.get("product"),
                "version": data.get("version"),
                "extrainfo": data.get("extrainfo"),
            })

    # Simple inference for AD/DC likelihood
    open_ports = {p["port"] for p in normalized["ports"] if p.get("state") == "open"}
    if 389 in open_ports and 445 in open_ports:
        normalized["inferences"]["possible_domain_controller"] = True
    if 88 in open_ports:
        normalized["inferences"]["kerberos_present"] = True

    return normalized


def run_scan(target: str, work_dir: Path) -> Path:
    """Run Active Directory focused scan and save structured JSON.
    Returns path to scan.json.
    """
    scan_path = work_dir / "scan.json"
    try:
        if nmap is not None:
            raw = _run_nmap_python(target)
        else:
            raw = _run_nmap_subprocess(target)
        result = _normalize_nmap_result(raw)
        if not result.get("target"):
            result["target"] = target
    except Exception as e:
        result = {
            "target": target,
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "ports": [],
            "error": str(e),
        }

    scan_path.write_text(json.dumps(result, indent=2))
    return scan_path


