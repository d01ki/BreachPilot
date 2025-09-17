from pathlib import Path
import json
import requests


def fetch_poc(scan_json_path: Path, work_dir: Path) -> dict:
    """Fetch PoC metadata for CVE-2020-1472 from GitHub/ExploitDB (metadata only PoC)."""
    data = json.loads(scan_json_path.read_text())
    cve = "CVE-2020-1472"
    info = {"cve": cve, "sources": []}

    # GitHub search API (unauthenticated limited)
    try:
        gh = requests.get(
            "https://api.github.com/search/repositories",
            params={"q": f"{cve} in:name,description", "sort": "stars"},
            timeout=15,
        )
        if gh.ok:
            payload = gh.json()
            for item in payload.get("items", [])[:5]:
                info["sources"].append({
                    "type": "github",
                    "name": item.get("full_name"),
                    "url": item.get("html_url"),
                    "stars": item.get("stargazers_count"),
                })
    except Exception:
        pass

    # ExploitDB metadata (no official API; use website link as placeholder)
    info["sources"].append({
        "type": "exploitdb",
        "name": "ExploitDB search",
        "url": "https://www.exploit-db.com/search?cve=2020-1472",
    })

    (work_dir / "poc.json").write_text(json.dumps(info, indent=2))
    return info


