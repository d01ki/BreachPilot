from pathlib import Path
import json
import os
import time
from datetime import datetime
import requests
from src.utils.config import load_config


def _score_repo(item: dict) -> float:
    """Score GitHub repo candidate for PoC relevance."""
    score = 0.0
    stars = item.get("stargazers_count") or 0
    score += min(stars, 2000) * 0.002  # up to +4
    # recent activity
    pushed_at = item.get("pushed_at") or item.get("updated_at")
    try:
        if pushed_at:
            dt = datetime.fromisoformat(pushed_at.replace('Z','+00:00'))
            age_days = max((datetime.utcnow() - dt).days, 0)
            score += max(0, 2.0 - (age_days / 180.0) * 2.0)  # within 6 months ~ +2
    except Exception:
        pass
    # language preference
    lang = (item.get("language") or "").lower()
    if lang in ("python", "go"): score += 1.0
    # name/desc keywords
    text = f"{item.get('full_name','')} {item.get('description','')}".lower()
    for kw, w in [("zerologon",1.5),("cve-2020-1472",1.5),("exploit",0.8),("poc",0.8)]:
        if kw in text: score += w
    return round(score, 3)


def fetch_poc(scan_json_path: Path, work_dir: Path) -> dict:
    """Fetch PoC metadata for CVE-2020-1472 from GitHub/ExploitDB with basic scoring."""
    data = json.loads(scan_json_path.read_text())
    cve = "CVE-2020-1472"
    info = {"cve": cve, "sources": [], "selected": None, "generated_at": datetime.utcnow().isoformat()+"Z"}

    # GitHub search API (use token if configured)
    try:
        headers = {}
        cfg = load_config()
        token = cfg.get("GITHUB_TOKEN")
        if token:
            headers["Authorization"] = f"Bearer {token}"
        gh = requests.get(
            "https://api.github.com/search/repositories",
            params={"q": f"{cve} zerologon in:name,description,readme", "sort": "stars"},
            timeout=15,
            headers=headers,
        )
        if gh.ok:
            payload = gh.json()
            items = []
            for item in payload.get("items", [])[:15]:
                entry = {
                    "type": "github",
                    "name": item.get("full_name"),
                    "url": item.get("html_url"),
                    "stars": item.get("stargazers_count"),
                    "language": item.get("language"),
                    "pushed_at": item.get("pushed_at"),
                    "updated_at": item.get("updated_at"),
                }
                entry["score"] = _score_repo(item)
                items.append(entry)
            # sort by score desc
            info["sources"] = sorted(items, key=lambda x: x.get("score",0), reverse=True)
            if info["sources"]:
                info["selected"] = info["sources"][0]
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


