from pathlib import Path
from datetime import datetime


def generate_report(target: str, artifacts: dict, work_dir: Path) -> tuple[Path, Path]:
    """Generate Markdown and a placeholder PDF report.
    Returns (md_path, pdf_path).
    """
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    md = work_dir / f"report_{ts}.md"
    pdf = work_dir / f"report_{ts}.pdf"

    md.write_text(f"""# Pentest Automation Report (PoC)\n\nTarget: {target}\n\n## Scan\n\n- scan_json: {artifacts.get('scan_json')}\n\n## PoC Sources\n\n{artifacts.get('poc')}\n\n## Exploit\n\n- log: {artifacts.get('exploit_log')}\n\n## Notes\n\nThis is a PoC auto-generated report.\n""")

    # Minimal placeholder PDF (empty file with hint)
    pdf.write_bytes(b"%PDF-1.4\n% PoC placeholder, see Markdown report.\n")
    return md, pdf


