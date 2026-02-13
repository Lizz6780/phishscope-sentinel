import json
from datetime import UTC, datetime
from pathlib import Path

from reports.incident_db import insert_incident

def write_incident(report):
    ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S_%f")
    reports_dir = Path("reports")
    reports_dir.mkdir(parents=True, exist_ok=True)
    path = reports_dir / f"incident_{ts}.json"

    with path.open("w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    insert_incident(report, path.name)
    return str(path)
