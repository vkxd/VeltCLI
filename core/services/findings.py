"""Findings — structured, severity-ranked discoveries persisted locally."""
from __future__ import annotations

from datetime import datetime, timezone

from .store import JsonStore

SEVERITIES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
_SEVERITY_RANK = {name: rank for rank, name in enumerate(SEVERITIES)}


class FindingsService:
    def __init__(self, store: JsonStore | None = None):
        self.store = store or JsonStore("findings")

    def add(self, title: str, description: str = "", severity: str = "INFO",
            category: str = "general", target: str = "", evidence_ids: list[str] | None = None,
            source: str = "", tags: list[str] | None = None, status: str = "open") -> dict:
        severity = severity.upper()
        if severity not in SEVERITIES:
            severity = "INFO"
        data = self.store.get() or {"counter": 0, "findings": []}
        data["counter"] = int(data.get("counter", 0)) + 1
        finding = {
            "id": f"FINDING-{data['counter']:04d}",
            "title": title,
            "description": description,
            "severity": severity,
            "category": category,
            "target": target,
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "evidence_ids": evidence_ids or [],
            "source": source,
            "tags": tags or [],
            "status": status,
        }
        findings = data.get("findings", [])
        findings.append(finding)
        data["findings"] = findings[-500:]  # cap storage; old findings roll off
        self.store.set(data)
        return finding

    def list(self, severity: str | None = None) -> list[dict]:
        findings = (self.store.get() or {}).get("findings", [])
        if severity:
            wanted = severity.upper()
            if wanted == "HIGH+":  # convenience: HIGH and above
                findings = [f for f in findings if _SEVERITY_RANK.get(f["severity"], 0) >= _SEVERITY_RANK["HIGH"]]
            else:
                findings = [f for f in findings if f["severity"] == wanted]
        return list(reversed(findings))  # newest first

    def exists(self, title: str, target: str) -> bool:
        """True when an identical finding was already recorded for this target."""
        wanted_title = str(title or "").strip().lower()
        wanted_target = str(target or "").strip().lower()
        for finding in (self.store.get() or {}).get("findings", []):
            if finding["title"].strip().lower() == wanted_title and finding["target"].strip().lower() == wanted_target:
                return True
        return False

    def view(self, finding_id: str) -> dict | None:
        for finding in (self.store.get() or {}).get("findings", []):
            if finding["id"].lower() == finding_id.strip().lower():
                return finding
        return None

    def stats(self) -> dict:
        findings = (self.store.get() or {}).get("findings", [])
        by_severity = {name: 0 for name in SEVERITIES}
        for finding in findings:
            by_severity[finding["severity"]] = by_severity.get(finding["severity"], 0) + 1
        return {"total": len(findings), "by_severity": by_severity}

    def clear(self) -> int:
        data = self.store.get() or {}
        count = len(data.get("findings", []))
        self.store.set({"counter": data.get("counter", 0), "findings": []})
        return count
