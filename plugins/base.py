"""Base class shared by every Scylla module.

Modules return human-readable text for the terminal *and* record structured
intelligence (findings, graph nodes, graph edges) through the helpers below.
The engine harvests that intelligence after each run, so a real result from a
real tool becomes a persisted finding instead of being re-guessed from text.
"""
from __future__ import annotations


def _empty_intel() -> dict:
    return {"findings": [], "nodes": [], "edges": []}


class BasePlugin:
    def __init__(self, client):
        self.client = client
        self.values: dict = {}
        self.config = None
        self._intel: dict = _empty_intel()

    # ------------------------------------------------------------ lifecycle

    def reset_intel(self) -> None:
        self._intel = _empty_intel()

    @property
    def intel(self) -> dict:
        return self._intel

    # ------------------------------------------------------- intel recording

    def finding(self, title: str, description: str = "", severity: str = "INFO",
                category: str = "general", tags: list[str] | None = None) -> None:
        """Record a real, evidence-backed finding for the engine to persist."""
        if not title:
            return
        entry = {
            "title": str(title)[:160],
            "description": str(description)[:900],
            "severity": str(severity).upper(),
            "category": category,
            "tags": list(tags or []),
        }
        if entry["severity"] not in {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            entry["severity"] = "INFO"
        if all(existing["title"] != entry["title"] for existing in self._intel["findings"]):
            self._intel["findings"].append(entry)

    def node(self, label: str, typ: str = "host", metadata: dict | None = None) -> None:
        label = str(label or "").strip()
        if not label:
            return
        entry = {"label": label, "type": typ, "metadata": metadata or {}}
        for existing in self._intel["nodes"]:
            if existing["label"].lower() == entry["label"].lower() and existing["type"] == entry["type"]:
                existing["metadata"].update(entry["metadata"])
                return
        self._intel["nodes"].append(entry)

    def edge(self, source: str, target: str, rel: str = "related_to",
             source_type: str = "host", target_type: str = "host") -> None:
        if not source or not target or source.lower() == target.lower():
            return
        entry = {
            "source": str(source), "target": str(target), "rel": rel,
            "source_type": source_type, "target_type": target_type,
        }
        if all(
            not (existing["source"].lower() == entry["source"].lower()
                 and existing["target"].lower() == entry["target"].lower()
                 and existing["rel"] == entry["rel"])
            for existing in self._intel["edges"]
        ):
            self._intel["edges"].append(entry)

    # ------------------------------------------------------ abstract surface

    async def run_all(self, target):
        raise NotImplementedError

    async def run_sub(self, sub_id, target):
        raise NotImplementedError
