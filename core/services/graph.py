"""Relationship graph — reusable nodes/edges engine for infrastructure & entity relationships."""
from __future__ import annotations

import html
import uuid
from datetime import datetime, timezone

from .store import JsonStore

EDGE_TYPES = {
    "resolves_to",
    "contains",
    "belongs_to",
    "points_to",
    "uses",
    "related_to",
}

TYPE_LABELS = {
    "domain": "Domain",
    "subdomain": "Subdomain",
    "ip": "IP Address",
    "organization": "Organization",
    "asn": "ASN",
    "email": "Email",
    "technology": "Technology/Service",
    "host": "Host",
    "url": "URL",
    "certificate": "Certificate",
    "username": "Username",
}


class GraphService:
    """Stores entities (nodes) and relationships (edges) with dedup."""

    def __init__(self, store: JsonStore | None = None):
        self.store = store or JsonStore("graph")

    # ---------- nodes ----------
    def _node_id(self, label: str, typ: str, metadata: dict | None) -> str:
        key = f"{str(label).strip().lower()}|{typ}"
        return str(uuid.uuid5(uuid.NAMESPACE_OID, key))

    def add_node(self, label: str, typ: str, metadata: dict | None = None) -> dict:
        typ = typ.lower()
        if typ not in TYPE_LABELS:
            typ = "host"
        node_id = self._node_id(label, typ, metadata)
        data = self.store.get() or {"nodes": [], "edges": []}
        existing = next((n for n in data.get("nodes", []) if n["id"] == node_id), None)
        if existing:
            return existing
        node = {
            "id": node_id,
            "type": typ,
            "label": label,
            "metadata": metadata or {},
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        data["nodes"].append(node)
        self.store.set(data)
        return node

    def get_node(self, node_id: str) -> dict | None:
        for node in (self.store.get() or {}).get("nodes", []):
            if node["id"] == node_id:
                return node
        return None

    def nodes_for_target(self, label_like: str) -> list[dict]:
        """Return nodes whose label loosely matches the supplied target string."""
        needle = label_like.strip().lower()
        nodes = (self.store.get() or {}).get("nodes", [])
        out = []
        for node in nodes:
            lbl = node["label"].lower()
            if lbl == needle or lbl.endswith("." + needle) or lbl.startswith(needle + ".") or node["id"] == needle:
                out.append(node)
        return out

    # ---------- edges ----------
    def _edge_id(self, source: str, target: str, rel: str, metadata: dict | None) -> str:
        key = f"{source}|{target}|{rel}"
        return str(uuid.uuid5(uuid.NAMESPACE_OID, key))

    def add_edge(self, source: str, target: str, rel: str, metadata: dict | None = None) -> dict:
        rel = rel.lower()
        if rel not in EDGE_TYPES:
            rel = "related_to"
        data = self.store.get() or {"nodes": [], "edges": []}
        edge_id = self._edge_id(source, target, rel, metadata)
        existing = next((e for e in data.get("edges", []) if e["id"] == edge_id), None)
        if existing:
            return existing
        edge = {
            "id": edge_id,
            "source": source,
            "target": target,
            "relationship": rel,
            "metadata": metadata or {},
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        data["edges"].append(edge)
        self.store.set(data)
        return edge

    def edges_for_node(self, node_id: str) -> list[dict]:
        edges = (self.store.get() or {}).get("edges", [])
        return [e for e in edges if e["source"] == node_id or e["target"] == node_id]

    def related_nodes(self, node_id: str) -> list[dict]:
        """Return adjacent nodes reachable from the given node id."""
        edges = self.edges_for_node(node_id)
        node_ids = set()
        for e in edges:
            node_ids.add(e["source"])
            node_ids.add(e["target"])
        node_ids.discard(node_id)
        all_nodes = (self.store.get() or {}).get("nodes", [])
        return [n for n in all_nodes if n["id"] in node_ids]

    def stats(self) -> dict:
        data = self.store.get() or {}
        return {
            "nodes": len(data.get("nodes", [])),
            "edges": len(data.get("edges", [])),
        }

    def clear(self) -> dict:
        data = self.store.get() or {}
        nodes_count = len(data.get("nodes", []))
        edges_count = len(data.get("edges", []))
        self.store.set({"nodes": [], "edges": []})
        return {"nodes": nodes_count, "edges": edges_count}

    def all_nodes(self) -> list[dict]:
        return (self.store.get() or {}).get("nodes", [])

    def all_edges(self) -> list[dict]:
        return (self.store.get() or {}).get("edges", [])

    # ---------- rendering ----------
    def text_map(self, target: str | None = None) -> str:
        """Readable tree-like relationship view, optionally centered on a target."""
        lines = []
        nodes = self.all_nodes()
        edges = self.all_edges()
        if not nodes:
            return "No graph data has been collected yet."

        if target:
            target_nodes = self.nodes_for_target(target)
            if not target_nodes:
                lines.append(f"No graph nodes found for target: {target}")
                return "\n".join(lines)
            center = target_nodes[0]["id"]
            visited = {center}
            stack = [center]
            local_edges = []
            while stack:
                current = stack.pop()
                for e in edges:
                    if e["source"] == current and e["target"] not in visited:
                        visited.add(e["target"])
                        stack.append(e["target"])
                        local_edges.append(e)
                    elif e["target"] == current and e["source"] not in visited:
                        visited.add(e["source"])
                        stack.append(e["source"])
                        local_edges.append(e)
            node_set = {e["source"] for e in local_edges} | {e["target"] for e in local_edges} | {center}
            by_id = {n["id"]: n for n in nodes if n["id"] in node_set}
            return self._tree_view(center, by_id, local_edges, f"Relationship graph: {target}")

        # Pick a useful root (domain first) and render a readable hierarchy.
        by_id = {n["id"]: n for n in nodes}
        root = next((n for n in nodes if n["type"] == "domain"), nodes[0])
        return self._tree_view(root["id"], by_id, edges, f"Relationship graph ({len(nodes)} nodes, {len(edges)} relationships)")

    def _tree_view(self, root_id: str, by_id: dict, edges: list[dict], title: str) -> str:
        """Render a compact Unicode relationship tree from a root node."""
        children: dict[str, list[dict]] = {}
        for edge in edges:
            if edge["source"] in by_id and edge["target"] in by_id:
                children.setdefault(edge["source"], []).append(edge)
        lines = [title, "─" * max(40, min(70, len(title) + 4))]
        root = by_id.get(root_id)
        if not root:
            return "\n".join(lines)
        lines.append(f"{root['label']} [{TYPE_LABELS.get(root['type'], root['type'])}]")
        visited = {root_id}

        def visit(parent: str, prefix: str = "") -> None:
            outgoing = [edge for edge in children.get(parent, []) if edge["target"] not in visited]
            for index, edge in enumerate(outgoing):
                child = by_id[edge["target"]]
                visited.add(child["id"])
                branch = "└── " if index == len(outgoing) - 1 else "├── "
                lines.append(f"{prefix}{branch}{edge['relationship']} → {child['label']} [{TYPE_LABELS.get(child['type'], child['type'])}]")
                visit(child["id"], prefix + ("    " if index == len(outgoing) - 1 else "│   "))

        visit(root_id)
        # Show disconnected entities rather than silently hiding them.
        for node in by_id.values():
            if node["id"] not in visited:
                lines.append(f"• {node['label']} [{TYPE_LABELS.get(node['type'], node['type'])}] (unconnected)")
        return "\n".join(lines)

    def to_json(self) -> dict:
        nodes = self.all_nodes()
        edges = self.all_edges()
        return {
            "nodes": nodes,
            "edges": edges,
            "summary": self.stats(),
            "exported_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }

    def to_graphml(self) -> str:
        """Produce a GraphML document suitable for import into graph tools."""
        nodes = self.all_nodes()
        edges = self.all_edges()
        if not nodes and not edges:
            return "No graph data to export."
        lines = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            '<graphml xmlns="http://graphml.graphdrawing.org/xmlns"',
            '    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"',
            '    xsi:schemaLocation="http://graphml.graphdrawing.org/xmlns',
            '    http://graphml.graphdrawing.org/xmlns/1.0/graphml.xsd">',
            '  <key id="d0" for="node" attr.name="label" attr.type="string"/>',
            '  <key id="d1" for="node" attr.name="type" attr.type="string"/>',
            '  <key id="d2" for="edge" attr.name="relationship" attr.type="string"/>',
            '  <graph edgedefault="directed">',
        ]
        for n in nodes:
            label = html.escape(str(n["label"]))
            typ = html.escape(str(n["type"]))
            lines.append(f'    <node id="{n["id"]}"><data key="d0">{label}</data><data key="d1">{typ}</data></node>')
        for e in edges:
            relationship = html.escape(str(e["relationship"]))
            lines.append(f'    <edge id="{e["id"]}" source="{e["source"]}" target="{e["target"]}"><data key="d2">{relationship}</data></edge>')
        lines.append('  </graph>')
        lines.append('</graphml>')
        return "\n".join(lines)
