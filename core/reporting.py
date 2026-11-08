from __future__ import annotations

import csv
import json
import re
from datetime import datetime, timezone
from pathlib import Path


SECRET_PATTERN = re.compile(
    r"(?i)\b(api[_-]?key|access[_-]?key|token|authorization|password|passwd|secret)\b"
    r"(\s*[:=]\s*)(\S+)"
)
MARKERS = {"[+]": "ok", "[-]": "issue", "[!]": "note", "[>]": "info"}


def redact(text: str) -> str:
    return SECRET_PATTERN.sub(r"\1\2[REDACTED]", str(text))


def safe_lines(result: str) -> list[str]:
    return [redact(line) for line in str(result).splitlines()]


def classify(line: str) -> str:
    for marker, label in MARKERS.items():
        if line.strip().startswith(marker):
            return label
    return "text"


def summarize(lines: list[str]) -> dict:
    counts = {"ok": 0, "issue": 0, "note": 0, "info": 0, "text": 0}
    for line in lines:
        counts[classify(line)] += 1
    return counts


def export_report(result: str, target: str, tool: str, output_dir: str = "outputs") -> dict[str, str]:
    """Write the run to JSON, CSV and Markdown, redacting secrets on the way out."""
    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    stem = re.sub(r"[^a-zA-Z0-9_-]+", "_", f"{tool}_{target}").strip("_")[:80] or "scylla_report"
    lines = safe_lines(result)
    counts = summarize(lines)
    metadata = {
        "app": "Scylla",
        "tool": tool,
        "target": redact(target),
        "created_at": stamp,
        "summary": counts,
        "entries": [{"status": classify(line), "text": line} for line in lines],
        "findings": lines,
    }
    paths = {
        "json": directory / f"{stem}_{stamp}.json",
        "csv": directory / f"{stem}_{stamp}.csv",
        "md": directory / f"{stem}_{stamp}.md",
    }

    paths["json"].write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")

    with paths["csv"].open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["status", "marker", "finding"])
        for line in lines:
            marker = line.strip()[:3] if line.strip()[:3] in MARKERS else ""
            writer.writerow([classify(line), marker, line])

    sections = [
        ("Issues", "issue"),
        ("Notes and limitations", "note"),
        ("Observed", "ok"),
        ("Context", "info"),
    ]
    markdown = [
        "# Scylla Report",
        "",
        f"- Tool: `{tool}`",
        f"- Target: `{redact(target)}`",
        f"- Created: `{stamp}`",
        f"- Entries: {len(lines)} (issues: {counts['issue']}, notes: {counts['note']}, observed: {counts['ok']})",
        "",
    ]
    for title, key in sections:
        selected = [line for line in lines if classify(line) == key]
        if not selected:
            continue
        markdown.append(f"## {title}")
        markdown.append("")
        markdown.extend(f"- {line}" for line in selected)
        markdown.append("")
    remainder = [line for line in lines if classify(line) == "text"]
    if remainder:
        markdown.append("## Raw output")
        markdown.append("")
        markdown.extend(f"    {line}" for line in remainder)
        markdown.append("")
    markdown.append("_Results are research leads; verify important findings manually._")
    paths["md"].write_text("\n".join(markdown) + "\n", encoding="utf-8")

    return {kind: str(path) for kind, path in paths.items()}
