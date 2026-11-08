"""Wayback Machine history: capture span, archived URLs and removed pages."""
from __future__ import annotations

import asyncio
import re
from urllib.parse import urlparse

from core import netutils as net

from .base import BasePlugin

SENSITIVE_PATTERNS = (
    (".env", "environment file"),
    (".git", "git metadata"),
    (".sql", "database dump"),
    (".bak", "backup file"),
    (".old", "old version"),
    (".swp", "editor swap file"),
    (".zip", "archive"),
    (".tar", "archive"),
    (".7z", "archive"),
    ("backup", "backup path"),
    ("config", "configuration path"),
    ("admin", "admin path"),
    ("debug", "debug endpoint"),
    ("phpinfo", "phpinfo page"),
    ("id_rsa", "private key"),
    ("credentials", "credentials file"),
)


class Wayback(BasePlugin):
    """Read-only Wayback Machine (CDX) intelligence."""

    CDX = "https://web.archive.org/cdx/search/cdx"
    AVAILABLE = "https://archive.org/wayback/available"

    async def run_all(self, target):
        return await self.overview(target)

    async def run_sub(self, sub_id, target):
        handlers = {
            "wayback_overview": self.overview,
            "wayback_urls": self.archived_urls,
            "wayback_deleted": self.removed_pages,
        }
        handler = handlers.get(sub_id)
        if handler is None:
            return f"[!] Archive tool '{sub_id}' is not registered."
        return await handler(target)

    # ------------------------------------------------------------- plumbing

    async def _cdx(self, target: str, limit: int = 4000, collapse: str = "urlkey"):
        url = net.ensure_url(target)
        params = {
            "url": url,
            "output": "json",
            "limit": limit,
            "collapse": collapse,
            "fl": "timestamp,original,statuscode,mimetype",
        }
        last_error = "no response"
        for attempt in range(3):
            response, error = await net.get(self.client, self.CDX, timeout=60, params=params)
            if response is not None and response.status_code == 200:
                try:
                    rows = response.json()
                except ValueError:
                    last_error = "CDX returned non-JSON output"
                    continue
                if not rows:
                    return [], ""
                header, *data = rows
                entries = []
                for row in data:
                    if isinstance(row, list) and len(row) == len(header):
                        entries.append(dict(zip(header, row)))
                return entries, ""
            if response is not None and response.status_code in {429, 502, 503, 504}:
                last_error = f"CDX busy (HTTP {response.status_code})"
                await asyncio.sleep(2 + attempt * 2)
                continue
            return [], (error or f"HTTP {getattr(response, 'status_code', '?')}")
        return [], last_error

    @staticmethod
    def _stamp(value: str) -> str:
        value = str(value or "")
        if len(value) >= 14:
            return f"{value[0:4]}-{value[4:6]}-{value[6:8]} {value[8:10]}:{value[10:12]}"
        return value or "unknown"

    # ------------------------------------------------------------- overview

    async def overview(self, target):
        url = net.ensure_url(target)
        host = net.host_of(url)
        if not host:
            return "[!] Enter a website URL or domain."
        lines = [f"[>] Wayback Machine history for {url}"]

        response, error = await net.get(self.client, self.AVAILABLE, timeout=30, params={"url": url})
        closest = {}
        if response is not None and response.status_code == 200:
            closest = ((response.json() or {}).get("archived_snapshots") or {}).get("closest") or {}

        entries, cdx_error = await self._cdx(url, limit=4000, collapse="urlkey")
        if cdx_error:
            lines.append(f"[!] CDX index unavailable ({cdx_error}).")
        if not entries and not closest:
            lines.append("[-] No archived captures were found for this URL.")
            lines.append("[!] Private, new or crawl-blocked sites are often absent from the archive.")
            return "\n".join(lines)

        if entries:
            stamps = sorted(str(entry.get("timestamp", "")) for entry in entries)
            first, last = stamps[0], stamps[-1]
            unique_paths = {urlparse(entry.get("original", "")).path for entry in entries}
            hosts = {net.host_of(entry.get("original", "")) for entry in entries if net.host_of(entry.get("original", ""))}
            lines.extend([
                f"[+] Unique archived URLs: {len(entries)}",
                f"[+] Distinct paths: {len(unique_paths)}",
                f"[+] Hosts seen: {', '.join(sorted(hosts)[:8])}",
                f"[+] First capture: {self._stamp(first)}",
                f"[+] Last capture: {self._stamp(last)}",
            ])
            self.node(host, "domain")
            for seen_host in sorted(hosts)[:10]:
                self.node(seen_host, "subdomain" if seen_host != host else "domain")
                if seen_host != host:
                    self.edge(host, seen_host, "contains", "domain", "subdomain")
            self.finding(
                f"Archive holds {len(entries)} captures for {host}",
                f"Wayback history spans {self._stamp(first)} to {self._stamp(last)} across "
                f"{len(unique_paths)} distinct paths.",
                "INFO", "archive", tags=["wayback", "history"],
            )
        if closest:
            lines.append(
                f"[+] Closest snapshot: {closest.get('timestamp', 'unknown')} "
                f"({closest.get('status', 'unknown')}) {closest.get('url', '')}"
            )
            lines.append(f"[>] Open snapshot: {closest.get('url', '')}")
        lines.append("[!] Archive coverage depends on what crawlers actually stored.")
        return "\n".join(lines)

    # ----------------------------------------------------------- archived urls

    async def archived_urls(self, target):
        entries, error = await self._cdx(net.ensure_url(target), limit=6000, collapse="urlkey")
        if error:
            return f"[!] CDX index unavailable ({error}). Try again shortly."
        if not entries:
            return f"[-] No archived URLs were found for {target}."

        urls = sorted({str(entry.get("original", "")) for entry in entries if entry.get("original")})
        interesting = []
        for url in urls:
            lowered = url.lower()
            labels = [label for token, label in SENSITIVE_PATTERNS if token in lowered]
            if labels:
                interesting.append((url, sorted(set(labels))))

        lines = [
            f"[>] Archived URLs for {net.ensure_url(target)}",
            f"[+] Archived URLs: {len(urls)}",
            f"[!] Sensitive-looking URLs: {len(interesting)}",
        ]
        for url, labels in interesting[:30]:
            lines.append(f"[-] {url[:150]} ({', '.join(labels)})")
        if len(interesting) > 30:
            lines.append(f"[!] {len(interesting) - 30} more sensitive-looking URLs not shown")
        lines.extend(f"[+] {url[:150]}" for url in urls[:40])
        if len(urls) > 40:
            lines.append(f"[!] {len(urls) - 40} more URLs not shown")

        host = net.host_of(net.ensure_url(target))
        for url, _labels in interesting[:50]:
            self.node(url, "url", {"source": "wayback", "sensitive": True})
        if interesting:
            self.finding(
                "Archived URLs include sensitive-looking paths",
                f"{len(interesting)} archived URL(s) match backup, config, database or admin patterns "
                f"(for example {interesting[0][0][:120]}). Verify whether they are still reachable.",
                "MEDIUM", "exposure", tags=["wayback", "archived-paths"],
            )
        if host:
            self.node(host, "domain")
        lines.append("[!] Archived paths may be long gone; confirm current state before reporting exposure.")
        return "\n".join(lines)

    # ---------------------------------------------------------- removed pages

    async def removed_pages(self, target):
        entries, error = await self._cdx(net.ensure_url(target), limit=1500, collapse="urlkey")
        if error:
            return f"[!] CDX index unavailable ({error}). Try again shortly."
        if not entries:
            return f"[-] No archived URLs were found for {target}."

        host = net.host_of(net.ensure_url(target))
        urls = [str(entry.get("original", "")) for entry in entries if entry.get("original")]
        sample = [url for url in dict.fromkeys(urls) if net.host_of(url) == host][:20]
        if not sample:
            return f"[!] No same-host archived URLs were available to compare for {host}."

        async def live_state(url: str):
            response, failure = await net.get(self.client, url, timeout=12)
            if response is None:
                return url, f"unreachable ({failure})", False
            return url, f"HTTP {response.status_code}", 400 <= response.status_code < 500

        results = await asyncio.gather(*(live_state(url) for url in sample))
        gone = [(url, status) for url, status, missing in results if missing]
        lines = [
            f"[>] Archived vs live comparison for {host}",
            f"[+] Archived URLs sampled: {len(sample)}",
            f"[!] Currently missing (4xx): {len(gone)}",
        ]
        for url, status in gone[:20]:
            lines.append(f"[-] {url[:140]} -> {status} now, archived earlier")
        for url, status, _missing in results:
            if (url, status) not in gone:
                lines.append(f"[+] {url[:140]} -> {status} now")
        if gone:
            self.finding(
                f"{len(gone)} archived page(s) are no longer live",
                "Removed pages in " + host + " may still be readable in the archive; review whether they exposed anything sensitive.",
                "LOW", "archive", tags=["wayback", "removed-content"],
            )
        lines.append("[!] A 4xx can also mean routing or auth changes rather than deleted content.")
        return "\n".join(lines)
