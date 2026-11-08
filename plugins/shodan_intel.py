"""Shodan host intelligence: free InternetDB first, full API when keyed."""
from __future__ import annotations

import asyncio

from core import netutils as net

from .base import BasePlugin

RISKY_PORTS = {21: "FTP", 23: "Telnet", 445: "SMB", 1433: "MSSQL", 3306: "MySQL",
               3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 27017: "MongoDB"}


class ShodanIntel(BasePlugin):
    """Exposed-service context with an honest free/keyed split."""

    INTERNETDB = "https://internetdb.shodan.io/{ip}"
    API = "https://api.shodan.io"

    async def run_all(self, target):
        return await self.host(target)

    async def run_sub(self, sub_id, target):
        handlers = {"shodan_host": self.host, "shodan_search": self.search}
        handler = handlers.get(sub_id)
        if handler is None:
            return f"[!] Shodan tool '{sub_id}' is not registered."
        return await handler(target)

    def _key(self) -> str:
        return self.config.provider_key("shodan") if self.config is not None else ""

    @staticmethod
    async def _address(target) -> str:
        value = str(target or "").strip()
        if net.is_ip(value):
            return value
        addresses = await asyncio.to_thread(net.resolve_addresses, net.host_of(value) or value)
        return addresses[0] if addresses else ""

    async def host(self, target):
        address = await self._address(target)
        if not address:
            return f"[!] Could not resolve {target or 'the supplied target'} to an IP address."
        lines = [f"[>] Shodan host intelligence for {target} ({address})"]

        response, error = await net.get(self.client, self.INTERNETDB.format(ip=address), timeout=25)
        if response is not None and response.status_code == 200:
            payload = response.json() or {}
            ports = payload.get("ports") or []
            vulns = payload.get("vulns") or []
            lines.extend([
                "[>] Source: Shodan InternetDB (free cached snapshot)",
                f"[{'!' if ports else '+'}] Exposed ports: {', '.join(str(port) for port in ports) or 'none cached'}",
                f"[+] Hostnames: {', '.join(payload.get('hostnames', [])[:8]) or 'none published'}",
                f"[+] CPEs: {', '.join(payload.get('cpes', [])[:6]) or 'none published'}",
                f"[+] Tags: {', '.join(payload.get('tags', [])[:8]) or 'none'}",
            ])
            self.node(address, "ip")
            for port in ports[:25]:
                self.node(f"{address}:{port}", "host", {"port": port, "source": "shodan"})
                self.edge(address, f"{address}:{port}", "uses", "ip", "host")
                if port in RISKY_PORTS:
                    self.finding(
                        f"Shodan records {RISKY_PORTS[port]} exposed on {address}:{port}",
                        f"InternetDB lists TCP {port} ({RISKY_PORTS[port]}) open for {address}.",
                        "MEDIUM", "exposure", tags=["shodan", RISKY_PORTS[port].lower()],
                    )
            if vulns:
                lines.append(f"[-] Known CVEs referenced: {', '.join(vulns[:12])}")
                self.finding(
                    f"{len(vulns)} known CVE(s) referenced for {address}",
                    "Shodan InternetDB links these CVEs to the observed software: " + ", ".join(vulns[:10]),
                    "HIGH", "vulnerability", tags=["shodan", "cve"],
                )
            else:
                lines.append("[+] No CVE references were cached for this address.")
        elif response is not None and response.status_code == 404:
            lines.append("[!] Shodan InternetDB has no cached record for this address.")
        else:
            lines.append(f"[!] InternetDB lookup failed ({error or 'HTTP ' + str(getattr(response, 'status_code', '?'))}).")

        key = self._key()
        if not key:
            lines.append("[>] Add a Shodan API key in SETTINGS for banners, history, hostnames and vuln detail.")
        else:
            detail, detail_error = await net.get(
                self.client, f"{self.API}/shodan/host/{address}", timeout=30, params={"key": key}
            )
            if detail is not None and detail.status_code == 200:
                payload = detail.json() or {}
                lines.extend([
                    "[>] Source: Shodan API (keyed)",
                    f"[+] Organization: {payload.get('org') or 'not published'}",
                    f"[+] ISP: {payload.get('isp') or 'not published'}",
                    f"[+] OS: {payload.get('os') or 'not published'}",
                    f"[+] Last update: {payload.get('last_update') or 'unknown'}",
                ])
                for match in payload.get("data", [])[:6]:
                    product = " ".join(
                        str(part) for part in (match.get("product"), match.get("version")) if part
                    ) or match.get("transport", "")
                    lines.append(
                        f"    [+] {match.get('port')}/{match.get('transport', 'tcp')} "
                        f"{product or 'service'} {match.get('_shodan', {}).get('module', '')}"
                    )
            else:
                lines.append(f"[!] Keyed Shodan lookup failed ({detail_error or 'HTTP ' + str(getattr(detail, 'status_code', '?'))}).")

        lines.append("[!] Cached observations can lag reality; verify open services from an authorized network.")
        return "\n".join(lines)

    async def search(self, target):
        query = str(target or "").strip()
        if not query:
            return "[!] Enter a Shodan query, for example: org:\"Example Inc\""
        key = self._key()
        if not key:
            return "\n".join([
                f"[>] Shodan search for: {query}",
                "[!] Shodan's search endpoint needs an API key with search credits; none is configured.",
                "[>] Add it under SETTINGS (SHODAN) or set SHODAN_API_KEY in your local .env.",
                "[>] The Shodan Host tool works without a key through InternetDB.",
                "[!] No results were fabricated.",
            ])
        response, error = await net.get(
            self.client, f"{self.API}/shodan/host/search", timeout=45, params={"key": key, "query": query}
        )
        if response is None:
            return f"[!] Shodan search failed ({error})."
        if response.status_code in {401, 403}:
            return "[!] This Shodan key was rejected or lacks search credits. Use the Shodan Host tool instead."
        if response.status_code != 200:
            return f"[!] Shodan search returned HTTP {response.status_code}."
        payload = response.json() or {}
        matches = payload.get("matches", []) or []
        lines = [
            f"[>] Shodan search: {query}",
            f"[+] Total matches: {payload.get('total', 0)}",
            f"[+] Matches shown: {len(matches)}",
        ]
        for match in matches[:15]:
            lines.append(
                f"[+] {match.get('ip_str')}:{match.get('port')} "
                f"({match.get('org') or 'unknown org'}) {match.get('product') or ''}"
            )
            if match.get("ip_str"):
                self.node(match["ip_str"], "ip", {"org": match.get("org")})
        self.finding(
            f"Shodan search returned {payload.get('total', 0)} match(es)",
            f"Query: {query}. Review only assets you own or are authorized to assess.",
            "INFO", "exposure", tags=["shodan", "search"],
        )
        lines.append("[!] Shodan data is observed third-party scanning; confirm ownership before contact or testing.")
        return "\n".join(lines)
