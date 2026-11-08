"""Authorized vulnerability-surface review with real checks (no invented output)."""
from __future__ import annotations

import asyncio
import re
from urllib.parse import urlparse

from core import netutils as net

from .base import BasePlugin

SERVICE_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8080: "HTTP-alt", 8443: "HTTPS-alt", 27017: "MongoDB",
}
RISKY_PORTS = {21, 23, 1433, 3306, 3389, 5432, 5900, 6379, 27017}


class VulnFinder(BasePlugin):
    """Real, low-volume checks against an authorized target."""

    async def run_all(self, target):
        parts = await asyncio.gather(
            self.analyze_ports(target),
            self.fingerprint_tech(target),
            self.discover_subdomains(target),
        )
        return "\n\n".join(part for part in parts if part)

    async def run_sub(self, sub_id, target):
        handlers = {
            "sub_ports": self.analyze_ports,
            "sub_ddos_assessment": self.assess_ddos_resilience,
            "sub_subdomains": self.discover_subdomains,
            "sub_tech": self.fingerprint_tech,
            "sub_cves": self.match_cves,
            "sub_buckets": self.check_buckets,
        }
        handler = handlers.get(sub_id)
        if handler is None:
            return f"[!] Vulnerability tool '{sub_id}' is not registered."
        return await handler(target)

    # ---------------------------------------------------------------- ports

    @staticmethod
    def _host(target: str) -> str:
        host = net.host_of(target) or net.normalize_domain(target)
        return host.split(":")[0] if host else ""

    async def _probe_port(self, host: str, port: int) -> bool:
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=2.0)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return True
        except (OSError, asyncio.TimeoutError):
            return False

    async def _banner(self, host: str, port: int) -> str:
        """Best-effort service hint for a reachable port (no exploitation)."""
        if port not in {21, 22, 25, 80, 110, 143, 443, 8080, 8443}:
            return ""
        try:
            if port in {443, 8443}:
                info = await asyncio.to_thread(net.tls_info, host, port, 6)
                if info.get("error"):
                    return ""
                return f"TLS {info.get('subject') or host} ({info.get('issuer') or 'issuer unknown'})"
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=3)
            if port in {80, 8080}:
                writer.write(f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
                await writer.drain()
            data = await asyncio.wait_for(reader.read(200), timeout=3)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            text = data.decode("utf-8", errors="replace").strip().splitlines()
            if port in {80, 8080}:
                server = next((line for line in text if line.lower().startswith("server:")), "")
                return server.split(":", 1)[1].strip() if server else (text[0][:80] if text else "")
            return text[0][:80] if text else ""
        except Exception:
            return ""

    async def analyze_ports(self, target):
        host = self._host(target)
        if not host:
            return "[!] Enter a hostname or IP address you are authorized to assess."
        lines = [
            f"[>] Authorized TCP service review for {host}",
            f"[>] Checking {len(SERVICE_PORTS)} common ports with a 2s connect timeout; no exploitation or fingerprinting.",
        ]
        open_ports: list[tuple[int, str]] = []
        results = await asyncio.gather(*(self._probe_port(host, port) for port in SERVICE_PORTS))
        for (port, label), is_open in zip(SERVICE_PORTS.items(), results):
            if is_open:
                open_ports.append((port, label))

        banners = await asyncio.gather(*(self._banner(host, port) for port, _label in open_ports[:6]))
        banner_map = {port: banner for (port, _label), banner in zip(open_ports[:6], banners) if banner}

        self.node(host, "ip" if net.is_ip(host) else "host")
        for port, label in open_ports:
            service = f"{label}/{port}"
            hint = f" — {banner_map[port]}" if port in banner_map else ""
            lines.append(f"[!] {service}: reachable from this check — confirm it must be public{hint}")
            self.node(f"{host}:{port}", "host", {"service": label, "port": port})
            self.edge(host, f"{host}:{port}", "uses", "host", "host")
            if port in RISKY_PORTS:
                self.finding(
                    f"Management/data service exposed: {label} ({port}/{host})",
                    f"{host} accepted a TCP connection on {port} ({label}). Verify this is intentional and restricted by network controls.",
                    "MEDIUM", "exposure", tags=["open-port", label.lower()],
                )
        if not open_ports:
            lines.append("[+] None of the checked ports responded from this network location.")

        lines.append(f"[+] Reachable services: {len(open_ports)} of {len(SERVICE_PORTS)} checked")
        lines.append("[!] Closed results can be caused by a firewall or upstream block; absence is not proof of closure.")
        lines.append("[!] Only scan systems you own or are explicitly authorized to assess.")
        return "\n".join(lines)

    # ------------------------------------------------------------ ddos check

    async def assess_ddos_resilience(self, target):
        """Single-request, evidence-based resilience review (never generates load)."""
        target = str(target).strip()
        url = net.ensure_url(target)
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.username or parsed.password:
            return "[!] Provide a valid website URL, such as https://example.com"

        report = [
            f"[>] Defensive DDoS resilience assessment for {url}",
            "[>] Safe assessment: one ordinary GET; no flooding, UDP, packet generation, or stress testing.",
            "[>] Results are evidence-based; a missing header is not treated as proof of a vulnerability.",
        ]
        try:
            started = asyncio.get_running_loop().time()
            response = await self.client.get(url, headers={"User-Agent": net.USER_AGENT, "Cache-Control": "no-cache"})
            elapsed_ms = round((asyncio.get_running_loop().time() - started) * 1000)
            headers = {key.lower(): value.strip() for key, value in response.headers.items()}
            server = headers.get("server", "").lower()
            cdn_headers = {"cf-ray", "x-cache", "x-cdn", "x-amz-cf-id", "x-sucuri-id", "akamai-grn"}
            edge_names = {"cf-ray": "Cloudflare", "x-amz-cf-id": "CloudFront", "x-sucuri-id": "Sucuri", "akamai-grn": "Akamai"}
            edge = next((name for header, name in edge_names.items() if header in headers), "")
            if not edge and cdn_headers.intersection(headers):
                edge = "CDN/WAF indicators detected"
            if not edge and "cloudflare" in server:
                edge = "Cloudflare"
            cache = headers.get("cache-control", "")
            rate_headers = {"retry-after", "ratelimit-limit", "x-ratelimit-limit", "x-rate-limit-limit"}
            rate_signal = bool(rate_headers.intersection(headers)) or response.status_code == 429
            status_ok = 200 <= response.status_code < 400
            body_size = len(response.content or b"")
            hsts = "strict-transport-security" in headers
            cache_ok = bool(cache) and "no-store" not in cache.lower()

            report.extend([
                f"[{'+' if status_ok else '-'}] HTTP availability: {response.status_code} ({elapsed_ms} ms, {body_size} bytes)",
                "",
                "Observed protections",
                f"[{'+' if edge else '!'}] Edge/CDN/WAF: {edge or 'not identifiable from this response'}",
                f"[{'+' if rate_signal else '!'}] Rate limiting: {'advertised or enforced' if rate_signal else 'not observable from one request'}",
                f"[{'+' if cache_ok else '!'}] Caching: {cache or 'no cache policy advertised'}",
                f"[{'+' if hsts else '!'}] HTTPS hardening: {'HSTS enabled' if hsts else 'HSTS not confirmed'}",
                "",
                "Exposure by attack category (public evidence only)",
                f"[{'!' if edge else '!'}] HTTP/L7 flood: {'edge filtering may absorb some traffic; verify limits in the provider dashboard' if edge else 'no control was observable'}",
                "[-] POST/body floods: not tested; configure request-body limits and WAF rules",
                "[-] Slow HTTP/connection exhaustion: not tested; set short header/body timeouts",
                "[-] UDP amplification: not assessed by this HTTP-only tool",
                "",
                "What needs attention",
                f"[{'-' if body_size > 2_000_000 else '+'}] Large GET response: {body_size} bytes" + (" — paginate, compress, or cache it" if body_size > 2_000_000 else ""),
                f"[{'+' if rate_signal else '!'}] Rate limiting: {'verify per-IP and per-session limits on expensive routes' if rate_signal else 'configure and verify per-IP/per-session limits'}",
                "",
                "Recommended fixes",
                "[+] CDN/WAF rate limiting with per-IP, per-session and route-specific rules",
                "[+] Request-body, connection, upstream and keep-alive timeouts",
                "[+] Cache static content and review expensive GET/POST endpoints",
                "[+] Keep the origin private and allow traffic only from the edge",
                "[+] Bot controls, traffic dashboards and spike alerts",
                "",
                "[+] Defensive assessment complete.",
                "[!] No attack traffic was generated; effectiveness claims rest only on observable response evidence.",
            ])
            if not edge:
                self.finding(
                    "No edge/DDoS protection observable",
                    f"A single request to {url} exposed no CDN/WAF signal. Confirm whether protection exists before a real traffic spike.",
                    "LOW", "resilience", tags=["ddos", "cdn"],
                )
            if body_size > 2_000_000:
                self.finding(
                    "Oversized GET response increases flood cost",
                    f"{url} returned {body_size} bytes for a normal GET, which amplifies bandwidth cost under load.",
                    "LOW", "resilience", tags=["performance"],
                )
        except Exception as error:
            report.extend([
                f"[-] HTTP availability: assessment request failed ({type(error).__name__})",
                "[!] No resilience conclusion can be made from this failed request.",
                "[>] Verify the URL, TLS certificate, DNS and authorized network access.",
            ])
        return "\n".join(report)

    # ---------------------------------------------------------- subdomains

    async def _resolve_name(self, name: str) -> tuple[str, list[str]]:
        addresses = await asyncio.to_thread(net.resolve_addresses, name)
        return name, addresses

    async def discover_subdomains(self, target):
        domain = net.normalize_domain(str(target))
        if not domain:
            return "[!] Enter a domain such as example.com"
        lines = [f"[>] Public subdomain discovery for {domain}", "[>] Passive certificate logs plus DNS resolution of common names."]

        entries, error = await net.crt_entries(self.client, domain)
        cert_names = net.crt_names(entries, domain) if not error else []
        if error:
            lines.append(f"[!] Certificate-transparency lookup unavailable ({error}); continuing with DNS only.")

        candidates = dict.fromkeys([*cert_names, *(f"{prefix}.{domain}" for prefix in net.COMMON_SUBDOMAINS)])
        resolved: dict[str, list[str]] = {}
        results = await net.gather_limited((self._resolve_name(name) for name in candidates), limit=12)
        for result in results:
            if isinstance(result, Exception):
                continue
            name, addresses = result
            if addresses:
                resolved[name] = addresses

        for name in cert_names:
            self.node(name, "subdomain")
            self.edge(domain, name, "contains", "domain", "subdomain")

        lines.append(f"[+] Live names resolved: {len(resolved)}")
        for name in sorted(resolved):
            lines.append(f"[+] {name}: {', '.join(resolved[name][:3])}")
            self.node(name, "subdomain")
            self.edge(domain, name, "contains", "domain", "subdomain")
            for address in resolved[name][:3]:
                self.node(address, "ip")
                self.edge(name, address, "resolves_to", "subdomain", "ip")
        if not resolved:
            lines.append("[-] No names resolved from certificate logs or the common-name list.")

        sensitive = [name for name in resolved if re.match(r"^(admin|dev|staging|test|internal|jenkins|grafana|kibana|jira|s3|vpn|git)\.", name)]
        if sensitive:
            self.finding(
                "Sensitive-sounding hostnames are publicly resolvable",
                "These names resolved publicly: " + ", ".join(sorted(sensitive)[:10]) + ". Confirm they should be internet-facing.",
                "LOW", "exposure", tags=["subdomain", "asset-inventory"],
            )
        lines.append(f"[+] Certificate-log names seen: {len(cert_names)}")
        lines.append("[!] Discovery is passive and wordlist-limited; unlisted names may exist.")
        return "\n".join(lines)

    # ---------------------------------------------------------------- tech

    async def fingerprint_tech(self, target):
        url = net.ensure_url(str(target))
        response, error = await net.get(self.client, url, timeout=15)
        if response is None:
            return f"[!] Technology fingerprint failed ({error}). Check the URL and that it is reachable."
        headers = {key.lower(): value for key, value in response.headers.items()}
        signals = net.fingerprint(response.text, response.headers)
        meta = net.page_metadata(response.text)

        lines = [f"[>] Passive technology fingerprint for {url}", f"[+] HTTP response: {response.status_code}"]
        lines.extend(f"[+] {name} — evidence: {evidence}" for name, evidence in signals)
        if not signals:
            lines.append("[!] No confident technology signal was detected from headers or HTML.")
        for header_name in ("server", "x-powered-by", "via"):
            if headers.get(header_name):
                lines.append(f"[+] Header {header_name}: {headers[header_name]}")
        if meta["generator"]:
            lines.append(f"[+] Meta generator: {meta['generator']}")

        host = net.host_of(url)
        self.node(host, "domain")
        for name, evidence in signals:
            self.node(name, "technology", {"evidence": evidence})
            self.edge(host, name, "uses", "domain", "technology")
        lines.append("[!] Fingerprinting is heuristic; proxies and custom headers can hide or spoof it.")
        return "\n".join(lines)

    # ---------------------------------------------------------------- cves

    async def _nvd_search(self, keyword: str, limit: int = 12) -> tuple[list[dict], str]:
        key = ""
        if self.config is not None:
            key = self.config.provider_key("nvd")
        headers = {"User-Agent": net.USER_AGENT}
        if key:
            headers["apiKey"] = key
        try:
            response = await self.client.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={"keywordSearch": keyword, "resultsPerPage": limit},
                headers=headers, timeout=30,
            )
        except Exception as error:
            return [], type(error).__name__
        if response.status_code != 200:
            return [], f"HTTP {response.status_code}"
        try:
            payload = response.json()
        except ValueError:
            return [], "invalid JSON from NVD"
        return payload.get("vulnerabilities", []) or [], ""

    @staticmethod
    def _cve_summary(item: dict) -> tuple[str, str, str, str]:
        cve = item.get("cve", {}) or {}
        identifier = cve.get("id", "unknown CVE")
        descriptions = cve.get("descriptions", []) or []
        summary = next((entry.get("value", "") for entry in descriptions if entry.get("lang") == "en"), "")
        metrics = cve.get("metrics", {}) or {}
        score, severity = "", ""
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            for metric in metrics.get(key, []) or []:
                data = metric.get("cvssData", {}) or {}
                score = str(data.get("baseScore", "")) or score
                severity = str(data.get("baseSeverity", "") or metric.get("baseSeverity", "")).upper() or severity
                if score:
                    break
            if score:
                break
        return identifier, summary, score, severity

    async def match_cves(self, target):
        url = net.ensure_url(str(target))
        response, error = await net.get(self.client, url, timeout=15)
        if response is None:
            return f"[!] CVE matching needs a reachable website to fingerprint first ({error})."
        signals = net.fingerprint(response.text, response.headers)
        if not signals:
            return "\n".join([
                "[!] No software could be fingerprinted, so no keyword-based CVE search was made.",
                "[>] Provide a more specific URL (a login page or product page) or check the service manually.",
                "[!] No CVE match was invented.",
            ])

        keywords = [name for name, _ in signals if name not in {"jQuery", "React", "Vue.js", "PHP session", "Java application server"}][:2]
        lines = [
            f"[>] CVE research for {url}",
            f"[+] Fingerprinted software used as keywords: {', '.join(keywords)}",
            "[>] Keyword search over the NVD CVE API; version-specific matches still need manual confirmation.",
        ]
        total = 0
        for keyword in keywords:
            items, nvd_error = await self._nvd_search(keyword)
            if nvd_error:
                lines.append(f"[!] NVD lookup for '{keyword}' unavailable ({nvd_error}).")
                continue
            if not items:
                lines.append(f"[+] {keyword}: no CVE records matched this keyword.")
                continue
            lines.append(f"[+] {keyword}: {len(items)} recent CVE records")
            for item in items[:8]:
                identifier, summary, score, severity = self._cve_summary(item)
                total += 1
                tag = f" CVSS {score}" if score else (f" {severity}" if severity else "")
                lines.append(f"[+] {identifier}{tag}: {summary[:220]}")
                self.node(identifier, "technology", {"type": "cve", "keyword": keyword})
                if severity in {"CRITICAL", "HIGH"}:
                    self.finding(
                        f"{severity} CVE related to {keyword}: {identifier}",
                        summary[:600],
                        severity, "vulnerability", tags=["cve", keyword.lower()],
                    )
            await asyncio.sleep(1.0 if self.config and self.config.provider_key("nvd") else 6.0)
        lines.append(f"[+] CVE records reviewed: {total}")
        lines.append("[!] A keyword match is a lead to verify against your exact version; it is not proof of exploitability.")
        return "\n".join(lines)

    # ------------------------------------------------------------- buckets

    async def _candidate_bucket_names(self, target: str) -> list[str]:
        domain = net.normalize_domain(target) or net.host_of(target)
        brand = domain.split(".")[0] if domain else ""
        base = {brand, brand.replace("-", ""), domain.replace(".", "-")}
        suffixes = ("", "-backup", "-dev", "-data", "-assets", "-public", "-static")
        names = []
        for value in base:
            if not value:
                continue
            for suffix in suffixes:
                name = f"{value}{suffix}".strip("-")
                if name and name not in names:
                    names.append(name)
        return names[:6]

    async def check_buckets(self, target):
        names = await self._candidate_bucket_names(str(target))
        if not names:
            return "[!] Enter an organization or domain name so bucket names can be derived."
        lines = [
            f"[>] Public cloud-storage review for {target}",
            f"[>] Probing {len(names)} conventional names across S3, GCS and Azure Blob with read-only requests.",
        ]
        findings = 0
        for name in names:
            probes = await asyncio.gather(*(net.probe_bucket(self.client, provider, name) for provider in ("s3", "gcs", "azure")))
            for probe in probes:
                if not isinstance(probe, dict):
                    continue
                state = probe.get("state")
                if state == "absent" or state == "error":
                    continue
                label = f"{probe.get('provider')}:{name}"
                if state == "public":
                    findings += 1
                    lines.append(f"[-] {label}: PUBLIC listing at {probe.get('url')} — contains publicly listable objects")
                    self.node(probe.get("url", label), "url", {"provider": probe.get("provider"), "bucket": name})
                    self.finding(
                        f"Publicly listable storage bucket: {label}",
                        f"{probe.get('url')} returned a public bucket listing. Confirm ownership and restrict access immediately.",
                        "HIGH", "exposure", tags=["cloud-storage", probe.get("provider", "")],
                    )
                elif state == "exists-private":
                    lines.append(f"[+] {label}: name exists but listing is denied (private or access-controlled)")
                elif state == "unknown":
                    lines.append(f"[!] {label}: inconclusive response (HTTP {probe.get('status')})")
        if not findings:
            lines.append("[+] No publicly listable bucket was confirmed for the conventional names tested.")
        lines.append("[!] Only conventional names were tested, read-only; no objects were downloaded or modified.")
        return "\n".join(lines)
