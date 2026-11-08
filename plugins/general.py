"""Public-information and local-file helpers for the full Scylla catalog.

Every handler here performs a real, read-only check and reports exactly what it
observed. Handlers that cannot run without an optional provider say so instead
of returning invented output.
"""
from __future__ import annotations

import asyncio
import hashlib
import html
import json
import re
import socket
import zipfile
from pathlib import Path
from urllib.parse import urljoin, urlparse

from core import netutils as net

from .base import BasePlugin

SECRET_PATTERNS = [
    ("private key header", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"), "CRITICAL"),
    ("AWS access key id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "HIGH"),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"), "HIGH"),
    ("Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), "HIGH"),
    ("Stripe live key", re.compile(r"\bsk_live_[A-Za-z0-9]{16,}\b"), "CRITICAL"),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "MEDIUM"),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), "MEDIUM"),
    ("OpenAI/Anthropic key", re.compile(r"\bsk-(?:ant-)?[A-Za-z0-9_-]{20,}\b"), "HIGH"),
    ("SendGrid key", re.compile(r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b"), "HIGH"),
    ("npm token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"), "HIGH"),
    ("Discord webhook", re.compile(r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[\w-]+"), "MEDIUM"),
    ("database URL with password", re.compile(r"(?i)\b[a-z]+://[^\s:@/]+:[^\s@/]{6,}@[^\s/]+"), "HIGH"),
    ("generic assignment", re.compile(r"(?i)\b(api[_-]?key|secret|token|password|passwd|access[_-]?key)\b\s*[:=]\s*[\"']?[^\s\"']{8,}"), "MEDIUM"),
]


class GeneralOSINT(BasePlugin):
    """Safe public-information, DNS, local-file and research helpers."""

    # ------------------------------------------------------------- dispatch

    async def run_all(self, target):
        return await self.security_headers(target)

    async def run_sub(self, sub_id, target):
        handlers = {
            # web security
            "security_headers": self.security_headers,
            "ssl_check": self.ssl_check,
            "redirect_checker": self.redirect_checker,
            "robots_analyzer": self.robots_analyzer,
            "sitemap_analyzer": self.sitemap_analyzer,
            "cookie_audit": self.cookie_audit,
            "uptime_check": self.uptime_check,
            "certificate_expiry": self.certificate_expiry,
            "origin_review": self.origin_review,
            "cloud_service_map": self.cloud_service_map,
            # dns / email
            "email_domain_info": self.email_domain_info,
            "spf_check": self.spf_check,
            "dmarc_check": self.dmarc_check,
            "dnssec_check": self.dnssec_check,
            "ip_info": self.ip_info,
            "reverse_dns": self.reverse_dns,
            "whois_lookup": self.whois_lookup,
            "subdomain_enum": self.subdomain_enum,
            "certificate_history": self.certificate_history,
            "certificate_search": self.certificate_search,
            "asn_details": self.asn_details,
            "asn_map": self.network_range,
            "network_range": self.network_range,
            "web_info": self.web_info,
            "infra_map": self.infra_map,
            "company_profile": self.company_profile,
            # research / web pages
            "tech_detect": self.tech_detect,
            "article_summary": self.article_summary,
            "profile_summary": self.article_summary,
            "product_research": self.article_summary,
            "public_links": self.public_links,
            "article_search": self.article_search,
            "place_search": self.place_search,
            "coordinate_info": self.coordinate_info,
            "brand_monitor": self.brand_monitor,
            "email_discovery": self.email_discovery,
            "threat_feed_check": self.threat_feed_check,
            "storage_review": self.storage_review,
            "secret_scan": self.secret_scan,
            # local files
            "image_metadata": self.image_metadata,
            "document_metadata": self.document_metadata,
            "file_inventory": self.file_inventory,
            "metadata_cleaner": self.metadata_cleaner,
            "ocr": self.ocr,
            "text_extract": self.text_extract,
            "dependency_audit": self.dependency_audit,
            "header_analyzer": self.header_analyzer,
            "timeline_notes": self.local_timeline,
            "source_compare": self.local_timeline,
            "timeline_builder": self.local_timeline,
            "exposure_diff": self.exposure_diff,
        }
        handler = handlers.get(sub_id)
        if handler is None:
            return f"[!] This catalog tool is not implemented yet: {sub_id}"
        return await handler(target)

    # -------------------------------------------------------------- helpers

    @staticmethod
    def _url(target: str) -> str:
        return net.ensure_url(str(target or ""))

    def _merge_intel(self, inner: BasePlugin) -> None:
        for entry in inner.intel["findings"]:
            self.finding(entry["title"], entry["description"], entry["severity"], entry["category"], entry["tags"])
        for entry in inner.intel["nodes"]:
            self.node(entry["label"], entry["type"], entry["metadata"])
        for entry in inner.intel["edges"]:
            self.edge(entry["source"], entry["target"], entry["rel"], entry["source_type"], entry["target_type"])

    async def _delegate(self, target, method_name: str) -> str:
        from .infra import InfraDNS

        inner = InfraDNS(self.client)
        inner.config = self.config
        result = await getattr(inner, method_name)(target)
        self._merge_intel(inner)
        return result

    @staticmethod
    def _header_flags(response) -> dict[str, str]:
        return {key.lower(): value for key, value in response.headers.items()}

    # --------------------------------------------------------- web security

    async def security_headers(self, target):
        url = self._url(target)
        response, error = await net.get(self.client, url, timeout=15)
        if response is None:
            return f"[!] Could not retrieve {url} ({error}). Check the URL and network access."
        headers = self._header_flags(response)
        checks = (
            ("Content-Security-Policy", "content-security-policy", "MEDIUM"),
            ("Strict-Transport-Security", "strict-transport-security", "MEDIUM"),
            ("X-Content-Type-Options", "x-content-type-options", "LOW"),
            ("X-Frame-Options", "x-frame-options", "LOW"),
            ("Referrer-Policy", "referrer-policy", "LOW"),
            ("Permissions-Policy", "permissions-policy", "LOW"),
        )
        lines = [
            f"[>] Browser security-header review for {url} ({response.status_code})",
            "[>] Headers tell browsers which defensive rules to enforce.",
            "",
        ]
        missing = 0
        for label, key, severity in checks:
            if key in headers:
                lines.append(f"[+] {label}: {headers[key]}")
            else:
                missing += 1
                lines.append(f"[-] {label}: missing")
                self.finding(
                    f"Missing security header: {label}",
                    f"{url} did not send {label}. Adding it lets browsers enforce the matching defensive rule.",
                    severity, "web-security", tags=["headers", key],
                )
        present = len(checks) - missing
        score = round(present / len(checks) * 100)
        grade = "A" if score >= 90 else "B" if score >= 70 else "C" if score >= 50 else "D" if score >= 30 else "E"
        csp = headers.get("content-security-policy", "")
        unsafe = [flag for flag in ("unsafe-inline", "unsafe-eval", " *") if flag in csp]
        cookies = len(response.headers.get_list("set-cookie"))
        lines.extend([
            "",
            f"[+] Headers present: {present}/{len(checks)} (score {score}/100, grade {grade})",
            f"[{'+' if csp and not unsafe else '!'}] CSP: {('unsafe directives: ' + ', '.join(unsafe)) if unsafe else (csp or 'not published')}",
            f"[+] Cookies set on this response: {cookies}",
            "[!] Missing headers are hardening opportunities, not proof of compromise.",
        ])
        if unsafe:
            self.finding(
                "Content-Security-Policy allows unsafe directives",
                f"{url} publishes a CSP containing {', '.join(unsafe)}, which weakens its XSS protection.",
                "MEDIUM", "web-security", tags=["csp", "headers"],
            )
        self.node(net.host_of(url) or url, "domain")
        return "\n".join(lines)

    async def ssl_check(self, target):
        url = self._url(target)
        host = net.host_of(url)
        info = await asyncio.to_thread(net.tls_info, host)
        lines = [f"[>] TLS and HTTPS review for {url}"]
        if info.get("error"):
            lines.append(f"[-] TLS handshake failed: {info['error']}")
            lines.append("[!] A failed handshake can be a firewall, an invalid certificate, or a wrong hostname.")
            return "\n".join(lines)
        lines.extend([
            f"[+] TLS protocol: {info['version']}",
            f"[+] Cipher: {info['cipher']}",
            f"[+] Certificate subject: {info['subject'] or 'not published'}",
            f"[+] Issued by: {info['issuer'] or 'not published'}",
            f"[+] Expires: {info['expires_at']} ({info['days_left']} days)",
            f"[+] Names on certificate: {len(info['alt_names'])}",
            f"[{'+' if info.get('verified', True) else '!'}] Chain trusted by this device: {'yes' if info.get('verified', True) else 'no'}",
        ])
        if info.get("verification_error"):
            lines.append(f"[!] Local chain verification failed: {info['verification_error']}")
            lines.append("[!] This is often a device trust-store gap rather than a server fault; confirm in a browser.")
        if info["days_left"] is not None and info["days_left"] < 0:
            self.finding("TLS certificate has expired", f"{host} presented a certificate that expired {abs(info['days_left'])} days ago.", "HIGH", "web-security", tags=["tls", "certificate"])
        elif info["days_left"] is not None and info["days_left"] <= 21:
            self.finding("TLS certificate expires soon", f"{host} presented a certificate expiring in {info['days_left']} days.", "MEDIUM", "web-security", tags=["tls", "certificate"])

        response, error = await net.get(self.client, url, timeout=15)
        hsts = self._header_flags(response).get("strict-transport-security", "") if response is not None else ""
        lines.append(f"[{'+' if hsts else '!'}] HSTS: {hsts or 'not sent'}")
        if not hsts:
            lines.append("[>] Add Strict-Transport-Security with a long max-age once HTTPS works everywhere.")
        lines.append("[!] Chain validation and revocation are browser/provider responsibilities; this check reports the live leaf.")
        return "\n".join(lines)

    async def redirect_checker(self, target):
        url = self._url(target)
        chain: list[str] = []
        current = url
        status = None
        for _hop in range(6):
            response, error = await net.get(self.client, current, follow_redirects=False, timeout=15)
            if response is None:
                chain.append(f"{current} -> request failed ({error})")
                break
            status = response.status_code
            location = response.headers.get("location", "")
            chain.append(f"{status} {current}")
            if not location or status not in {301, 302, 303, 307, 308}:
                break
            current = urljoin(current, location)
        lines = [f"[>] Redirect review for {url}"] + [f"[+] {step}" for step in chain]
        if status and 300 <= status < 400:
            lines.append(f"[!] Final hop still returns {status}; the chain did not terminate in 6 hops.")
        cross = len({net.host_of(step.split(" ")[-1]) for step in chain if step.split(" ")[-1].startswith("http")}) > 1
        if cross:
            lines.append("[!] This URL crosses domains; verify the destination is intentional and owned by the same party.")
            self.finding("Cross-domain redirect chain", f"{url} redirects across hosts: {' -> '.join(step.split(' ')[-1] for step in chain[:4])}", "LOW", "web-security", tags=["redirect"])
        lines.append("[+] Redirect chain complete.")
        return "\n".join(lines)

    async def robots_analyzer(self, target):
        base = self._url(target).rstrip("/")
        url = base + "/robots.txt"
        response, error = await net.get(self.client, url, timeout=15)
        if response is None:
            return f"[!] robots.txt request failed ({error})."
        rules = []
        sitemaps = []
        for line in response.text.splitlines():
            stripped = line.strip()
            lowered = stripped.lower()
            if lowered.startswith(("disallow:", "allow:")):
                rules.append(stripped)
            elif lowered.startswith("sitemap:"):
                sitemaps.append(stripped.split(":", 1)[1].strip())
        disallowed = sum(1 for rule in rules if rule.lower().startswith("disallow:") and rule.split(":", 1)[1].strip())
        lines = [
            f"[>] Public robots.txt review: {url}",
            f"[{' +' if response.status_code == 200 else '!'}] HTTP response: {response.status_code}",
            f"[+] Rules found: {len(rules)} ({disallowed} disallow entries)",
        ]
        lines.extend(f"[+] {rule}" for rule in rules[:30])
        if sitemaps:
            lines.append(f"[+] Sitemaps declared: {', '.join(sitemaps[:5])}")
        interesting = [rule for rule in rules if re.search(r"(admin|backup|config|private|internal|\.git|db)", rule, re.I)]
        if interesting:
            lines.append("[!] Sensitive-sounding paths are listed publicly: " + ", ".join(interesting[:6]))
            self.finding(
                "robots.txt advertises sensitive paths",
                "Crawler rules point at sensitive-sounding locations; review whether these paths should be public at all: " + ", ".join(interesting[:6]),
                "LOW", "exposure", tags=["robots", "information-disclosure"],
            )
        lines.append("[!] robots.txt is a crawler preference, not access control.")
        return "\n".join(lines)

    async def sitemap_analyzer(self, target):
        base = self._url(target).rstrip("/")
        url = base + "/sitemap.xml"
        response, error = await net.get(self.client, url, timeout=15)
        if response is None:
            return f"[!] sitemap.xml request failed ({error})."
        locations = re.findall(r"<loc>\s*(.*?)\s*</loc>", response.text, re.I | re.S)
        lines = [
            f"[>] Public sitemap review: {url}",
            f"[{' +' if response.status_code == 200 else '!'}] HTTP response: {response.status_code}",
            f"[+] URLs listed: {len(locations)}",
        ]
        lines.extend(f"[+] {location[:160]}" for location in locations[:30])
        if len(locations) > 30:
            lines.append(f"[!] {len(locations) - 30} more URLs not shown")
        lines.append("[+] Sitemaps show what a site advertises to search engines.")
        return "\n".join(lines)

    async def cookie_audit(self, target):
        url = self._url(target)
        response, error = await net.get(self.client, url, timeout=15)
        if response is None:
            return f"[!] Cookie review failed: {error}."
        cookies = response.headers.get_list("set-cookie")
        lines = [f"[>] Cookie flag review for {url} ({len(cookies)} cookie(s) observed)"]
        if not cookies:
            lines.append("[+] No Set-Cookie header was returned by this response.")
        for cookie in cookies:
            name = cookie.split("=", 1)[0].strip()
            lowered = cookie.lower()
            secure = "secure" in lowered.split(";")[1:] or "; secure" in lowered
            httponly = "; httponly" in lowered
            same_site = "samesite=strict" if "samesite=strict" in lowered else "samesite=lax" if "samesite=lax" in lowered else "samesite=none" if "samesite=none" in lowered else "unset"
            host_prefix = name.startswith("__Host-")
            lines.append(
                f"[{'+' if secure and httponly else '-'}] {name}: Secure={'yes' if secure else 'no'}, "
                f"HttpOnly={'yes' if httponly else 'no'}, SameSite={same_site}"
                + (", __Host- prefix" if host_prefix else "")
            )
            if not (secure and httponly) or same_site == "unset":
                self.finding(
                    f"Cookie '{name}' is missing security flags",
                    f"{url} set cookie '{name}' with Secure={'yes' if secure else 'no'}, HttpOnly={'yes' if httponly else 'no'}, SameSite={same_site}.",
                    "MEDIUM" if not httponly else "LOW", "web-security", tags=["cookies", name[:40]],
                )
        lines.append("[!] Flags are judged from this response only; session cookies may be set elsewhere.")
        return "\n".join(lines)

    async def uptime_check(self, target):
        url = self._url(target)
        started = asyncio.get_running_loop().time()
        response, error = await net.get(self.client, url, timeout=20)
        elapsed = round((asyncio.get_running_loop().time() - started) * 1000)
        if response is None:
            self.finding("Website did not respond", f"{url} failed a single availability request ({error}).", "MEDIUM", "availability", tags=["uptime"])
            return f"[-] {url} did not respond ({error}).\n[!] One failed request is not proof of an outage."
        headers = self._header_flags(response)
        lines = [
            f"[+] {url} responded with HTTP {response.status_code} in {elapsed} ms",
            f"[+] Final URL: {str(response.url)}",
            f"[+] Server: {headers.get('server', 'not disclosed')}",
            f"[+] Response size: {len(response.content or b'')} bytes",
            "[!] One request is a snapshot, not continuous uptime monitoring.",
        ]
        if elapsed > 3000:
            self.finding("Slow initial response", f"{url} took {elapsed} ms for a single GET.", "LOW", "performance", tags=["latency"])
        return "\n".join(lines)

    async def certificate_expiry(self, target):
        url = self._url(target)
        host = net.host_of(url)
        info = await asyncio.to_thread(net.tls_info, host)
        if info.get("error"):
            return f"[!] Could not read the certificate for {host} ({info['error']})."
        days = info["days_left"]
        lines = [
            f"[>] Certificate expiry review for {host}",
            f"[+] Expires: {info['expires_at'] or 'not readable'}",
            f"[{'+' if days is not None and days > 30 else '-'}] Days remaining: {days if days is not None else 'unknown'}",
            f"[+] Issuer: {info['issuer'] or 'not published'}",
            f"[+] Names: {', '.join(info['alt_names'][:8]) or 'none published'}",
        ]
        if days is not None and days <= 30:
            self.finding(
                "TLS certificate expires within 30 days",
                f"{host} certificate expires {info['expires_at']} ({days} days). Renew or automate rotation.",
                "MEDIUM" if days > 7 else "HIGH", "availability", tags=["tls", "certificate"],
            )
        lines.append("[!] Renewal automation and alerts prevent avoidable HTTPS outages.")
        return "\n".join(lines)

    async def origin_review(self, target):
        url = self._url(target)
        host = net.host_of(url)
        response, error = await net.get(self.client, url, timeout=15)
        lines = [f"[>] Passive origin review for {host}"]
        if response is None:
            lines.append(f"[!] Website request failed ({error}); CDN signals could not be read.")
        else:
            headers = self._header_flags(response)
            edge = {
                "cf-ray": "Cloudflare", "x-amz-cf-id": "Amazon CloudFront",
                "x-sucuri-id": "Sucuri", "akamai-grn": "Akamai", "x-fastly-request-id": "Fastly",
            }
            detected = next((name for header, name in edge.items() if header in headers), "")
            lines.append(f"[{'+' if detected else '!'}] Edge/CDN: {detected or 'not identifiable from response headers'}")
            addresses = net.resolve_addresses(host)
            for address in addresses[:3]:
                context = await net.ip_context(self.client, address)
                org = str(context.get("org") or context.get("isp") or "")
                lines.append(f"[+] {address}: {org or 'ownership not published'} ({context.get('country', 'unknown')})")
                if detected and org and not any(token in org.lower() for token in ("cloudflare", "akamai", "fastly", "amazon", "microsoft", "google", "sucuri")):
                    lines.append(f"[!] The edge vendor is {detected} but DNS resolves to {org}; that can expose the origin directly.")
                    self.finding(
                        "Origin may be directly exposed",
                        f"{host} uses {detected} but resolves to {address} owned by {org}.",
                        "MEDIUM", "exposure", tags=["cdn", "origin"],
                    )
            if not addresses:
                lines.append("[!] No A/AAAA records resolved.")
        lines.append("[!] Origin privacy cannot be proven from a public response; confirm in the CDN and DNS dashboards.")
        return "\n".join(lines)

    async def cloud_service_map(self, target):
        domain = net.normalize_domain(str(target))
        if not domain:
            return "[!] Enter a domain such as example.com"
        lines = [f"[>] Public cloud-service clues for {domain}"]
        cname = net.dns_lookup(domain, "CNAME").get("values", [])
        if cname:
            lines.append(f"[+] CNAME: {' -> '.join(cname[:3])}")
        response, error = await net.get(self.client, f"https://{domain}", timeout=15)
        provider = ""
        if response is not None:
            headers = self._header_flags(response)
            server = headers.get("server", "")
            hints = {"cloudflare": "Cloudflare", "cloudfront": "AWS CloudFront", "sucuri": "Sucuri", "akamai": "Akamai", "gws": "Google", "azure": "Microsoft Azure"}
            provider = next((name for token, name in hints.items() if token in server.lower()), "")
            if not provider and any(header in headers for header in ("cf-ray", "x-amz-cf-id", "x-azure-ref", "x-goog-generation")):
                provider = "edge provider confirmed by response headers"
            lines.append(f"[{'+' if provider else '!'}] Header/CDN clue: {provider or 'none observed'}")
        else:
            lines.append(f"[!] Website request failed ({error}); header clues unavailable.")
        addresses = net.resolve_addresses(domain)
        for address in addresses[:2]:
            context = await net.ip_context(self.client, address)
            lines.append(f"[+] {address}: {context.get('org') or context.get('isp') or 'ownership not published'}")
            if context.get("asn"):
                self.node(f"AS{str(context['asn']).removeprefix('AS')}", "asn", {"org": context.get("org")})
        lines.append("[+] DNS, TLS and header clues only; cloud ownership still needs inventory confirmation.")
        return "\n".join(lines)

    # ------------------------------------------------------------ dns / mail

    async def email_domain_info(self, target):
        _local, domain = net.split_target(str(target))
        if not domain:
            return "[!] Enter an email address or domain."
        return await self._delegate(domain, "records")

    async def spf_check(self, target):
        _local, domain = net.split_target(str(target))
        if not domain:
            return "[!] Enter a domain such as example.com"
        return await self._delegate(domain, "spf_check")

    async def dmarc_check(self, target):
        _local, domain = net.split_target(str(target))
        if not domain:
            return "[!] Enter a domain such as example.com"
        return await self._delegate(domain, "dmarc_check")

    async def dnssec_check(self, target):
        domain = net.normalize_domain(str(target))
        if not domain:
            return "[!] Enter a domain such as example.com"
        return await self._delegate(domain, "dnssec_check")

    async def ip_info(self, target):
        host = net.host_of(str(target)) or str(target).strip()
        if not host:
            return "[!] Enter a hostname or IP address."
        addresses = [host] if net.is_ip(host) else net.resolve_addresses(host)
        if not addresses:
            return f"[-] Could not resolve {host}."
        lines = [f"[>] IP information for {host}"]
        for address in addresses[:5]:
            ptr = net.reverse_dns(address)
            context = await net.ip_context(self.client, address)
            lines.append(f"[+] {address}" + (f" (PTR {ptr})" if ptr else ""))
            if not context.get("error"):
                lines.append(
                    f"    ASN: {context.get('asn') or 'n/a'} | Org: {context.get('org') or 'n/a'} | "
                    f"Location: {context.get('city') or '?'}, {context.get('country') or '?'}"
                )
            self.node(address, "ip", {"org": context.get("org")})
            if net.is_ip(host):
                self.node(host, "ip")
        lines.append("[!] Geolocation and ownership data are approximate.")
        return "\n".join(lines)

    async def reverse_dns(self, target):
        value = net.host_of(str(target)) or str(target).strip()
        return await self._delegate(value, "reverse_dns")

    async def whois_lookup(self, target):
        domain = net.normalize_domain(str(target))
        if not domain or "." not in domain:
            return "[!] Enter a domain such as example.com; URLs and paths are accepted too."
        candidates = [domain]
        parent = self._registrable_parent(domain)
        if parent and parent != domain:
            candidates.append(parent)

        errors = []
        for candidate in candidates:
            payload, error = await net.rdap_domain(self.client, candidate)
            if payload:
                nameservers = [item.get("ldhName") for item in payload.get("nameservers", []) if item.get("ldhName")]
                events = {event.get("eventAction"): event.get("eventDate") for event in payload.get("events", [])}
                lines = [
                    f"[>] Public WHOIS/RDAP lookup for {candidate}",
                    f"[+] Handle: {payload.get('handle', 'not published')}",
                    f"[+] Status: {', '.join(payload.get('status', [])) or 'not published'}",
                ]
                if candidate != domain:
                    lines.insert(1, f"[!] {domain} is a hosted name; registration data is shown for parent domain {candidate}.")
                lines.extend([
                    f"[+] Registered: {events.get('registration', 'not published')}",
                    f"[+] Updated: {events.get('last changed', 'not published')}",
                    f"[+] Expires: {events.get('expiration', 'not published')}",
                    f"[+] Entities: {', '.join(net.rdap_entities(payload)) or 'not published'}",
                    f"[+] Nameservers: {', '.join(nameservers[:8]) or 'not published'}",
                ])
                self.node(candidate, "domain", {"registrar": ", ".join(net.rdap_entities(payload))[:120]})
                for nameserver in nameservers[:6]:
                    self.node(nameserver.rstrip("."), "host", {"role": "nameserver"})
                    self.edge(candidate, nameserver.rstrip("."), "uses", "domain", "host")
                expiry = events.get("expiration", "")
                lines.append("[!] Privacy services and registry policies may hide registrant details.")
                if expiry:
                    lines.append(f"[+] Expiry reference: {expiry}")
                return "\n".join(lines)
            errors.append(f"{candidate}: {error}")

        return "\n".join([
            f"[!] No registration record could be retrieved for {domain} ({'; '.join(errors)}).",
            "[>] Public web lookup fallback:",
            f"[+] https://www.whois.com/whois/{parent or domain}",
            f"[+] https://lookup.icann.org/en/lookup/{parent or domain}",
            "[!] Hosted subdomains usually do not have their own WHOIS record; check the parent domain.",
        ])

    @staticmethod
    def _registrable_parent(domain: str) -> str:
        labels = [label for label in domain.split(".") if label]
        if len(labels) <= 2:
            return domain
        if len(labels[-1]) == 2 and labels[-2] in {"co", "com", "net", "org", "gov", "ac"}:
            return ".".join(labels[-3:])
        return ".".join(labels[-2:])

    async def subdomain_enum(self, target):
        domain = net.normalize_domain(str(target))
        if not domain:
            return "[!] Enter a domain such as example.com"
        entries, error = await net.crt_entries(self.client, domain)
        if error:
            return f"[!] Certificate-transparency lookup failed ({error}). Try again shortly."
        names = net.crt_names(entries, domain)
        lines = [
            f"[>] Passive certificate-transparency enumeration for {domain}",
            f"[+] Log entries: {len(entries)}",
            f"[+] Unique names found: {len(names)}",
        ]
        lines.extend(f"[+] {name}" for name in names[:200])
        if len(names) > 200:
            lines.append(f"[!] {len(names) - 200} more names not shown")
        for name in names:
            self.node(name, "subdomain" if name != domain else "domain")
            if name != domain:
                self.edge(domain, name, "contains", "domain", "subdomain")
        self.finding(
            f"Certificate logs expose {len(names)} public names for {domain}",
            "Review these hostnames against live inventory; forgotten names are common exposure.",
            "INFO", "asset-inventory", tags=["ct", "subdomain"],
        )
        lines.append("[!] Names may be expired or unrelated; verify ownership and liveness.")
        return "\n".join(lines)

    async def certificate_history(self, target):
        domain = net.normalize_domain(str(target))
        if not domain:
            return "[!] Enter a domain such as example.com"
        entries, error = await net.crt_entries(self.client, domain)
        if error:
            return f"[!] Certificate-transparency lookup failed ({error})."
        by_name: dict[str, tuple[str, str]] = {}
        for item in entries:
            name = str(item.get("common_name") or item.get("name_value", "")).splitlines()[0].strip().lower()
            if not name or (name != domain and not name.endswith("." + domain)):
                continue
            first, last = str(item.get("not_before", "")), str(item.get("not_after", ""))
            previous = by_name.get(name)
            by_name[name] = (
                min(first, previous[0]) if previous and previous[0] else first,
                max(last, previous[1]) if previous and previous[1] else last,
            )
        lines = [
            f"[>] Certificate history for {domain}",
            f"[+] Log entries reviewed: {len(entries)}",
            f"[+] Names with dated certificates: {len(by_name)}",
        ]
        for name in sorted(by_name)[:60]:
            first, last = by_name[name]
            lines.append(f"[+] {name}: {first[:10]} -> {last[:10]}")
        if len(by_name) > 60:
            lines.append(f"[!] {len(by_name) - 60} more names not shown")
        lines.append("[!] Logs are public, incomplete, and may include certificates no longer valid.")
        return "\n".join(lines)

    async def certificate_search(self, target):
        return await self._delegate(str(target), "certificate_search")

    async def asn_details(self, target):
        value = net.host_of(str(target)) or str(target).strip()
        addresses = [value] if net.is_ip(value) else net.resolve_addresses(value)
        if not addresses:
            return f"[!] Could not resolve {value or 'the supplied target'}."
        lines = [f"[>] Public network ownership for {value}"]
        for address in addresses[:3]:
            context = await net.ip_context(self.client, address)
            if context.get("error"):
                lines.append(f"[!] {address}: ownership lookup failed ({context['error']})")
                continue
            lines.append(f"[+] Address: {address}")
            lines.append(f"[+] ASN: {context.get('asn') or 'not published'}")
            lines.append(f"[+] Organization: {context.get('org') or 'not published'}")
            lines.append(f"[+] ISP: {context.get('isp') or 'not published'}")
            lines.append(f"[+] Location: {context.get('city') or '?'}, {context.get('country') or '?'}")
            self.node(address, "ip")
            if context.get("org"):
                self.node(context["org"], "organization")
                self.edge(address, context["org"], "belongs_to", "ip", "organization")
        lines.append("[!] Ownership and geolocation data may be approximate.")
        return "\n".join(lines)

    async def network_range(self, target):
        return await self._delegate(str(target), "asn_map")

    async def web_info(self, target):
        return await self._delegate(str(target), "web_info")

    async def infra_map(self, target):
        return await self._delegate(str(target), "infrastructure_map")

    async def company_profile(self, target):
        domain = net.normalize_domain(str(target))
        if not domain:
            return "[!] Enter a company domain such as example.com"
        payload, error = await net.rdap_domain(self.client, domain)
        lines = [f"[>] Company/domain public profile for {domain}"]
        if payload:
            entities = net.rdap_entities(payload)
            events = {event.get("eventAction"): event.get("eventDate") for event in payload.get("events", [])}
            lines.append(f"[+] Registration entities: {', '.join(entities) or 'not published'}")
            lines.append(f"[+] Registered: {events.get('registration', 'not published')}")
            self.node(domain, "domain", {"entities": ", ".join(entities)[:160]})
            for entity in entities[:4]:
                self.node(entity, "organization")
                self.edge(domain, entity, "belongs_to", "domain", "organization")
        else:
            lines.append(f"[!] Registration data unavailable ({error}).")
        addresses = net.resolve_addresses(domain)
        for address in addresses[:2]:
            context = await net.ip_context(self.client, address)
            lines.append(f"[+] Hosting: {address} — {context.get('org') or context.get('isp') or 'ownership not published'}")
        lines.append("[+] Starting point for vendor and product research; verify with primary sources.")
        return "\n".join(lines)

    # ---------------------------------------------------------- web research

    async def tech_detect(self, target):
        url = self._url(target)
        response, error = await net.get(self.client, url, timeout=15)
        if response is None:
            return f"[!] Technology detection failed ({error}). Check the URL and network access."
        signals = net.fingerprint(response.text, response.headers)
        meta = net.page_metadata(response.text)
        lines = [
            f"[>] Passive technology detection for {url}",
            f"[+] HTTP response: {response.status_code}",
            f"[+] Signals detected: {len(signals)}",
        ]
        lines.extend(f"[+] {name} — {evidence}" for name, evidence in signals)
        if not signals:
            lines.append("[!] No confident signal was detected; the site may be behind a proxy or use custom headers.")
        if meta["generator"]:
            lines.append(f"[+] Meta generator: {meta['generator']}")
        host = net.host_of(url)
        self.node(host, "domain")
        for name, evidence in signals:
            self.node(name, "technology", {"evidence": evidence})
            self.edge(host, name, "uses", "domain", "technology")
        lines.append("[!] Fingerprinting is heuristic and may be hidden or spoofed.")
        return "\n".join(lines)

    async def article_summary(self, target):
        url = self._url(target)
        response, error = await net.get(self.client, url, timeout=20)
        if response is None:
            return f"[!] Could not retrieve {url} ({error})."
        meta = net.page_metadata(response.text)
        text = net.strip_html(response.text)
        lines = [
            f"[>] Content review for {url}",
            f"[+] HTTP response: {response.status_code}",
            f"[+] Title: {meta['title'] or 'not published'}",
        ]
        if meta["description"]:
            lines.append(f"[+] Description: {meta['description']}")
        lines.extend([
            f"[+] Extracted words: {len(text.split())}",
            f"[+] Extracted preview: {text[:600] or 'no readable text'}",
            "[!] This is extraction, not independent fact verification.",
        ])
        self.node(net.host_of(url) or url, "domain")
        return "\n".join(lines)

    async def public_links(self, target):
        url = self._url(target)
        response, error = await net.get(self.client, url, timeout=20)
        if response is None:
            return f"[!] Could not retrieve {url} ({error})."
        links = []
        for match in re.findall(r"href=[\"']([^\"'#]+)", response.text, re.I):
            absolute = urljoin(url, html.unescape(match.strip()))
            if absolute.startswith(("http://", "https://")):
                links.append(absolute)
        internal = sorted({link for link in links if net.host_of(link) == net.host_of(url)})
        external = sorted({link for link in links if net.host_of(link) != net.host_of(url)})
        lines = [
            f"[>] Public links from {url}",
            f"[+] Links found: {len(links)} ({len(internal)} internal, {len(external)} external)",
        ]
        lines.extend(f"[+] internal: {link}" for link in internal[:40])
        lines.extend(f"[+] external: {link}" for link in external[:40])
        for host in sorted({net.host_of(link) for link in external if net.host_of(link)})[:10]:
            self.node(host, "domain")
            self.edge(net.host_of(url) or url, host, "related_to", "domain", "domain")
        return "\n".join(lines)

    async def article_search(self, target):
        query = str(target or "").strip()
        if not query:
            return "[!] Enter a search phrase, event, or topic."
        url = "https://news.google.com/rss/search"
        response, error = await net.get(
            self.client, url, timeout=20,
            params={"q": query, "hl": "en-US", "gl": "US", "ceid": "US:en"},
            headers={"Accept": "application/rss+xml, application/xml"},
        )
        if response is None:
            return f"[!] News search failed ({error})."
        items = re.findall(r"<item>(.*?)</item>", response.text, re.S | re.I)
        lines = [f"[>] Public news search for: {query}", f"[+] Sources returned: {len(items)}"]
        for item in items[:15]:
            title = re.search(r"<title>(?:<!\[CDATA\[)?(.*?)(?:\]\]>)?</title>", item, re.S)
            link = re.search(r"<link>(.*?)</link>", item, re.S)
            published = re.search(r"<pubDate>(.*?)</pubDate>", item, re.S)
            lines.append(
                f"[+] {(title.group(1).strip() if title else 'untitled')[:140]}"
                + (f" | {published.group(1).strip()}" if published else "")
            )
            if link:
                lines.append(f"    {link.group(1).strip()}")
        lines.append("[!] Aggregated public headlines; open and verify the original sources before citing.")
        return "\n".join(lines)

    async def place_search(self, target):
        query = str(target or "").strip()
        if not query:
            return "[!] Enter a place name or landmark."
        key = self.config.provider_key("geocoding") if self.config is not None else ""
        if key:
            response, error = await net.get(
                self.client, "https://api.opencagedata.com/geocode/v1/json",
                timeout=20, params={"q": query, "key": key, "limit": 5, "no_annotations": 1},
            )
            if response is not None and response.status_code == 200:
                results = response.json().get("results", [])
                lines = [f"[>] Place search (OpenCage) for: {query}", f"[+] Matches: {len(results)}"]
                for result in results[:5]:
                    geometry = result.get("geometry", {})
                    lines.append(f"[+] {result.get('formatted', 'unknown')} ({geometry.get('lat')}, {geometry.get('lng')})")
                    self.node(f"{geometry.get('lat')},{geometry.get('lng')}", "host", {"label": result.get("formatted", "")})
                return "\n".join(lines)
        response, error = await net.get(
            self.client, "https://nominatim.openstreetmap.org/search",
            timeout=25, params={"q": query, "format": "jsonv2", "limit": 5},
        )
        if response is None or response.status_code != 200:
            return f"[!] Place search failed ({(error or 'HTTP ' + str(getattr(response, 'status_code', '?')))})."
        results = response.json() or []
        lines = [f"[>] Place search (OpenStreetMap) for: {query}", f"[+] Matches: {len(results)}"]
        for result in results[:5]:
            lines.append(
                f"[+] {result.get('display_name', 'unknown')} ({result.get('lat')}, {result.get('lon')}) "
                f"[{result.get('type', 'place')}]"
            )
        lines.append("[!] Public gazetteer data; coordinates are approximate and not a person-tracking service.")
        return "\n".join(lines)

    async def coordinate_info(self, target):
        text = str(target or "").strip()
        try:
            latitude, longitude = (float(part.strip()) for part in re.split(r"[,\s]+", text)[:2])
        except (ValueError, IndexError):
            return "[!] Use coordinates in the form: latitude, longitude (for example 40.7128, -74.0060)"
        if not (-90 <= latitude <= 90 and -180 <= longitude <= 180):
            return "[!] Latitude must be -90..90 and longitude -180..180."
        lines = [f"[+] Coordinates accepted: latitude={latitude}, longitude={longitude}"]
        response, error = await net.get(
            self.client, "https://nominatim.openstreetmap.org/reverse",
            timeout=25, params={"lat": latitude, "lon": longitude, "format": "jsonv2"},
        )
        if response is not None and response.status_code == 200:
            payload = response.json() or {}
            lines.append(f"[+] Nearest public place: {payload.get('display_name', 'not published')}")
        else:
            lines.append(f"[!] Reverse geocoding unavailable ({error or 'no response'}).")
        lines.append("[!] Public map data only; no real-time tracking or private-address discovery.")
        return "\n".join(lines)

    async def brand_monitor(self, target):
        domain = net.normalize_domain(str(target))
        if not domain or "." not in domain:
            return "[!] Enter a brand domain such as example.com"
        brand = domain.split(".")[0]
        suffixes = ("com", "net", "org", "io", "co", "app", "dev", "shop", "xyz", "site", "online", "info")
        variants = {f"{brand}-{word}" for word in ("login", "secure", "support", "verify", "account", "billing", "help", "official")}
        variants |= {f"{brand}{suffix}" for suffix in suffixes}
        variants |= {f"{brand.replace('-', '')}.{domain.rsplit('.', 1)[-1]}", f"{brand}s.com"}
        variants.discard(domain)

        async def check(name: str):
            return name, await asyncio.to_thread(net.resolve_addresses, name)

        results = await net.gather_limited((check(name) for name in sorted(variants)[:30]), limit=10)
        live = {}
        for result in results:
            if isinstance(result, Exception):
                continue
            name, addresses = result
            if addresses:
                live[name] = addresses
        lines = [
            f"[>] Lookalike-domain review for {brand} ({domain})",
            f"[+] Variants checked: {min(len(variants), 30)}",
            f"[!] Resolving variants: {len(live)}",
        ]
        for name in sorted(live):
            lines.append(f"[-] {name}: {', '.join(live[name][:2])}")
            self.node(name, "domain", {"relation": "lookalike-candidate"})
            self.edge(domain, name, "related_to", "domain", "domain")
        if live:
            self.finding(
                "Lookalike domains resolve publicly",
                "These brand-similar domains resolve: " + ", ".join(sorted(live)[:10]) + ". Verify whether any are yours or malicious.",
                "MEDIUM", "brand", tags=["typosquatting", "phishing"],
            )
        lines.append("[!] DNS resolution alone does not prove ownership or intent; confirm before acting.")
        return "\n".join(lines)

    async def email_discovery(self, target):
        base = self._url(target).rstrip("/")
        pages = [base, base + "/contact", base + "/about"]
        found: set[str] = set()
        fetched = 0
        for page in pages:
            response, _error = await net.get(self.client, page, timeout=15)
            if response is None:
                continue
            fetched += 1
            found |= set(re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", response.text))
            found |= set(re.findall(r"mailto:([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})", response.text, re.I))
        domain = net.normalize_domain(base)
        found = {value.lower().rstrip(".") for value in found if not value.lower().endswith((".png", ".jpg", ".gif", ".png"))}
        relevant = sorted(value for value in found if domain and value.endswith("@" + domain))
        lines = [
            f"[>] Public email clues from {base}",
            f"[+] Pages checked: {fetched}",
            f"[+] Addresses on the target domain: {len(relevant)}",
        ]
        lines.extend(f"[+] {value}" for value in relevant[:50])
        other = sorted(found - set(relevant))
        if other:
            lines.append(f"[+] Third-party addresses seen: {len(other)}")
        for value in relevant[:20]:
            self.node(value, "email")
            if domain:
                self.edge(domain, value, "related_to", "domain", "email")
        lines.append("[!] One site only; do not use this for bulk harvesting or spam.")
        return "\n".join(lines)

    async def threat_feed_check(self, target):
        value = str(target or "").strip()
        if not value:
            return "[!] Enter a public URL, hostname, or IP address."
        lines = [f"[>] Threat-intelligence context for {value}"]
        if value.startswith(("http://", "https://")):
            try:
                response = await self.client.post(
                    "https://urlhaus-api.abuse.ch/v1/url/", data={"url": value},
                    headers={"User-Agent": net.USER_AGENT}, timeout=20,
                )
                payload = response.json() if response.status_code == 200 else {}
            except Exception as error:
                payload = {}
                lines.append(f"[!] URLhaus lookup failed ({type(error).__name__}).")
            status = str(payload.get("query_status", ""))
            if status == "no_results":
                lines.append("[+] URLhaus: no matching malware URL report.")
            elif payload.get("threat") or status == "ok":
                lines.append(f"[-] URLhaus: matching report found (threat={payload.get('threat', 'unknown')}, tags={payload.get('tags', 'n/a')})")
                self.finding(
                    "URL appears in a malware URL feed",
                    f"URLhaus returned a matching report for {value}. Validate with the feed before acting.",
                    "HIGH", "threat-intel", tags=["urlhaus", "malware"],
                )
            elif status:
                lines.append(f"[!] URLhaus returned: {status}")
            host = net.host_of(value)
        else:
            host = net.host_of(value) or value

        addresses = [host] if net.is_ip(host) else net.resolve_addresses(host)
        for address in addresses[:3]:
            context = await net.ip_context(self.client, address)
            lines.append(f"[+] {address}: ASN {context.get('asn') or 'n/a'} | {context.get('org') or 'ownership not published'} | {context.get('country') or '?'}")
            self.node(address, "ip", {"org": context.get("org")})
        if not addresses:
            lines.append("[!] The target did not resolve; no IP reputation could be requested.")
        lines.append("[!] A clean feed result is not proof of safety. AbuseIPDB is not queried without a key.")
        return "\n".join(lines)

    async def storage_review(self, target):
        domain = net.normalize_domain(str(target)) or net.host_of(str(target))
        if not domain:
            return "[!] Enter a domain or organization name."
        brand = domain.split(".")[0]
        names = list(dict.fromkeys([brand, brand.replace("-", ""), domain.replace(".", "-"), f"{brand}-backup", f"{brand}-assets"]))[:4]
        lines = [
            f"[>] Public storage review for {domain}",
            f"[>] Probing {len(names)} conventional bucket names across S3, GCS and Azure (read-only, no listing download).",
        ]
        exposed = 0
        for name in names:
            probes = await asyncio.gather(*(net.probe_bucket(self.client, provider, name) for provider in ("s3", "gcs", "azure")))
            for probe in probes:
                if not isinstance(probe, dict):
                    continue
                state = probe.get("state")
                if state in {"absent", "error"}:
                    continue
                label = f"{probe.get('provider')}:{name}"
                if state == "public":
                    exposed += 1
                    lines.append(f"[-] {label}: PUBLIC listing at {probe.get('url')}")
                    self.node(probe.get("url", label), "url", {"bucket": name})
                    self.finding(
                        f"Publicly listable bucket: {label}",
                        f"{probe.get('url')} returned a public object listing.",
                        "HIGH", "exposure", tags=["cloud-storage", probe.get("provider", "")],
                    )
                elif state == "exists-private":
                    lines.append(f"[+] {label}: exists, listing denied (private)")
                else:
                    lines.append(f"[!] {label}: inconclusive (HTTP {probe.get('status')})")
        if not exposed:
            lines.append("[+] No publicly listable bucket was confirmed for these names.")
        lines.append("[!] Only conventional names were tested; only audit storage you own or are authorized to review.")
        return "\n".join(lines)

    # ----------------------------------------------------------- local files

    async def image_metadata(self, target):
        path = self._path(target)
        if not path.is_file():
            return f"[!] Image file not found: {path}"
        stat = path.stat()
        digest = await asyncio.to_thread(self._sha256, path)
        lines = [
            f"[>] Image metadata for {path.name}",
            f"[+] Size: {stat.st_size:,} bytes",
            f"[+] SHA-256: {digest}",
        ]
        try:
            from PIL import Image
            from PIL.ExifTags import TAGS, GPSTAGS
        except ImportError:
            lines.append("[!] Pillow is not installed, so EXIF metadata was not read (no bytes were uploaded).")
            lines.append("[>] Install it with: pip install pillow")
            return "\n".join(lines)

        def inspect() -> dict:
            with Image.open(path) as image:
                details = {"format": image.format, "size": image.size, "mode": image.mode, "tags": {}}
                exif = image.getexif()
                for tag_id, value in exif.items():
                    name = TAGS.get(tag_id, str(tag_id))
                    if name in {"GPSInfo", "ExifOffset", "MakerNote"}:
                        continue
                    text = str(value)
                    details["tags"][name] = text[:120]
                try:
                    gps = exif.get_ifd(0x8825)
                    if gps:
                        details["tags"]["GPS"] = ", ".join(
                            f"{GPSTAGS.get(key, key)}={value}" for key, value in list(gps.items())[:6]
                        )[:200]
                except Exception:
                    pass
                return details

        try:
            details = await asyncio.to_thread(inspect)
        except Exception as error:
            lines.append(f"[!] The image could not be parsed ({type(error).__name__}).")
            return "\n".join(lines)

        lines.append(f"[+] Format: {details['format']} {details['size'][0]}x{details['size'][1]} ({details['mode']})")
        lines.extend(f"[+] {name}: {value}" for name, value in details["tags"].items())
        if not details["tags"]:
            lines.append("[+] No EXIF tags were present in this file.")
        sensitive = {"GPS", "Make", "Model", "Software", "DateTime", "DateTimeOriginal", "Artist", "Copyright"}
        flagged = sorted(set(details["tags"]) & sensitive)
        if flagged:
            self.finding(
                "Image metadata exposes device or location details",
                f"{path.name} contains: {', '.join(flagged)}. Strip it before publishing the file.",
                "MEDIUM" if "GPS" in flagged else "LOW", "privacy", tags=["metadata", "exif"],
            )
        lines.append("[!] The file was read locally and never uploaded.")
        return "\n".join(lines)

    async def document_metadata(self, target):
        path = self._path(target)
        if not path.is_file():
            return f"[!] Document not found: {path}"
        stat = path.stat()
        digest = await asyncio.to_thread(self._sha256, path)
        lines = [
            f"[>] Document metadata for {path.name}",
            f"[+] Size: {stat.st_size:,} bytes",
            f"[+] SHA-256: {digest}",
        ]
        suffix = path.suffix.lower()
        metadata: dict[str, str] = {}
        if suffix in {".docx", ".xlsx", ".pptx"}:
            metadata = await asyncio.to_thread(self._ooxml_metadata, path)
        elif suffix == ".pdf":
            metadata = await asyncio.to_thread(self._pdf_metadata, path)
        elif suffix in {".jpg", ".jpeg", ".png"}:
            return await self.image_metadata(target)
        if metadata:
            lines.extend(f"[+] {key}: {value}" for key, value in metadata.items())
            author = metadata.get("creator") or metadata.get("author") or metadata.get("creator_tool")
            if author:
                self.finding(
                    "Document metadata includes authoring details",
                    f"{path.name} records: {', '.join(f'{k}={v}' for k, v in metadata.items() if k in {'creator', 'author', 'lastModifiedBy', 'company'})}. Review before sharing.",
                    "LOW", "privacy", tags=["metadata", "document"],
                )
        else:
            lines.append("[!] No embedded document metadata was readable for this format.")
            lines.append("[>] Supported: PDF, DOCX, XLSX, PPTX, JPEG/PNG.")
        lines.append("[!] Local-only review; the file was never uploaded.")
        return "\n".join(lines)

    @staticmethod
    def _ooxml_metadata(path: Path) -> dict[str, str]:
        metadata: dict[str, str] = {}
        try:
            with zipfile.ZipFile(path) as archive:
                for name, prefix in (("docProps/core.xml", ""), ("docProps/app.xml", "")):
                    if name not in archive.namelist():
                        continue
                    raw = archive.read(name).decode("utf-8", errors="replace")
                    for tag in ("creator", "lastModifiedBy", "title", "subject", "created", "modified", "Application", "Company"):
                        match = re.search(rf"<(?:\w+:)?{tag}>(.*?)</(?:\w+:)?{tag}>", raw, re.S | re.I)
                        if match:
                            metadata[tag.lower()] = re.sub(r"\s+", " ", match.group(1)).strip()[:160]
        except (zipfile.BadZipFile, KeyError, OSError):
            return {}
        return metadata

    @staticmethod
    def _pdf_metadata(path: Path) -> dict[str, str]:
        try:
            raw = path.read_bytes()[:400_000].decode("latin-1", errors="replace")
        except OSError:
            return {}
        metadata: dict[str, str] = {}
        for key in ("Title", "Author", "Creator", "Producer", "CreationDate", "ModDate"):
            match = re.search(rf"/{key}\s*\(([^)]*)\)", raw)
            if match:
                metadata[key.lower()] = match.group(1)[:160]
        match = re.search(r"/Count\s+(\d+)", raw)
        if match:
            metadata["pages_hint"] = match.group(1)
        return metadata

    @staticmethod
    def _sha256(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    async def file_inventory(self, target):
        path = self._path(target)
        if not path.exists():
            return f"[!] Path not found: {path}"
        files = [path] if path.is_file() else [item for item in path.rglob("*") if item.is_file()]
        if len(files) > 2000:
            files = files[:2000]
        total = sum(item.stat().st_size for item in files)
        extensions: dict[str, int] = {}
        for item in files:
            extensions[item.suffix.lower() or "(none)"] = extensions.get(item.suffix.lower() or "(none)", 0) + 1
        lines = [
            f"[>] File inventory: {path}",
            f"[+] Files: {len(files)}",
            f"[+] Total size: {total:,} bytes",
            f"[+] Types: {', '.join(f'{ext} x{count}' for ext, count in sorted(extensions.items(), key=lambda item: -item[1])[:10])}",
        ]
        for item in sorted(files, key=lambda entry: entry.stat().st_size, reverse=True)[:30]:
            lines.append(f"[+] {item.name} — {item.stat().st_size:,} bytes")
        lines.append("[!] Only inspect files you are authorized to access.")
        return "\n".join(lines)

    async def metadata_cleaner(self, target):
        path = self._path(target)
        if not path.is_file():
            return f"[!] File not found: {path}"
        try:
            from PIL import Image
        except ImportError:
            return "\n".join([
                f"[>] Metadata removal for {path.name}",
                "[!] Pillow is not installed, so a sanitized copy could not be produced.",
                "[>] Install it with: pip install pillow, then run this tool again.",
            ])
        output_dir = Path("outputs") / "sanitized"
        output_dir.mkdir(parents=True, exist_ok=True)
        destination = output_dir / f"{path.stem}_clean{path.suffix or '.png'}"

        def strip() -> tuple[bool, str]:
            with Image.open(path) as image:
                cleaned = Image.new(image.mode, image.size)
                cleaned.putdata(list(image.getdata()))
                cleaned.save(destination)
            return True, ""

        try:
            await asyncio.to_thread(strip)
        except Exception as error:
            return f"[!] A sanitized copy could not be created ({type(error).__name__}: {error})."
        return "\n".join([
            f"[>] Metadata removal for {path.name}",
            f"[+] Sanitized copy written: {destination}",
            "[+] EXIF/GPS/device tags are not carried over to the new file.",
            "[!] The original is untouched; verify the copy visually before sharing it.",
        ])

    async def ocr(self, target):
        path = self._path(target)
        if not path.is_file():
            return f"[!] Image file not found: {path}"
        try:
            import pytesseract
            from PIL import Image
        except ImportError:
            return "\n".join([
                f"[>] Local OCR for {path.name}",
                "[!] OCR dependencies are not installed, so no text was extracted.",
                "[>] Install them with: pip install pillow pytesseract",
                "[>] pytesseract also needs the Tesseract binary (https://github.com/tesseract-ocr/tesseract).",
            ])
        try:
            text = await asyncio.to_thread(lambda: pytesseract.image_to_string(Image.open(path)))
        except Exception as error:
            return f"[!] OCR failed ({type(error).__name__}). Confirm the Tesseract binary is installed and on PATH."
        cleaned = re.sub(r"\n{3,}", "\n\n", text).strip()
        return "\n".join([
            f"[>] Local OCR for {path.name}",
            f"[+] Characters extracted: {len(cleaned)}",
            f"[+] Text preview: {cleaned[:1500] or 'no readable text found'}",
            "[!] OCR makes mistakes; verify any quoted text against the image.",
        ])

    async def text_extract(self, target):
        path = self._path(target)
        if not path.is_file():
            return f"[!] File not found: {path}"
        suffix = path.suffix.lower()

        def extract() -> tuple[str, str]:
            if suffix in {".docx", ".doc"}:
                try:
                    with zipfile.ZipFile(path) as archive:
                        raw = archive.read("word/document.xml").decode("utf-8", errors="replace")
                    return net.strip_html(raw), "docx"
                except (zipfile.BadZipFile, KeyError):
                    return "", ""
            if suffix in {".html", ".htm", ".xml"}:
                return net.strip_html(path.read_text(encoding="utf-8", errors="replace")), suffix
            if suffix == ".pdf":
                raw = path.read_bytes()[:2_000_000].decode("latin-1", errors="replace")
                chunks = re.findall(r"\(([^()]{2,})\)", raw)
                return " ".join(chunks)[:200_000], "pdf"
            return path.read_text(encoding="utf-8", errors="replace"), suffix

        text, kind = await asyncio.to_thread(extract)
        text = re.sub(r"[ \t]+", " ", text).strip()
        if not text:
            return "\n".join([
                f"[>] Text extraction for {path.name}",
                "[!] No readable text could be extracted from this file.",
                "[>] Supported: .txt .md .csv .json .html .xml .docx and basic PDF text streams.",
            ])
        lines = [
            f"[>] Text extraction for {path.name} ({kind})",
            f"[+] Words: {len(text.split())}",
            f"[+] Characters: {len(text)}",
            "",
            text[:4000],
        ]
        if len(text) > 4000:
            lines.append(f"[!] Preview truncated; {len(text) - 4000} characters remain in the file.")
        lines.append("[!] Local-only extraction; the file was never uploaded.")
        return "\n".join(lines)

    async def secret_scan(self, target):
        """Scan one file, or walk a folder and aggregate per-file hits."""
        path = self._path(target)
        if path.is_file():
            return await self._secret_scan_file(target)
        if not path.is_dir():
            return f"[!] Local file or folder not found: {path}"

        files = await asyncio.to_thread(self._scan_candidates, path)
        if not files:
            return f"[!] No readable text files were found under {path}."

        per_file: list[tuple[Path, list[tuple[int, str, str]]]] = []
        total_lines = 0
        for item in files:
            try:
                content = item.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            total_lines += len(content.splitlines())
            hits: list[tuple[int, str, str]] = []
            for number, line in enumerate(content.splitlines(), 1):
                for label, pattern, severity in SECRET_PATTERNS:
                    if pattern.search(line):
                        hits.append((number, label, severity))
                        break
            if hits:
                per_file.append((item, hits))

        flat = [hit for _item, hits in per_file for hit in hits]
        lines = [
            f"[>] Redacted secret-pattern review: {path} ({len(files)} file(s))",
            f"[+] Lines scanned: {total_lines:,}",
            f"[{'!' if flat else '+'}] Candidate findings: {len(flat)}",
        ]
        for item, hits in per_file[:12]:
            try:
                label = str(item.relative_to(path))
            except ValueError:
                label = item.name
            flagged = any(severity in {"HIGH", "CRITICAL"} for _, _, severity in hits)
            lines.append(f"[{'-' if flagged else '!'}] {label}: {len(hits)} candidate(s)")
            for number, kind, severity in hits[:4]:
                lines.append(f"    [{'-' if severity in {'HIGH', 'CRITICAL'} else '!'}] line {number}: {kind} ({severity})")
        if len(per_file) > 12:
            lines.append(f"[!] {len(per_file) - 12} more files with candidates not shown")
        if flat:
            worst = "CRITICAL" if any(sev == "CRITICAL" for _, _, sev in flat) else "HIGH" if any(sev == "HIGH" for _, _, sev in flat) else "MEDIUM"
            self.finding(
                f"Secret-shaped content under {path.name}",
                f"{len(flat)} candidate secret(s) across {len(per_file)} file(s). Values were never printed.",
                worst, "exposure", tags=["secret-scan", "credentials"],
            )
            lines.append("[>] Rotate any real credential and remove it from version control history.")
        lines.append("[!] Values are never printed. Heuristics can miss secrets and flag placeholders.")
        return "\n".join(lines)

    def _scan_candidates(self, root: Path) -> list[Path]:
        skip = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build", ".mypy_cache", ".pytest_cache"}
        candidates: list[Path] = []
        for item in root.rglob("*"):
            if not item.is_file() or any(part in skip for part in item.parts):
                continue
            try:
                if item.stat().st_size > 2_000_000:
                    continue
            except OSError:
                continue
            candidates.append(item)
            if len(candidates) >= 400:
                break
        return candidates

    async def _secret_scan_file(self, target):
        path = self._path(target)
        if not path.is_file():
            return f"[!] Local file not found: {path}"
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError as error:
            return f"[!] The file could not be read ({type(error).__name__})."

        patterns = SECRET_PATTERNS
        hits: list[tuple[int, str, str]] = []
        for number, line in enumerate(content.splitlines(), 1):
            for label, pattern, severity in patterns:
                if pattern.search(line):
                    hits.append((number, label, severity))
                    break
        lines = [
            f"[>] Redacted secret-pattern review: {path.name}",
            f"[+] Lines scanned: {len(content.splitlines()):,}",
            f"[{'!' if hits else '+'}] Candidate findings: {len(hits)}",
        ]
        for number, label, severity in hits[:40]:
            lines.append(f"[{'-' if severity in {'HIGH', 'CRITICAL'} else '!'}] line {number}: {label} ({severity})")
        if len(hits) > 40:
            lines.append(f"[!] {len(hits) - 40} more candidates not shown")
        if hits:
            worst = "CRITICAL" if any(severity == "CRITICAL" for _, _, severity in hits) else "HIGH" if any(severity == "HIGH" for _, _, severity in hits) else "MEDIUM"
            self.finding(
                f"Secret-shaped content in {path.name}",
                f"{len(hits)} candidate secret(s) on lines: {', '.join(str(number) for number, _, _ in hits[:15])}. Values were never printed.",
                worst, "exposure", tags=["secret-scan", "credentials"],
            )
            lines.append("[>] Rotate any real credential and remove it from version control history.")
        lines.append("[!] Values are never printed. Heuristics can miss secrets and flag placeholders.")
        return "\n".join(lines)

    async def header_analyzer(self, target):
        path = self._path(target)
        if not path.is_file():
            return f"[!] Header file not found: {path}"
        raw = path.read_text(encoding="utf-8", errors="replace")[:400_000]
        headers = {}
        for line in raw.splitlines():
            if line[:1] in {" ", "\t"} or ":" not in line:
                continue
            key, value = line.split(":", 1)
            headers.setdefault(key.strip().lower(), []).append(value.strip())

        auth = " ".join(headers.get("authentication-results", []))
        results = {}
        for label in ("spf", "dkim", "dmarc"):
            match = re.search(rf"{label}=(\w+)", auth, re.I)
            results[label] = match.group(1).lower() if match else "not published"
        hops = len(headers.get("received", []))
        from_address = " ".join(headers.get("from", []))
        reply_to = " ".join(headers.get("reply-to", []))
        from_domain = net.split_target(from_address)[1]
        reply_domain = net.split_target(reply_to)[1] if reply_to else ""

        lines = [
            f"[>] Email header analysis: {path.name}",
            f"[+] From: {from_address or 'not published'}",
            f"[+] Reply-To: {reply_to or 'not published'}",
            f"[+] Return-Path: {' '.join(headers.get('return-path', [])) or 'not published'}",
            f"[+] Delivery hops (Received): {hops}",
            f"[+] Authentication-Results: SPF={results['spf']} DKIM={results['dkim']} DMARC={results['dmarc']}",
        ]
        if reply_domain and from_domain and reply_domain != from_domain:
            lines.append(f"[!] Reply-To domain ({reply_domain}) differs from From domain ({from_domain}).")
            self.finding(
                "Reply-To differs from From domain",
                f"The message claims {from_domain} but replies go to {reply_domain}.",
                "MEDIUM", "email", tags=["phishing", "header"],
            )
        failures = [name.upper() for name, value in results.items() if value in {"fail", "softfail", "none"}]
        if failures:
            self.finding(
                "Email authentication did not pass",
                f"Authentication-Results reports: {', '.join(failures)}.",
                "LOW", "email", tags=["spf", "dkim", "dmarc"],
            )
        for hop in headers.get("received", [])[:5]:
            lines.append(f"[+] Received: {hop[:160]}")
        lines.append("[!] Header parsing is local-only; message bodies are never read or uploaded.")
        return "\n".join(lines)

    # ---------------------------------------------------------- dependencies

    @staticmethod
    def _parse_dependencies(path: Path) -> list[tuple[str, str, str]]:
        """Pinned packages from requirements, npm locks, Poetry, PEP 621 and go.mod."""
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []
        found: list[tuple[str, str, str]] = []
        if path.suffix == ".txt" or path.name.endswith((".in", ".txt")):
            for line in text.splitlines():
                line = line.split("#", 1)[0].strip()
                if not line or line.startswith("-"):
                    continue
                match = re.match(r"^([A-Za-z0-9_.\-]+)\s*(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9_.\-+]+)", line)
                if match:
                    found.append((match.group(1).lower(), match.group(2), "PyPI"))
        elif path.name == "package.json":
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                return []
            dependencies = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
            for name, spec in dependencies.items():
                version = re.sub(r"^[^0-9]*", "", str(spec)).split(" ")[0]
                if version and version[0].isdigit():
                    found.append((name, version, "npm"))
        elif path.name == "package-lock.json":
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                return []
            for key, meta in (data.get("packages") or {}).items():
                if not key or not isinstance(meta, dict):
                    continue
                name = meta.get("name") or key.split("node_modules/")[-1]
                version = str(meta.get("version") or "")
                if name and version:
                    found.append((name, version, "npm"))
        elif path.name == "poetry.lock":
            for block in text.split("[[package]]")[1:]:
                name = re.search(r'name\s*=\s*"([^"]+)"', block)
                version = re.search(r'version\s*=\s*"([^"]+)"', block)
                if name and version:
                    found.append((name.group(1), version.group(1), "PyPI"))
        elif path.name == "pyproject.toml":
            for match in re.finditer(r'"([A-Za-z0-9_.\-]+)\s*==\s*([A-Za-z0-9_.\-]+)"', text):
                found.append((match.group(1).lower(), match.group(2), "PyPI"))
        elif path.name == "go.mod":
            for match in re.finditer(r"^\s*([\w.\-/]+)\s+v([0-9][\w.\-+]*)", text, re.M):
                found.append((match.group(1), match.group(2), "Go"))
        return found

    async def dependency_audit(self, target):
        path = self._path(target)
        if not path.is_file():
            return f"[!] Dependency file not found: {path}"
        packages = self._parse_dependencies(path)
        if not packages:
            return "\n".join([
                f"[>] Dependency review: {path.name}",
                "[!] No pinned versions (name==version) were found in this file.",
                "[>] Supported: requirements.txt, poetry.lock, pyproject.toml (PyPI);",
                "[>]            package.json, package-lock.json (npm); go.mod (Go).",
            ])
        packages = packages[:40]
        lines = [
            f"[>] Dependency advisory review: {path.name}",
            f"[+] Pinned packages queried against OSV: {len(packages)}",
            "",
        ]
        results = await net.gather_limited(
            (net.osv_query(self.client, name, ecosystem, version) for name, version, ecosystem in packages), limit=5
        )
        flawed = 0
        for (name, version, ecosystem), result in zip(packages, results):
            if isinstance(result, Exception):
                continue
            vulnerabilities, error = result
            if error:
                lines.append(f"[!] {name} {version}: advisory lookup failed ({error})")
                continue
            if not vulnerabilities:
                lines.append(f"[+] {name} {version}: no advisory match")
                continue
            flawed += 1
            lines.append(f"[-] {name} {version} ({ecosystem}): {len(vulnerabilities)} advisory(ies)")
            for vulnerability in vulnerabilities[:4]:
                identifier = vulnerability.get("id", "unknown")
                summary = (vulnerability.get("summary") or vulnerability.get("details") or "").strip()
                kind, score = net.osv_severity(vulnerability)
                tag = f" [{kind} {score}]" if score else ""
                lines.append(f"    [-] {identifier}{tag}: {summary[:180]}")
                self.node(identifier, "technology", {"type": "advisory", "package": name})
            self.finding(
                f"Known advisories affect {name} {version}",
                f"OSV returned {len(vulnerabilities)} advisory record(s) for {name} {version}. Upgrade to a patched release.",
                "MEDIUM", "dependency", tags=["osv", ecosystem.lower()],
            )
        lines.extend([
            "",
            f"[+] Packages with advisory matches: {flawed}/{len(packages)}",
            "[!] Advisory matches are version-range based; confirm the fix release before upgrading.",
        ])
        return "\n".join(lines)

    # ---------------------------------------------------------- local notes

    async def local_timeline(self, target):
        path = self._path(target)
        if not path.is_file():
            return f"[!] Local research file not found: {path}"
        entries = [line.strip() for line in path.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()]
        dated = []
        undated = []
        for entry in entries:
            match = re.search(r"(\d{4}-\d{2}-\d{2}|\d{2}/\d{2}/\d{4})", entry)
            if match:
                dated.append((match.group(1), entry))
            else:
                undated.append(entry)
        dated.sort(key=lambda item: item[0])
        lines = [
            f"[>] Chronological notes from {path.name}",
            f"[+] Entries: {len(entries)} ({len(dated)} dated)",
        ]
        lines.extend(f"[+] {stamp}: {text[:200]}" for stamp, text in dated[:100])
        if undated:
            lines.append(f"[!] Undated entries kept at the end: {len(undated)}")
            lines.extend(f"[+] {text[:200]}" for text in undated[:40])
        lines.append("[!] Notes are user-supplied; this tool orders them and does not infer facts.")
        return "\n".join(lines)

    async def exposure_diff(self, target):
        text = str(target or "").strip()
        separator = "," if "," in text else None
        parts = [item.strip() for item in (text.split(separator) if separator else text.split()) if item.strip()]
        if len(parts) < 2:
            return "[!] Provide two exported report paths, separated by a space or comma."
        first, second = self._path(parts[0]), self._path(parts[1])
        for path in (first, second):
            if not path.is_file():
                return f"[!] File not found: {path}"

        def lines_of(path: Path) -> set[str]:
            raw = path.read_text(encoding="utf-8", errors="replace")
            try:
                payload = json.loads(raw)
            except json.JSONDecodeError:
                return {line.strip() for line in raw.splitlines() if line.strip()}
            if isinstance(payload, dict) and isinstance(payload.get("findings"), list):
                return {str(entry).strip() for entry in payload["findings"] if str(entry).strip()}
            if isinstance(payload, list):
                return {str(entry).strip() for entry in payload}
            return {line.strip() for line in raw.splitlines() if line.strip()}

        before = lines_of(first)
        after = lines_of(second)
        added, removed = sorted(after - before), sorted(before - after)
        lines = [
            f"[>] Report comparison: {first.name} -> {second.name}",
            f"[+] Lines before: {len(before)} | after: {len(after)}",
            f"[{'-' if added else '+'}] New lines: {len(added)}",
        ]
        lines.extend(f"[-] + {line[:200]}" for line in added[:40])
        lines.append(f"[{'+' if removed else '!'}] Resolved lines: {len(removed)}")
        lines.extend(f"[+] - {line[:200]}" for line in removed[:40])
        if added:
            self.finding(
                "New public exposure appeared between reports",
                f"{len(added)} new line(s) appeared in the later report; review them first.",
                "MEDIUM", "monitoring", tags=["diff", "exposure"],
            )
        lines.append("[!] Diffing compares saved report text only; it does not re-scan either target.")
        return "\n".join(lines)

    # -------------------------------------------------------------- privates

    @staticmethod
    def _path(target) -> Path:
        return Path(str(target or "").strip().strip('"').strip("'"))
