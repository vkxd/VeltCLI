"""Passive DNS enumeration and subdomain-takeover detection."""
from __future__ import annotations

import asyncio

from core import netutils as net

from .base import BasePlugin

# Hosting providers whose default error pages are the classic takeover signal.
TAKEOVER_PROVIDERS = {
    "github.io": "GitHub Pages",
    "herokuapp.com": "Heroku",
    "azurewebsites.net": "Azure App Service",
    "cloudapp.azure.com": "Azure Cloud App",
    "trafficmanager.net": "Azure Traffic Manager",
    "cloudfront.net": "Amazon CloudFront",
    "s3.amazonaws.com": "Amazon S3",
    "elasticbeanstalk.com": "AWS Elastic Beanstalk",
    "wordpress.com": "WordPress.com",
    "myshopify.com": "Shopify",
    "bitbucket.io": "Bitbucket",
    "netlify.app": "Netlify",
    "vercel.app": "Vercel",
    "now.sh": "Vercel",
    "ghost.io": "Ghost",
    "readme.io": "ReadMe",
    "statuspage.io": "Statuspage",
    "unbouncepages.com": "Unbounce",
    "surge.sh": "Surge",
    "pantheonsite.io": "Pantheon",
    "fly.dev": "Fly.io",
    "onrender.com": "Render",
    "web.app": "Firebase",
    "firebaseapp.com": "Firebase",
    "pages.dev": "Cloudflare Pages",
    "workers.dev": "Cloudflare Workers",
    "zendesk.com": "Zendesk",
    "freshdesk.com": "Freshdesk",
    "helpscoutdocs.com": "Help Scout",
    "fastly.net": "Fastly",
}

TAKEOVER_FINGERPRINTS = {
    "There isn't a GitHub Pages site here": "GitHub Pages",
    "NoSuchBucket": "Amazon S3",
    "The specified bucket does not exist": "Amazon S3",
    "No such app": "Heroku",
    "404 Web Site not found": "Azure App Service",
    "No settings were found for this company": "Shopify",
    "project not found": "Netlify",
    "This site is not configured": "Surge",
    "Sorry, this page is no longer available": "Unbounce",
    "The feed has not been found": "Ghost",
    "Repository not found": "Bitbucket",
    "does not exist in our system": "Zendesk",
    "This ReadMe is not yet published": "ReadMe",
}


class PassiveDNS(BasePlugin):
    """Third-party passive DNS plus dangling-CNAME takeover checks."""

    def _domain(self, target) -> str:
        return net.normalize_domain(str(target))

    async def run_all(self, target):
        return await self.hosts(target)

    async def run_sub(self, sub_id, target):
        handlers = {
            "passive_dns": self.hosts,
            "sub_passive_dns": self.hosts,
            "sub_takeover": self.takeover,
        }
        handler = handlers.get(sub_id)
        if handler is None:
            return f"[!] Passive-DNS tool '{sub_id}' is not registered."
        return await handler(target)

    # ---------------------------------------------------------- passive dns

    async def _hostsearch(self, domain: str) -> tuple[list[tuple[str, str]], str]:
        response, error = await net.get(
            self.client, "https://api.hackertarget.com/hostsearch/", timeout=35, params={"q": domain}
        )
        if response is None:
            return [], f"request failed ({error})"
        body = (response.text or "").strip()
        if response.status_code != 200:
            return [], f"HTTP {response.status_code}"
        if "error" in body.lower()[:80] and "API count exceeded" in body:
            return [], "passive-DNS quota exceeded for today"
        pairs: list[tuple[str, str]] = []
        for line in body.splitlines():
            if "," not in line:
                continue
            host, address = (part.strip() for part in line.split(",", 1))
            if host and address and "." in host:
                pairs.append((host.lower(), address))
        return pairs, ""

    async def hosts(self, target):
        domain = self._domain(target)
        if not domain:
            return "[!] Enter a domain such as example.com"
        pairs, error = await self._hostsearch(domain)
        if error and not pairs:
            return f"[!] Passive DNS lookup for {domain} failed: {error}."
        if not pairs:
            return f"[-] No passive-DNS hostnames were returned for {domain}."

        lines = [
            f"[>] Passive DNS hosts for {domain}",
            f"[+] Hostnames returned: {len(pairs)}",
            "[>] Source: HackerTarget host search (third-party passive data).",
        ]
        for host, address in sorted(pairs)[:60]:
            lines.append(f"[+] {host} -> {address}")
            self.node(host, "subdomain" if host != domain else "domain")
            if host != domain:
                self.edge(domain, host, "contains", "domain", "subdomain")
            if net.is_ip(address):
                self.node(address, "ip")
                self.edge(host, address, "resolves_to", "subdomain", "ip")
        if len(pairs) > 60:
            lines.append(f"[!] {len(pairs) - 60} more hosts not shown")
        self.finding(
            f"Passive DNS lists {len(pairs)} hosts for {domain}",
            "Third-party passive DNS data adds hostnames that certificate logs may miss. "
            "Review them against authorized inventory.",
            "INFO", "asset-inventory", tags=["passive-dns", "subdomain"],
        )
        lines.append("[!] Passive data is historical and rate limited; verify each host before assessing it.")
        return "\n".join(lines)

    # ------------------------------------------------------------- takeover

    async def _fingerprint_page(self, host: str) -> str:
        for scheme in ("https", "http"):
            response, _error = await net.get(self.client, f"{scheme}://{host}", timeout=12)
            if response is None:
                continue
            body = (response.text or "")[:20000]
            for needle, provider in TAKEOVER_FINGERPRINTS.items():
                if needle.lower() in body.lower():
                    return provider
            return ""
        return ""

    async def takeover(self, target):
        domain = self._domain(target)
        if not domain:
            return "[!] Enter a domain such as example.com"

        pairs, dns_error = await self._hostsearch(domain)
        hosts = sorted({host for host, _address in pairs})[:80]
        for extra in (f"www.{domain}", domain):
            if extra not in hosts:
                hosts.insert(0, extra)
        if not hosts:
            return (
                f"[!] No candidate hosts could be enumerated for {domain} ({dns_error or 'no passive data'}).\n"
                "[>] Try the certificate-subdomain tool to build a candidate list, then re-run."
            )

        dangling: list[tuple[str, str, str]] = []
        unverified: list[tuple[str, str]] = []
        providers_seen: dict[str, int] = {}

        async def inspect(host: str):
            cname = net.dns_lookup(host, "CNAME").get("values", [])
            target = cname[0].rstrip(".").lower() if cname else ""
            provider = next((name for suffix, name in TAKEOVER_PROVIDERS.items() if target.endswith("." + suffix) or target == suffix), "")
            if not provider:
                addresses = await asyncio.to_thread(net.resolve_addresses, host)
                return host, target, "", bool(addresses), ""
            providers_seen[provider] = providers_seen.get(provider, 0) + 1
            resolves = bool(await asyncio.to_thread(net.resolve_addresses, host))
            fingerprint = ""
            if not resolves:
                fingerprint = provider  # dangling CNAME: the target no longer exists
            else:
                fingerprint = await self._fingerprint_page(host)
            return host, target, provider, resolves, fingerprint

        results = await net.gather_limited((inspect(host) for host in hosts), limit=8)
        for host, target, provider, resolves, fingerprint in (r for r in results if not isinstance(r, Exception)):
            if fingerprint and not resolves:
                dangling.append((host, target, fingerprint))
            elif fingerprint:
                dangling.append((host, target, fingerprint))
            elif provider:
                unverified.append((host, f"{provider} target resolves"))
            if provider:
                self.node(host, "subdomain", {"provider": provider, "cname": target})

        lines = [
            f"[>] Subdomain-takeover review for {domain}",
            f"[+] Candidate hosts checked: {len(hosts)}",
            f"[+] Hosts pointing at claimable providers: {sum(providers_seen.values())}",
            f"[!] Dangling or fingerprint-matching hosts: {len(dangling)}",
        ]
        for host, target, provider in dangling:
            lines.append(f"[-] {host} -> {target or 'no CNAME'} ({provider}) looks claimable")
            self.finding(
                f"Possible subdomain takeover: {host}",
                f"{host} points at {target or 'a provider default'} and returned a {provider} "
                "placeholder/error page, which usually means the resource is unclaimed.",
                "HIGH", "takeover", tags=["subdomain-takeover", provider.lower().replace(" ", "-")],
            )
        for host, note in unverified[:10]:
            lines.append(f"[+] {host}: {note}; no takeover fingerprint observed")
        if not dangling:
            lines.append("[+] No dangling CNAME or provider placeholder page was confirmed.")
        lines.append("[!] Fingerprints change over time; confirm in the provider dashboard before acting.")
        return "\n".join(lines)
