"""DNS and infrastructure intelligence: real records, mail policy, certificates."""
from __future__ import annotations

import asyncio

from core import netutils as net

from .base import BasePlugin

RECORD_ORDER = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA")


class InfraDNS(BasePlugin):
    """Full public DNS picture for a domain, plus certificate and ASN context."""

    async def run_all(self, target):
        return await self.infrastructure_map(target)

    async def run_sub(self, sub_id, target):
        handlers = {
            "infra_map": self.infrastructure_map,
            "web_info": self.web_info,
            "records": self.records,
            "spf_check": self.spf_check,
            "dmarc_check": self.dmarc_check,
            "dnssec_check": self.dnssec_check,
            "reverse_dns": self.reverse_dns,
            "certificate_search": self.certificate_search,
            "asn_map": self.asn_map,
        }
        handler = handlers.get(sub_id)
        if handler is None:
            return f"[!] Infrastructure tool '{sub_id}' is not registered."
        return await handler(target)

    # ------------------------------------------------------------- plumbing

    def _domain(self, target) -> str:
        domain = net.normalize_domain(str(target or ""))
        if not domain or " " in domain:
            return ""
        return domain

    def _record_lines(self, domain: str, include: tuple[str, ...] = RECORD_ORDER) -> list[str]:
        lines: list[str] = []
        for rdtype in include:
            result = net.dns_lookup(domain, rdtype)
            values, ttl = result.get("values", []), result.get("ttl")
            if values:
                suffix = f" (TTL {ttl}s)" if ttl else ""
                for value in values[:10]:
                    lines.append(f"[+] {rdtype}: {value}{suffix}")
                if len(values) > 10:
                    lines.append(f"[+] {rdtype}: {len(values) - 10} more values not shown")
            elif result.get("error") not in {"NoAnswer", "NXDOMAIN"}:
                lines.append(f"[!] {rdtype}: unavailable ({result.get('error')})")
        return lines

    def _collect_records(self, domain: str) -> None:
        addresses = net.resolve_addresses(domain)
        self.node(domain, "domain")
        for address in addresses:
            self.node(address, "ip")
            self.edge(domain, address, "resolves_to", "domain", "ip")
        for entry in net.dns_lookup(domain, "NS").get("values", []):
            name = entry.rstrip(".")
            if name:
                self.node(name, "host", {"role": "nameserver"})
                self.edge(domain, name, "uses", "domain", "host")
        for entry in net.dns_lookup(domain, "MX").get("values", []):
            host = entry.split()[-1].rstrip(".")
            if host:
                self.node(host, "host", {"role": "mail"})
                self.edge(domain, host, "uses", "domain", "host")

    # -------------------------------------------------------------- context

    @staticmethod
    def _ns_provider(name: str) -> str:
        name = name.lower()
        mapping = (
            ("cloudflare", "Cloudflare"), ("awsdns", "AWS Route 53"), ("azure-dns", "Azure DNS"),
            ("googledomains", "Google Cloud DNS"), ("domaincontrol", "GoDaddy"),
            ("registrar-servers", "Namecheap"), ("digitalocean", "DigitalOcean"),
            ("nsone", "NS1"), ("dnsimple", "DNSimple"), ("hetzner", "Hetzner"),
        )
        return next((label for token, label in mapping if token in name), "unknown provider")

    @staticmethod
    def _mail_provider(host: str) -> str:
        host = host.lower().rstrip(".")
        mapping = (
            ("google.com", "Google Workspace"), ("outlook.com", "Microsoft 365"),
            ("protonmail", "Proton Mail"), ("zoho", "Zoho"), ("yahoodns", "Yahoo Mail"),
            ("mimecast", "Mimecast"), ("pphosted", "Proofpoint"), ("barracudanetworks", "Barracuda"),
            ("amazonses", "Amazon SES"), ("mailgun", "Mailgun"), ("sendgrid", "SendGrid"),
        )
        return next((label for token, label in mapping if token in host), "self-hosted or unknown")

    def _wildcard(self, domain: str) -> bool:
        probe = f"scylla-wildcard-{abs(hash(domain)) % 100000}.{domain}"
        return bool(net.resolve_addresses(probe))

    def _dns_extras(self, domain: str) -> list[str]:
        extras: list[str] = []
        nameservers = [value.rstrip(".") for value in net.dns_lookup(domain, "NS").get("values", [])]
        if nameservers:
            extras.append(f"[+] DNS provider: {self._ns_provider(nameservers[0])} ({', '.join(nameservers[:3])})")

        mail_hosts: list[str] = []
        for value in net.dns_lookup(domain, "MX").get("values", []):
            parts = value.split()
            if not parts or "null" in value.lower():
                continue
            host = parts[-1].rstrip(".")
            if "." in host:
                mail_hosts.append(host)
        if mail_hosts:
            extras.append(f"[+] Mail-provider hint: {self._mail_provider(mail_hosts[0])} (MX {mail_hosts[0]})")
        else:
            extras.append("[-] Mail-provider hint: no routable MX (domain may not accept mail)")

        wildcard = self._wildcard(domain)
        extras.append(f"[{'+' if wildcard else '-'}] Wildcard DNS: {'enabled (random labels resolve)' if wildcard else 'not observed'}")
        if wildcard:
            self.finding(
                "Wildcard DNS is enabled",
                f"Random labels under {domain} resolve, which can mask typo-squatting and takeover findings.",
                "LOW", "dns", tags=["wildcard-dns"],
            )

        records = ["SPF"] if any(value.lower().startswith("v=spf1") for value in net.txt_values(domain)) else []
        if any(value.lower().startswith("v=stsv1") for value in net.txt_values(f"_mta-sts.{domain}")):
            records.append("MTA-STS")
        if any(value.lower().startswith("v=bimi1") for value in net.txt_values(f"default._bimi.{domain}")):
            records.append("BIMI")
        extras.append(f"[+] Email security records: {', '.join(records) if records else 'none published'}")

        caa = net.dns_lookup(domain, "CAA").get("values", [])
        extras.append(f"[{'+' if caa else '!'}] CAA policy: {', '.join(caa[:4]) if caa else 'not published (any CA may issue)'}")
        return extras

    # ------------------------------------------------------------- reports

    async def records(self, target):
        domain = self._domain(target)
        if not domain:
            return "[!] Enter a domain such as example.com"
        lines = [f"[>] Public DNS records for {domain}"]
        record_lines = self._record_lines(domain)
        lines.extend(record_lines or ["[!] No records returned by the configured resolver."])
        self._collect_records(domain)
        lines.extend(self._dns_extras(domain))
        lines.append("[!] DNS answers are point-in-time and may differ by resolver or location.")
        return "\n".join(lines)

    async def infrastructure_map(self, target):
        domain = self._domain(target)
        if not domain:
            return "[!] Enter a domain such as example.com"
        lines = [f"[>] Passive infrastructure map for {domain}", ""]
        lines.append("DNS")
        lines.append("─" * 46)
        record_lines = self._record_lines(domain)
        lines.extend(record_lines or ["[!] No records returned by the configured resolver."])
        self._collect_records(domain)
        lines.extend(self._dns_extras(domain))

        addresses = net.resolve_addresses(domain)
        if addresses:
            context = await net.ip_context(self.client, addresses[0])
            lines.extend(["", "Network ownership", "─" * 46])
            if context.get("error"):
                lines.append(f"[!] ASN context unavailable ({context['error']})")
            else:
                lines.append(f"[+] Address: {addresses[0]}")
                lines.append(f"[+] ASN: {context.get('asn') or 'not published'}")
                lines.append(f"[+] Organization: {context.get('org') or 'not published'}")
                lines.append(f"[+] Country: {context.get('country') or 'unknown'}")
                if context.get("asn"):
                    self.node(f"AS{str(context['asn']).removeprefix('AS')}", "asn", {"org": context.get("org")})
                    self.edge(domain, f"AS{str(context['asn']).removeprefix('AS')}", "belongs_to", "domain", "asn")
                if context.get("org"):
                    self.node(context["org"], "organization")
                    self.edge(domain, context["org"], "belongs_to", "domain", "organization")

        lines.extend(["", "Certificate transparency", "─" * 46])
        entries, error = await net.crt_entries(self.client, domain)
        if error:
            lines.append(f"[!] Certificate-transparency lookup unavailable ({error})")
        else:
            names = net.crt_names(entries, domain)
            lines.append(f"[+] Unique names seen in public logs: {len(names)}")
            for name in names[:40]:
                lines.append(f"[+] {name}")
                self.node(name, "subdomain" if name != domain else "domain")
                if name != domain:
                    self.edge(domain, name, "contains", "domain", "subdomain")
            if len(names) > 40:
                lines.append(f"[!] {len(names) - 40} more names not shown")

        lines.extend(["", "Mail policy", "─" * 46])
        lines.append(self._spf_summary(domain))
        lines.append(self._dmarc_summary(domain))
        lines.append("[!] Passive DNS/certificate data only; no host was probed in this map.")
        return "\n".join(lines)

    async def web_info(self, target):
        domain = self._domain(target)
        if not domain:
            return "[!] Enter a domain such as example.com"
        lines = [f"[>] Website information for {domain}"]

        response, error = await net.get(self.client, f"https://{domain}", timeout=15)
        if response is None:
            response, error = await net.get(self.client, f"http://{domain}", timeout=15)
        if response is not None:
            headers = {key.lower(): value for key, value in response.headers.items()}
            meta = net.page_metadata(response.text)
            lines.extend([
                f"[+] HTTP response: {response.status_code}",
                f"[+] Final URL: {str(response.url)}",
                f"[+] Server: {headers.get('server', 'not disclosed')}",
                f"[+] Page title: {meta['title'] or 'not published'}",
            ])
            if meta["description"]:
                lines.append(f"[+] Description: {meta['description']}")
            signals = net.fingerprint(response.text, response.headers)
            if signals:
                lines.append(f"[+] Technology clues: {', '.join(name for name, _ in signals)}")
            for name, evidence in signals:
                self.node(domain, "domain")
                self.node(name, "technology", {"evidence": evidence})
                self.edge(domain, name, "uses", "domain", "technology")
        else:
            lines.append(f"[!] The website did not respond to a normal HTTPS/HTTP request ({error}).")

        addresses = net.resolve_addresses(domain)
        lines.extend([f"[+] Resolved address: {address}" for address in addresses] or ["[!] No A/AAAA records resolved."])
        for address in addresses:
            self.node(address, "ip")
            self.edge(domain, address, "resolves_to", "domain", "ip")

        payload, rdap_error = await net.rdap_domain(self.client, domain)
        lines.append("")
        if payload:
            nameservers = [item.get("ldhName") for item in payload.get("nameservers", []) if item.get("ldhName")]
            events = {event.get("eventAction"): event.get("eventDate") for event in payload.get("events", [])}
            entities = net.rdap_entities(payload)
            lines.extend([
                "[>] Registration (RDAP)",
                f"[+] Registrar/entities: {', '.join(entities) or 'not published'}",
                f"[+] Registered: {events.get('registration', 'not published')}",
                f"[+] Expires: {events.get('expiration', 'not published')}",
                f"[+] Nameservers: {', '.join(nameservers[:6]) or 'not published'}",
            ])
        else:
            lines.append(f"[!] Registration data unavailable ({rdap_error}).")
        lines.append("[!] Registration dates and technology clues are evidence to verify, not conclusions.")
        self._collect_records(domain)
        return "\n".join(lines)

    async def reverse_dns(self, target):
        value = str(target or "").strip()
        addresses = [value] if net.is_ip(value) else net.resolve_addresses(net.normalize_domain(value))
        if not addresses:
            return f"[!] Could not resolve {value or 'the supplied target'}."
        lines = [f"[>] Reverse DNS for {value}"]
        for address in addresses[:10]:
            hostname = net.reverse_dns(address)
            if hostname:
                lines.append(f"[+] {address} -> {hostname}")
                self.node(hostname.rstrip("."), "host")
                self.node(address, "ip")
                self.edge(address, hostname.rstrip("."), "points_to", "ip", "host")
            else:
                lines.append(f"[!] {address}: no PTR record published")
        return "\n".join(lines)

    # ---------------------------------------------------------------- mail

    def _spf_summary(self, domain: str) -> str:
        records = [value for value in net.txt_values(domain) if value.lower().startswith("v=spf1")]
        if not records:
            return "[-] SPF: no record published (sender spoofing is easier to attempt)"
        record = records[0]
        qualifier = "fail (hard)" if "-all" in record else "softfail (~all)" if "~all" in record else "neutral (+all or none)"
        lookups = sum(record.lower().count(token) for token in (" include:", " a:", " mx", " ptr", " exists:", " redirect="))
        return f"[+] SPF: {record} | final qualifier: {qualifier} | DNS-lookup terms: {lookups}"

    def _dmarc_summary(self, domain: str) -> str:
        records = [value for value in net.txt_values(f"_dmarc.{domain}") if value.lower().startswith("v=dmarc1")]
        if not records:
            return "[-] DMARC: no record published (_dmarc subdomain empty)"
        record = records[0]
        policy = "none (monitor only)" if "p=none" in record.lower() else "quarantine" if "p=quarantine" in record.lower() else "reject" if "p=reject" in record.lower() else "unspecified"
        return f"[+] DMARC: {record} | enforcement: {policy}"

    async def spf_check(self, target):
        domain = self._domain(target) or net.split_target(str(target))[1]
        if not domain:
            return "[!] Enter a domain such as example.com"
        summary = self._spf_summary(domain)
        lines = [f"[>] SPF review for {domain}", summary]
        if summary.startswith("[-]"):
            self.finding(
                "SPF record is missing",
                f"{domain} publishes no v=spf1 record, so receivers have no authorized-sender list for it.",
                "MEDIUM", "email", tags=["spf", "email-spoofing"],
            )
            lines.append("[>] Add a single SPF record listing only the hosts that send mail for the domain.")
        else:
            record = summary.split("|")[0].replace("[+] SPF: ", "").strip()
            if "+all" in record:
                self.finding(
                    "SPF allows any sender",
                    f"{domain} ends its SPF record with +all, which authorizes every host.",
                    "HIGH", "email", tags=["spf"],
                )
            if "~all" in record:
                lines.append("[!] The record ends with ~all (softfail); -all is stricter once all senders are listed.")
        lines.append("[!] SPF alone does not stop spoofing; pair it with DKIM and a DMARC enforcement policy.")
        return "\n".join(lines)

    async def dmarc_check(self, target):
        domain = self._domain(target) or net.split_target(str(target))[1]
        if not domain:
            return "[!] Enter a domain such as example.com"
        summary = self._dmarc_summary(domain)
        lines = [f"[>] DMARC review for {domain}", summary]
        if summary.startswith("[-]"):
            self.finding(
                "DMARC record is missing",
                f"{domain} publishes no _dmarc policy, so receivers cannot act on failed authentication.",
                "MEDIUM", "email", tags=["dmarc", "email-spoofing"],
            )
            lines.append("[>] Start with v=DMARC1; p=none; rua=mailto:dmarc@yourdomain to collect reports, then enforce.")
        elif "p=none" in summary:
            self.finding(
                "DMARC is monitor-only",
                f"{domain} publishes p=none, so spoofed mail is observed but never rejected.",
                "LOW", "email", tags=["dmarc"],
            )
            lines.append("[>] Once reports look correct, move to p=quarantine and then p=reject.")
        lines.append("[!] DMARC depends on aligned SPF or DKIM; verify both before enforcing.")
        return "\n".join(lines)

    async def dnssec_check(self, target):
        domain = self._domain(target)
        if not domain:
            return "[!] Enter a domain such as example.com"
        keys = net.dns_lookup(domain, "DNSKEY")
        ds = net.dns_lookup(domain, "DS")
        lines = [f"[>] DNSSEC review for {domain}"]
        if keys.get("values"):
            lines.append(f"[+] DNSKEY records present: {len(keys['values'])}")
            lines.append(f"[+] DS record at parent: {'published' if ds.get('values') else 'not visible'}")
            lines.append("[+] Chain validation should be confirmed with your DNS provider or a validating resolver.")
        else:
            lines.append("[-] No DNSKEY records were returned, so DNSSEC is not confirmed for this domain.")
            self.finding(
                "DNSSEC is not enabled",
                f"{domain} returned no DNSKEY records; DNS answers are not cryptographically signed.",
                "LOW", "dns", tags=["dnssec"],
            )
        lines.append("[!] DNSSEC protects name resolution; it does not protect web content or email policy.")
        return "\n".join(lines)

    # ------------------------------------------------------ certificates/ASN

    async def certificate_search(self, target):
        domain = self._domain(target)
        if not domain:
            return "[!] Enter a domain such as example.com"
        entries, error = await net.crt_entries(self.client, domain)
        if error:
            return f"[!] Certificate-transparency lookup failed ({error}). Try again shortly."
        names = net.crt_names(entries, domain)
        issuers = sorted({str(item.get("issuer_name", "")).strip() for item in entries if item.get("issuer_name")})
        lines = [
            f"[>] Certificate-transparency search for {domain}",
            f"[+] Log entries: {len(entries)}",
            f"[+] Unique names: {len(names)}",
        ]
        lines.extend(f"[+] {name}" for name in names[:80])
        if len(names) > 80:
            lines.append(f"[!] {len(names) - 80} more names not shown")
        if issuers:
            lines.append(f"[+] Issuers observed: {', '.join(issuers[:5])}")
        for name in names:
            self.node(name, "subdomain" if name != domain else "domain")
            if name != domain:
                self.edge(domain, name, "contains", "domain", "subdomain")
        self.finding(
            f"Certificate transparency exposes {len(names)} names for {domain}",
            "Passive certificate logs list additional hostnames that may need inventory review.",
            "INFO", "certificate", tags=["ct", "asset-inventory"],
        )
        lines.append("[!] Logs are public and historical; names may be expired or unrelated to live hosts.")
        return "\n".join(lines)

    async def asn_map(self, target):
        value = str(target or "").strip()
        if not value:
            return "[!] Enter an ASN (AS15169), IP address, or domain."
        prefixes, error = await net.asn_prefixes(self.client, value)
        lines = [f"[>] Network ranges for {value}"]
        if error and not prefixes:
            lines.append(f"[!] Routing-data lookup unavailable ({error}).")
            return "\n".join(lines)
        lines.append(f"[+] Announced prefixes: {len(prefixes)}")
        lines.extend(f"[+] {prefix}" for prefix in prefixes[:40])
        if len(prefixes) > 40:
            lines.append(f"[!] {len(prefixes) - 40} more prefixes not shown")
        self.node(value.upper(), "asn" if value.upper().startswith("AS") else "ip")
        self.finding(
            f"Public address ranges mapped for {value}",
            f"{len(prefixes)} prefixes are announced for this resource; review them against your authorized scope.",
            "INFO", "network", tags=["asn", "asset-inventory"],
        )
        lines.append("[!] Only assess addresses you own or are explicitly authorized to review.")
        return "\n".join(lines)
