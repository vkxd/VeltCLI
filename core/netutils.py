"""Shared, dependency-free network helpers for Scylla modules.

Every helper here is used by more than one plugin: URL/DNS/TLS plumbing,
passive certificate-transparency lookups, RDAP, OSV advisories and public
storage probes. Keeping them in one place means the modules stay thin and
behave consistently (one user agent, one timeout policy, one output shape).
"""
from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

USER_AGENT = "Scylla-OSINT/2.0 (authorized public-information research)"
ACCEPT_HTML = "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.1"

DNS_TIMEOUT = 5.0
COMMON_SUBDOMAINS = (
    "www", "dev", "staging", "test", "api", "admin", "mail", "vpn", "git",
    "portal", "shop", "blog", "cdn", "app", "beta", "docs", "support",
    "status", "secure", "old", "demo", "sso", "dashboard", "files", "static",
    "media", "m", "webmail", "autodiscover", "owa", "remote", "assets",
    "internal", "intranet", "jenkins", "grafana", "kibana", "jira", "s3",
)


# ---------------------------------------------------------------- url helpers

def host_of(target: str) -> str:
    """Return a lowercase hostname from a URL, host, or host:port string."""
    value = (target or "").strip()
    if not value:
        return ""
    if "://" not in value:
        value = "//" + value
    parsed = urlparse(value)
    host = parsed.hostname or ""
    return host.strip("[]").rstrip(".").lower()


def normalize_domain(target: str) -> str:
    host = host_of(target)
    if not host:
        return ""
    return host.removeprefix("www.")


def ensure_url(target: str) -> str:
    value = (target or "").strip()
    if not value:
        return ""
    if not urlparse(value).scheme:
        value = "https://" + value
    return value


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address((value or "").strip().strip("[]"))
        return True
    except ValueError:
        return False


def split_target(target: str) -> tuple[str, str]:
    """Split an email into (local, domain) or return ('', domain)."""
    value = (target or "").strip().lower()
    if "@" in value:
        local, domain = value.rsplit("@", 1)
        return local, domain.split()[0].rstrip(".")
    return "", normalize_domain(value)


async def gather_limited(factories, limit: int = 8) -> list:
    """Run awaitables with a concurrency cap; exceptions become results."""
    semaphore = asyncio.Semaphore(limit)

    async def run(awaitable):
        async with semaphore:
            return await awaitable

    return await asyncio.gather(*(run(item) for item in factories), return_exceptions=True)


# ------------------------------------------------------------------ dns layer

def _rdata_value(rdata, rdtype: str) -> str:
    if rdtype == "MX":
        exchange = str(getattr(rdata, "exchange", rdata)).rstrip(".")
        return f"{getattr(rdata, 'preference', 10)} {exchange or '(null MX: domain does not accept mail)'}"
    if rdtype == "TXT":
        parts = getattr(rdata, "strings", None)
        if parts:
            return "".join(part.decode(errors="replace") if isinstance(part, bytes) else str(part) for part in parts)
        return str(rdata).strip('"')
    if rdtype == "SOA":
        return (
            f"{str(getattr(rdata, 'mname', '')).rstrip('.')} "
            f"serial={getattr(rdata, 'serial', '?')} "
            f"refresh={getattr(rdata, 'refresh', '?')} retry={getattr(rdata, 'retry', '?')}"
        )
    if rdtype == "CAA":
        return f"{getattr(rdata, 'flags', 0)} {getattr(rdata, 'tag', '?')} \"{getattr(rdata, 'value', '')}\""
    if rdtype == "SRV":
        return f"{getattr(rdata, 'priority', 0)} {getattr(rdata, 'weight', 0)} {getattr(rdata, 'port', 0)} {str(getattr(rdata, 'target', '')).rstrip('.')}"
    return str(rdata).rstrip(".")


FALLBACK_NAMESERVERS = ["1.1.1.1", "8.8.8.8"]
_FORCED_NAMESERVERS: list[str] | None = None
_PROBED = False


def _resolve_with(name: str, rdtype: str, nameservers, timeout: float) -> dict:
    import dns.resolver

    resolver = dns.resolver.Resolver(configure=nameservers is None)
    if nameservers:
        resolver.nameservers = list(nameservers)
    resolver.timeout = timeout
    resolver.lifetime = timeout * 2
    answers = resolver.resolve(name, rdtype, raise_on_no_answer=False)
    values = []
    for rdata in answers:
        try:
            values.append(_rdata_value(rdata, rdtype))
        except Exception:
            continue
    return {"values": values, "ttl": getattr(getattr(answers, "rrset", None), "ttl", None), "error": None}


def _probe_resolver() -> None:
    """Detect once whether the OS resolver answers direct queries.

    Hotspots and filtered networks often answer the operating system but drop
    dnspython's UDP packets, which used to make every lookup look "unavailable".
    """
    global _FORCED_NAMESERVERS, _PROBED
    if _PROBED:
        return
    _PROBED = True
    try:
        if _resolve_with("example.com", "A", None, 2.0)["values"]:
            return
    except Exception:
        pass
    _FORCED_NAMESERVERS = FALLBACK_NAMESERVERS


def dns_lookup(name: str, rdtype: str, timeout: float = DNS_TIMEOUT) -> dict:
    """Resolve one record type. Never raises: returns {'values': [], 'error': ...}."""
    try:
        import dns.resolver  # noqa: F401  (availability check only)
    except ImportError:
        return {"values": [], "ttl": None, "error": "dnspython is not installed"}

    _probe_resolver()
    plans = [_FORCED_NAMESERVERS] if _FORCED_NAMESERVERS else [None, FALLBACK_NAMESERVERS]
    last_error = "unavailable"
    for nameservers in plans:
        try:
            result = _resolve_with(name, rdtype, nameservers, timeout)
        except Exception as error:  # NXDOMAIN, NoAnswer, timeout, ...
            last_error = type(error).__name__
            continue
        if result["values"]:
            return result
        return {"values": [], "ttl": result["ttl"], "error": "NoAnswer"}

    if rdtype in {"A", "AAAA"}:
        family = socket.AF_INET if rdtype == "A" else socket.AF_INET6
        try:
            infos = socket.getaddrinfo(name, None, family)
            values = sorted({item[4][0] for item in infos})
            if values:
                return {"values": values, "ttl": None, "error": None}
        except OSError:
            pass
    return {"values": [], "ttl": None, "error": last_error}


def dns_records(domain: str, record_types=("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA")) -> dict:
    return {rdtype: dns_lookup(domain, rdtype) for rdtype in record_types}


def resolve_addresses(host: str) -> list[str]:
    """All A/AAAA addresses for a host, deduplicated and sorted."""
    found: list[str] = []
    for rdtype in ("A", "AAAA"):
        found.extend(dns_lookup(host, rdtype).get("values", []))
    if not found:
        try:
            found = sorted({item[4][0] for item in socket.getaddrinfo(host, None)})
        except OSError:
            return []
    cleaned = []
    for value in found:
        try:
            cleaned.append(str(ipaddress.ip_address(value)))
        except ValueError:
            continue
    return sorted(dict.fromkeys(cleaned))


def reverse_dns(address: str) -> str:
    try:
        return socket.gethostbyaddr(address.strip())[0]
    except (OSError, socket.herror, socket.gaierror):
        return ""


def txt_values(domain: str) -> list[str]:
    return dns_lookup(domain, "TXT").get("values", [])


# ------------------------------------------------------------------ tls layer

def _ssl_context() -> ssl.SSLContext:
    """Default context plus certifi roots, which Python on Windows often lacks."""
    context = ssl.create_default_context()
    try:
        import certifi
        context.load_verify_locations(certifi.where())
    except Exception:
        pass
    return context


def tls_info(host: str, port: int = 443, timeout: float = 8.0) -> dict:
    """Inspect the live TLS certificate and negotiated parameters.

    Verification is attempted with a certifi-augmented trust store. If the
    local store cannot build a chain, the handshake is retried without
    verification so issuer/expiry can still be reported, and the local
    verification failure is surfaced rather than hidden.
    """
    if not host:
        return {"error": "no host supplied"}
    verification_error = ""
    certificate: dict = {}
    version = ""
    cipher = ""
    sans: list[str] = []
    for context in (_ssl_context(), ssl._create_unverified_context()):
        try:
            with socket.create_connection((host, port), timeout=timeout) as raw:
                with context.wrap_socket(raw, server_hostname=host) as tls:
                    certificate = tls.getpeercert() or {}
                    version = tls.version() or ""
                    cipher = (tls.cipher() or ("",))[0]
                    sans = [value for kind, value in certificate.get("subjectAltName", ()) if kind == "DNS"]
            break
        except ssl.SSLCertVerificationError as error:
            verification_error = verification_error or f"{type(error).__name__}: {error}"
            continue
        except Exception as error:
            return {"error": f"{type(error).__name__}: {error}"}
    else:
        return {"error": verification_error or "TLS handshake failed"}
    subject = {key: value for item in certificate.get("subject", ()) for key, value in item}
    issuer = {key: value for item in certificate.get("issuer", ()) for key, value in item}
    expires_at = None
    days_left = None
    if certificate.get("notAfter"):
        try:
            stamp = ssl.cert_time_to_seconds(certificate["notAfter"])
            expires_at = datetime.fromtimestamp(stamp, tz=timezone.utc)
            days_left = (expires_at - datetime.now(timezone.utc)).days
        except (ValueError, OSError):
            pass
    return {
        "subject": subject.get("commonName", ""),
        "issuer": issuer.get("organizationName") or issuer.get("commonName", ""),
        "alt_names": sans,
        "expires_at": expires_at.strftime("%Y-%m-%dT%H:%M:%SZ") if expires_at else "",
        "days_left": days_left,
        "version": version or "",
        "cipher": cipher,
        "verified": not verification_error,
        "verification_error": verification_error,
        "error": None,
    }


# ----------------------------------------------------------------- web layer

async def get(client, url: str, timeout: float = 15.0, follow_redirects: bool = True, **kwargs):
    """GET with a stable user agent. Returns (response, error-string)."""
    headers = {"User-Agent": USER_AGENT, "Accept": ACCEPT_HTML}
    headers.update(kwargs.pop("headers", {}) or {})
    try:
        response = await client.get(url, headers=headers, follow_redirects=follow_redirects, timeout=timeout, **kwargs)
        return response, None
    except Exception as error:
        return None, type(error).__name__


def page_metadata(html: str) -> dict:
    """Extract title/description/links without requiring BeautifulSoup."""
    title_match = re.search(r"<title[^>]*>(.*?)</title>", html or "", re.I | re.S)
    description = re.search(
        r'<meta[^>]+name=["\']description["\'][^>]+content=["\'](.*?)["\']', html or "", re.I | re.S
    ) or re.search(
        r'<meta[^>]+property=["\']og:description["\'][^>]+content=["\'](.*?)["\']', html or "", re.I | re.S
    )
    generator = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\'](.*?)["\']', html or "", re.I)
    links = re.findall(r'href=["\']([^"\'#]+)', html or "", re.I)
    return {
        "title": re.sub(r"\s+", " ", title_match.group(1)).strip()[:200] if title_match else "",
        "description": re.sub(r"\s+", " ", description.group(1)).strip()[:300] if description else "",
        "generator": generator.group(1).strip()[:100] if generator else "",
        "links": links,
    }


def strip_html(html: str) -> str:
    text = re.sub(r"(?is)<(script|style|noscript)[^>]*>.*?</\1>", " ", html or "")
    text = re.sub(r"<[^>]+>", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def fingerprint(html: str, headers: dict) -> list[tuple[str, str]]:
    """Heuristic technology fingerprint: (name, evidence) pairs."""
    lower = {str(key).lower(): str(value).lower() for key, value in (headers or {}).items()}
    body = (html or "").lower()
    server = lower.get("server", "")
    powered = lower.get("x-powered-by", "")
    cookies = lower.get("set-cookie", "")
    signals: list[tuple[str, str]] = []

    def add(name: str, evidence: str) -> None:
        if all(name != existing for existing, _ in signals):
            signals.append((name, evidence))

    if "cf-ray" in lower or "cloudflare" in server:
        add("Cloudflare", "cf-ray/server header")
    if "x-amz-cf-id" in lower or "cloudfront" in lower.get("via", ""):
        add("Amazon CloudFront", "x-amz-cf-id")
    if "x-azure-ref" in lower or "azure" in server:
        add("Microsoft Azure", "x-azure-ref")
    if "x-goog" in lower.get("server", "") or "gws" in server:
        add("Google Frontend", "server header")
    if "akamai" in server or "akamai-grn" in lower:
        add("Akamai", "server header")
    if "sucuri" in server or "x-sucuri-id" in lower:
        add("Sucuri", "x-sucuri-id")
    if "fastly" in server or "x-served-by" in lower:
        add("Fastly", "server header")
    if "nginx" in server:
        add("nginx", "Server header")
    if "apache" in server:
        add("Apache httpd", "Server header")
    if "microsoft-iis" in server:
        add("Microsoft IIS", "Server header")
    if "express" in powered:
        add("Express (Node.js)", "X-Powered-By")
    if "php" in powered:
        add("PHP", "X-Powered-By")
    if "asp.net" in powered:
        add("ASP.NET", "X-Powered-By")
    if "__next_data__" in body or "/_next/" in body:
        add("Next.js", "HTML markers")
    if "wp-content" in body or "wp-includes" in body:
        add("WordPress", "wp-content paths")
    if "drupal" in body or "sites/default/files" in body:
        add("Drupal", "HTML markers")
    if "cdn.shopify.com" in body:
        add("Shopify", "asset host")
    if "static.wixstatic.com" in body or "wix.com" in body:
        add("Wix", "asset host")
    if "squarespace" in body:
        add("Squarespace", "HTML markers")
    if "csrfmiddlewaretoken" in body:
        add("Django", "CSRF token field")
    if "laravel_session" in cookies or "laravel" in body:
        add("Laravel", "cookie/HTML markers")
    if "jsessionid" in cookies:
        add("Java application server", "JSESSIONID cookie")
    if "phpsessid" in cookies:
        add("PHP session", "PHPSESSID cookie")
    if "react" in body and "react" not in [name.lower() for name, _ in signals]:
        add("React", "HTML markers")
    if "vue" in body:
        add("Vue.js", "HTML markers")
    if "jquery" in body:
        add("jQuery", "script reference")
    if "cloudflare-nginx" in server:
        add("Cloudflare (nginx origin)", "Server header")
    return signals


# --------------------------------------------------- certificate transparency

async def crt_entries(client, domain: str, timeout: float = 30.0) -> tuple[list[dict], str]:
    """Query crt.sh for certificate log entries. Returns (entries, error)."""
    domain = (domain or "").strip().lower().lstrip("*.")
    if not domain:
        return [], "no domain supplied"
    last_error = "no response"
    # crt.sh accepts both the wildcard form and a plain substring; it also
    # intermittently answers 404/502 under load, so try both before giving up.
    for query in (f"%.{domain}", domain):
        for attempt in range(2):
            try:
                response = await client.get(
                    "https://crt.sh/",
                    params={"q": query, "output": "json"},
                    headers={"Accept": "application/json", "User-Agent": USER_AGENT},
                    timeout=timeout,
                )
                if response.status_code == 200:
                    try:
                        payload = response.json()
                    except ValueError:
                        last_error = "crt.sh returned non-JSON output"
                        await asyncio.sleep(1.0 + attempt)
                        continue
                    if isinstance(payload, list):
                        return payload, ""
                    last_error = "crt.sh returned an unexpected payload"
                    continue
                last_error = f"HTTP {response.status_code}"
                if response.status_code in {429, 502, 503, 504}:
                    await asyncio.sleep(1.5 * (attempt + 1))
                    continue
                break
            except Exception as error:
                last_error = type(error).__name__
                await asyncio.sleep(1.0 + attempt)
    return [], last_error


def crt_names(entries: list[dict], domain: str) -> list[str]:
    domain = (domain or "").lower().lstrip("*.")
    names: set[str] = set()
    for item in entries:
        for name in str(item.get("name_value", "")).splitlines():
            name = name.strip().lower().lstrip("*.")
            if not name:
                continue
            if name == domain or name.endswith("." + domain):
                names.add(name)
    return sorted(names)


# ----------------------------------------------------------------- rdap layer

async def rdap_domain(client, domain: str) -> tuple[dict | None, str]:
    """Fetch registration data using the IANA RDAP bootstrap, no scraping."""
    domain = (domain or "").strip().lower()
    if not domain:
        return None, "no domain supplied"
    urls = [f"https://rdap.org/domain/{domain}"]
    try:
        bootstrap = await client.get("https://data.iana.org/rdap/dns.json", timeout=8)
        if bootstrap.status_code == 200:
            suffix = "." + domain.rsplit(".", 1)[-1]
            for service, suffixes in bootstrap.json().get("services", []):
                if suffix in suffixes:
                    urls.extend(service)
                    break
    except Exception:
        pass
    last = "no registry response"
    for url in dict.fromkeys(urls):
        try:
            response = await client.get(
                url, headers={"Accept": "application/rdap+json, application/json", "User-Agent": USER_AGENT}, timeout=12
            )
            last = f"HTTP {response.status_code}"
            if response.status_code != 200:
                continue
            payload = response.json()
            if isinstance(payload, dict):
                return payload, ""
        except Exception as error:
            last = type(error).__name__
    return None, last


def rdap_entities(payload: dict) -> list[str]:
    """Flatten registrant/registrar entity names for display."""
    names: list[str] = []

    def walk(entities) -> None:
        for entity in entities or []:
            vcard = (entity.get("vcardArray") or [None, []])[1] if entity.get("vcardArray") else []
            for field in vcard or []:
                if isinstance(field, list) and field and field[0] == "fn" and len(field) > 3:
                    names.append(str(field[3]))
            walk(entity.get("entities"))

    walk(payload.get("entities"))
    return list(dict.fromkeys(names))[:6]


# ------------------------------------------------------------ advisories (OSV)

async def osv_query(client, package: str, ecosystem: str, version: str = "", timeout: float = 15.0) -> tuple[list[dict], str]:
    payload: dict = {"package": {"name": package, "ecosystem": ecosystem}}
    if version:
        payload["version"] = version
    try:
        response = await client.post("https://api.osv.dev/v1/query", json=payload, timeout=timeout)
    except Exception as error:
        return [], type(error).__name__
    if response.status_code != 200:
        return [], f"HTTP {response.status_code}"
    try:
        return response.json().get("vulns", []) or [], ""
    except ValueError:
        return [], "invalid JSON from OSV"


def osv_severity(vulnerability: dict) -> tuple[str, str]:
    """Return (severity-label, score-string) from an OSV record."""
    for entry in vulnerability.get("severity", []) or []:
        score = str(entry.get("score", ""))
        if entry.get("type", "").startswith("CVSS"):
            return "CVSS", score
    specific = vulnerability.get("database_specific", {}) or {}
    label = str(specific.get("severity", "")).upper()
    if label:
        return "LABEL", label
    return "", ""


# ------------------------------------------------------- public storage probe

BUCKET_PROVIDERS = {
    "s3": {"url": "https://{name}.s3.amazonaws.com/", "marker": "<ListBucketResult"},
    "gcs": {"url": "https://storage.googleapis.com/{name}/", "marker": "<ListBucketResult"},
    "azure": {"url": "https://{name}.blob.core.windows.net/?comp=list", "marker": "<EnumerationResults"},
}


async def probe_bucket(client, provider: str, name: str, timeout: float = 8.0) -> dict:
    """Classify a bucket name as public / private / absent without listing data."""
    spec = BUCKET_PROVIDERS.get(provider)
    if not spec:
        return {"provider": provider, "name": name, "state": "unsupported"}
    url = spec["url"].format(name=name)
    try:
        response = await client.get(url, headers={"User-Agent": USER_AGENT}, timeout=timeout)
    except Exception as error:
        return {"provider": provider, "name": name, "state": "error", "detail": type(error).__name__}
    body = response.text[:4000] if response.text else ""
    if response.status_code == 200 and spec["marker"] in body:
        return {"provider": provider, "name": name, "state": "public", "status": 200, "url": url}
    if response.status_code in {200, 401, 403}:
        return {"provider": provider, "name": name, "state": "exists-private", "status": response.status_code, "url": url}
    if response.status_code == 404:
        return {"provider": provider, "name": name, "state": "absent", "status": 404}
    return {"provider": provider, "name": name, "state": "unknown", "status": response.status_code, "url": url}


# --------------------------------------------------------- network ownership

async def ip_context(client, address: str, timeout: float = 10.0) -> dict:
    """Public ASN/org/geo context for an address using ipwho.is."""
    try:
        response = await client.get(f"https://ipwho.is/{address}", timeout=timeout, headers={"User-Agent": USER_AGENT})
        payload = response.json()
    except Exception as error:
        return {"error": type(error).__name__}
    if not payload.get("success", True):
        return {"error": str(payload.get("message", "lookup failed"))}
    connection = payload.get("connection", {}) or {}
    return {
        "asn": connection.get("asn"),
        "org": connection.get("org") or connection.get("isp"),
        "isp": connection.get("isp"),
        "country": payload.get("country"),
        "city": payload.get("city"),
        "error": None,
    }


async def asn_prefixes(client, value: str, timeout: float = 15.0) -> tuple[list[str], str]:
    """Announced prefixes for an ASN or an address, via RIPEstat."""
    resource = (value or "").strip().upper()
    if not resource:
        return [], "no ASN or address supplied"
    if not resource.startswith("AS"):
        addresses = resolve_addresses(resource)
        if not addresses:
            return [], f"could not resolve {value}"
        resource = addresses[0]
        try:
            response = await client.get(
                "https://stat.ripe.net/data/network-info/data.json",
                params={"resource": resource},
                timeout=timeout,
                headers={"User-Agent": USER_AGENT},
            )
            payload = response.json().get("data", {}) or {}
            asns = payload.get("asns") or []
            if not asns:
                return [payload.get("prefix", "")] if payload.get("prefix") else [], "no ASN announced for address"
            resource = f"AS{asns[0]}"
        except Exception as error:
            return [], type(error).__name__
    try:
        response = await client.get(
            "https://stat.ripe.net/data/announced-prefixes/data.json",
            params={"resource": resource},
            timeout=timeout,
            headers={"User-Agent": USER_AGENT},
        )
        payload = response.json().get("data", {}) or {}
        prefixes = [str(item.get("prefix")) for item in payload.get("prefixes", []) if item.get("prefix")]
        return prefixes, ""
    except Exception as error:
        return [], type(error).__name__


def now_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
