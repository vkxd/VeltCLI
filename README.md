

```text
 ██▒   █▓ ▓█████  ██▓   ▄▄▄█████▓                       
▓██░   █▒ ▓█   ▀ ▓██▒   ▓  ██▒ ▓▒
 ▓██  ▒░ ▒███   ▒██░   ▒ ▓██░ ▒░
  ▒██ █░░ ▒▓█  ▄ ▒██░   ░ ▓██▓ ░                          | 
   ▒▀█░  ▒░▒████▒░██████  ▒██▒ ░
   ░ ▐░  ░░░ ▒░ ░░ ▒░▓    ▒ ░░
   ░ ░░  ░ ░ ░  ░░ ░ ▒      ░
     ░░      ░     ░ ░
      ░  ░   ░  ░    ░
```
### Terminal-based OSINT & defensive security research toolkit.

**VeltCLI** brings reconnaissance, security checks, public-information research, and reporting into one CLI-driven interface.

> 🔎 **Research. Analyze. Verify.**

[![Status](https://img.shields.io/badge/status-work%20in%20progress-orange)](https://github.com/vkxd/VeltCLI)
[![License](https://img.shields.io/badge/license-MIT-blue)](https://github.com/vkxd/VeltCLI)
[![Python](https://img.shields.io/badge/python-3.x-yellow)](https://www.python.org/)

---

## 🖥️ Preview

<!-- Replace this with a real screenshot/GIF -->

<p align="center">
  <img width="1879" height="948" alt="image" src="https://github.com/user-attachments/assets/b30c6c74-8f23-46a5-8f6f-e85358fdcc03" />

</p>

---

## ✦ What is VeltCLI?

VeltCLI is an **all-in-one terminal security research workspace**.

Instead of jumping between dozens of tools, VeltCLI organizes common research workflows into a single interface.

```text
┌─ VeltCLI
│
├── Vulnerability
├── DNS
├── Web Security
├── Social
├── Email
├── IP Intelligence
├── Cloud
├── People
├── News
├── Business
├── Geospatial
├── Images
├── Documents
├── Monitoring
├── Breaches
└── Temporary Mail
```

---

## 🚀 Features

| Category           | Capabilities                                     |
| ------------------ | ------------------------------------------------ |
| 🌐 Web Security    | Headers, redirects, uptime, public-page analysis |
| 🧬 DNS             | DNS records, SPF, DMARC, DNSSEC, ASN, passive DNS |
| 🔍 Vulnerability   | CVE research, secret scan, takeover, exposure     |
| 🐙 GitHub          | Profiles, organizations, repositories, commits   |
| 🗄️ Archive         | Wayback history, archived URLs, removed pages    |
| 👤 Social          | Public username discovery                        |
| 📧 Email           | Domain security & header analysis                |
| 🌎 IP Intelligence | Resolution, reverse DNS & network context        |
| ☁️ Cloud           | CDN, storage, origin & Shodan host analysis      |
| 📰 News            | Article research & source comparison             |
| 🗺️ Geospatial     | Public location & coordinate research            |
| 🖼️ Images         | Metadata, hashes & OCR workflows                 |
| 📄 Documents       | Metadata & text extraction                       |
| 📡 Monitoring      | Uptime & certificate monitoring                  |
| 📊 Reporting       | JSON, CSV & Markdown exports                     |

---

## ⚡ Quick Start

### 1. Clone

```bash
git clone https://github.com/vkxd/VeltCLI.git
cd VeltCLI
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Launch

```bash
python main.py
```

---

## 🎮 How It Works

VeltCLI uses a simple **category → tool → CLI** workflow.

```text
Category
   ↓
Tool
   ↓
Configure
   ↓
Run
   ↓
Results
   ↓
Export
```

Example:

```text
/help
set target https://example.com
run
```

Export results whenever you need:

```text
export json
export csv
export md
```

Reports are stored in:

```text
outputs/
```

---

## 🧩 Example Tools

### Username Research

Sherlock runs by default (`sherlock-project` is pinned in `requirements.txt`), and
its per-platform results are parsed rather than dumped:

```text
set username example_user    # method defaults to sherlock
run
```

```text
set method sherlock          # default: fast, no API key
set method maigret           # larger site database
set method both              # run both and compare coverage
set site github,twitter      # optional: narrow Sherlock's site list
run sherlock                 # one-off: force Sherlock regardless of method
```

Each run reports the engine and version, the confirmed profile count, one URL per
platform, and the saved report folder. Confirmed profiles are also recorded as
graph nodes plus a single INFO finding, so the evidence trail stays consistent.

> Results are **leads**, not proof of identity.

### Security Headers

```text
set target https://example.com
run
```

Checks headers such as:

```text
Content-Security-Policy
Strict-Transport-Security
X-Frame-Options
Referrer-Policy
Permissions-Policy
```

Each run now scores the header set (0–100 with a letter grade), reports whether
the CSP contains `unsafe-inline`/`unsafe-eval`, and counts cookies set on the
response.

### DNS Research

```text
set target example.com
run
```

Can inspect:

```text
A / AAAA
MX
SPF
DMARC
DNSSEC
Nameservers
Reverse DNS
```

DNS runs also report the detected DNS and mail provider, whether wildcard DNS is
enabled, which email-security records exist, and the published CAA policy.

### GitHub Research

Public API only, no key required (rate limited to 60 requests/hour):

```text
set target octocat                 # profile: dates, company, links, repos
set target github                  # organization: members and repositories
set target octocat/Hello-World     # commit author identities
```

### Archive Research

```text
set target https://example.com
run                                # history span and capture count
```

Three archive tools are available: an overview, a URL list that flags
sensitive-looking paths (`backup`, `config`, `.sql`), and a check that compares
sampled archived URLs against the live site to find pages that are gone now.

### Passive DNS & Subdomain Takeover

```text
set target example.com
run
```

Passive DNS adds third-party hostnames without touching the target. The takeover
check follows CNAMEs and looks for provider placeholder pages that could be
claimed; findings are always marked for manual confirmation.

### Shodan Host Intel

```text
set target 1.1.1.1
run
```

Works without a key through Shodan's free InternetDB snapshot (ports, hostnames,
CPEs, tags, cached CVEs). Adding a `SHODAN_API_KEY` in settings unlocks banners,
history, and the Shodan search tool; without it the search tool says so instead
of inventing results.

---

## 🏗️ Project Structure

```text
VeltCLI/
├── core/          # Core application logic
├── plugins/       # VeltCLI tools & modules
├── ui/            # Terminal interface
├── docs/          # Documentation & assets
├── main.py        # Entry point
├── config.py      # Configuration
├── requirements.txt
└── outputs/       # Generated reports
```

---

## 🔌 API Providers

VeltCLI can optionally integrate with external providers such as:

* Shodan
* Have I Been Pwned
* GitHub
* Search providers
* Geocoding providers
* NVD / CVE providers

API keys are stored locally and masked in the interface.

---

## 🛡️ Safety

VeltCLI is designed for **lawful OSINT and defensive security research**.

It does **not**:

* ❌ Perform DDoS attacks
* ❌ Exploit vulnerabilities
* ❌ Test passwords against accounts
* ❌ Bypass CAPTCHAs or rate limits
* ❌ Access private profiles
* ❌ Track people in real time
* ❌ Claim public accounts belong to the same person

Use VeltCLI only against systems, data, and services you're authorized to research.

---

## ⚠️ Results ≠ Proof

VeltCLI produces **research leads and configuration guidance**.

Results can be affected by:

* Rate limits
* Blocked requests
* Missing API keys
* Network failures
* Incomplete public data
* False positives
* Provider changes

**Verify important findings manually.**

---

## 🗺️ Roadmap

* [x] Modular CLI architecture
* [x] Category-based interface
* [x] Export system
* [x] DNS research
* [x] Web security checks
* [x] Username research
* [ ] More plugins
* [ ] Improved reporting
* [ ] Plugin marketplace
* [ ] Better configuration system
* [ ] Expanded provider support

---

## 📜 License

VeltCLI is released under the **MIT License**.

---

<div align="center">

### ⚡ VeltCLI

**OSINT • Security Research • Reconnaissance**

Built by **[@vkxd](https://github.com/vkxd)**

⭐ Star the repo if you find it useful.

</div>
