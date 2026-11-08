"""Breach awareness and defensive credential-dataset profiling."""
from __future__ import annotations

import hashlib
import math
import os
import re
from collections import Counter
from pathlib import Path

from core import netutils as net

from .base import BasePlugin

COMMON_PASSWORDS = (
    "123456", "password", "12345678", "qwerty", "123456789", "12345", "1234",
    "111111", "1234567", "dragon", "123123", "baseball", "abc123", "football",
    "monkey", "letmein", "696969", "shadow", "master", "666666", "qwertyuiop",
    "123321", "mustang", "1234567890", "michael", "654321", "pussy", "superman",
    "1qaz2wsx", "7777777", "fuckyou", "121212", "000000", "qazwsx", "123qwe",
    "killer", "trustno1", "jordan", "jennifer", "zxcvbnm", "asdfgh", "hunter",
    "buster", "soccer", "harley", "batman", "andrew", "tigger", "sunshine",
    "iloveyou", "fuckme", "2000", "charlie", "robert", "thomas", "hockey",
    "ranger", "daniel", "starwars", "klaster", "112233", "george", "asshole",
    "computer", "michelle", "jessica", "pepper", "1111", "zxcvbn", "555555",
    "11111111", "131313", "freedom", "777777", "pass", "fuck", "maggie",
    "159753", "aaaaaa", "ginger", "princess", "joshua", "cheese", "amanda",
    "summer", "love", "ashley", "6969", "nicole", "chelsea", "biteme", "matthew",
    "access", "yankees", "987654321", "dallas", "austin", "thunder", "taylor",
    "matrix", "welcome", "admin", "root", "toor", "changeme", "secret",
)


class BreachDB(BasePlugin):
    """Breach lookup through configured providers, plus local credential review."""

    async def run_all(self, target):
        return await self.breach_lookup(target)

    async def run_sub(self, sub_id, target):
        if sub_id == "analyze_passwords":
            return self.analyze_password_txt(target)
        if sub_id == "breach_lookup":
            return await self.breach_lookup(target)
        return "[!] Breach tool is not registered."

    # ---------------------------------------------------------- breach lookup

    async def breach_lookup(self, target):
        value = str(target or "").strip()
        if not value:
            return "[!] Enter an email address to check breach exposure."
        key = self.config.provider_key("hibp") if self.config is not None else ""
        if not key:
            return "\n".join([
                f"[>] Breach lookup for {value}",
                "[!] This check needs a Have I Been Pwned API key; none is configured, so nothing was queried.",
                "[>] Add it under SETTINGS (HIBP) or set HIBP_API_KEY in your local .env.",
                "[!] No breach claim was fabricated.",
                "[>] You can also check manually at https://haveibeenpwned.com/",
            ])
        if "@" not in value:
            return "\n".join([
                f"[>] Breach lookup for {value}",
                "[!] Provider lookups are keyed by email address; usernames cannot be resolved reliably.",
                "[>] Provide the full email address you are authorized to check.",
            ])

        response, error = await net.get(
            self.client,
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{value}",
            timeout=20,
            headers={
                "hibp-api-key": key,
                "Accept": "application/json",
                "User-Agent": net.USER_AGENT,
            },
            params={"truncateResponse": "false"},
        )
        if response is None:
            return f"[!] Breach provider request failed ({error})."
        if response.status_code == 404:
            return "\n".join([
                f"[+] HIBP: no breach records were found for {value}.",
                "[!] Absence is not proof of safety; not every breach is public.",
            ])
        if response.status_code == 401:
            return "[!] The configured HIBP key was rejected. Update it in SETTINGS."
        if response.status_code == 429:
            return "[!] HIBP rate limit reached. Wait a minute and try again."
        if response.status_code != 200:
            return f"[!] Breach provider returned HTTP {response.status_code}."

        breaches = response.json() or []
        lines = [
            f"[-] Breach exposure found for {value}: {len(breaches)} breach(es)",
            "[!] Change any reused password and enable MFA on the affected accounts.",
        ]
        names = []
        for breach in breaches:
            name = breach.get("Name", "unknown")
            names.append(name)
            lines.append(
                f"  [-] {name} ({breach.get('BreachDate', 'unknown date')}): "
                f"{breach.get('PwnCount', 0):,} accounts, data classes: "
                f"{', '.join(breach.get('DataClasses', [])[:5]) or 'not published'}"
            )
        self.node(value.lower(), "email")
        self.finding(
            f"Breach exposure recorded for {value}",
            f"Configured providers reported {len(breaches)} breach(es): {', '.join(names[:10])}.",
            "HIGH" if len(breaches) >= 3 else "MEDIUM",
            "breach", tags=["hibp", "breach"],
        )
        lines.append("[!] Provider data is historical; verify current account security directly.")
        return "\n".join(lines)

    # -------------------------------------------------- local credential review

    @staticmethod
    def _entropy_bits(value: str) -> float:
        if not value:
            return 0.0
        pool = 0
        if re.search(r"[a-z]", value):
            pool += 26
        if re.search(r"[A-Z]", value):
            pool += 26
        if re.search(r"\d", value):
            pool += 10
        if re.search(r"[^A-Za-z0-9]", value):
            pool += 32
        return round(len(value) * math.log2(pool), 1) if pool else 0.0

    def analyze_password_txt(self, file_path):
        path = Path(str(file_path or "").strip())
        if not path.is_file():
            return f"[!] File {path} not found. Provide a valid authorized TXT/CSV file path."

        try:
            raw = path.read_text(encoding="utf-8", errors="replace")
        except OSError as error:
            return f"[!] The file could not be read ({type(error).__name__})."
        if len(raw) > 50_000_000:
            return "[!] File is too large for an in-memory defensive review (limit 50 MB)."

        entries = [line.strip() for line in raw.splitlines() if line.strip()]
        if not entries:
            return f"[!] {path.name} contains no non-empty lines to review."

        # A single "user:password" dump is common; keep only the credential part.
        secrets = []
        for entry in entries[:200_000]:
            secret = entry.rsplit(":", 1)[-1] if ":" in entry and len(entry.rsplit(":", 1)[0]) <= 64 else entry
            secrets.append(secret)

        total = len(secrets)
        lengths = [len(value) for value in secrets]
        common_hits = [value for value in secrets if value.lower() in COMMON_PASSWORDS]
        duplicates = Counter(secrets)
        repeated = {value: count for value, count in duplicates.items() if count > 1}
        digit_only = sum(1 for value in secrets if value.isdigit())
        has_upper = sum(1 for value in secrets if re.search(r"[A-Z]", value))
        has_symbol = sum(1 for value in secrets if re.search(r"[^A-Za-z0-9]", value))
        has_digit = sum(1 for value in secrets if re.search(r"\d", value))
        samples = secrets[:20_000]
        avg_entropy = round(sum(self._entropy_bits(value) for value in samples) / len(samples), 1)
        weak = sum(1 for value in samples if len(value) < 8 or self._entropy_bits(value) < 28)
        sha = hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()

        median = sorted(lengths)[total // 2]
        lines = [
            f"[>] Defensive credential-dataset profile: {path.name}",
            f"[+] Entries analyzed: {total:,}",
            f"[+] Length: average {sum(lengths) / total:.1f}, median {median}, shortest {min(lengths)}, longest {max(lengths)}",
            f"[+] Estimated entropy (first {len(samples):,}): average {avg_entropy} bits",
            f"[+] Weak by length/entropy heuristic: {weak:,} ({(weak / len(samples) * 100):.1f}%)",
            f"[+] Contains digits: {has_digit / total * 100:.1f}% | uppercase: {has_upper / total * 100:.1f}% | symbols: {has_symbol / total * 100:.1f}%",
            f"[+] Numeric-only passwords: {digit_only:,}",
            f"[-] Matches in the embedded common-password list: {len(common_hits):,} ({len(common_hits) / total * 100:.1f}%)",
            f"[-] Reused values: {len(repeated):,} distinct secrets account for {sum(repeated.values()) - len(repeated):,} repetitions",
            f"[+] Dataset SHA-256 (for integrity reference): {sha}",
        ]
        if duplicates:
            top = duplicates.most_common(3)
            lines.append("[!] Most repeated values are counted but never printed.")
            lines.append(f"[!] Highest repetition count: {top[0][1]}x")
        lines.extend([
            "",
            "Recommended actions",
            "[+] Rotate the most common and weakest values first, and never reuse a value across services",
            "[+] Enforce a minimum length (12+), block known-breached values, and require MFA",
            "[+] Monitor breach notifications and re-check this dataset after rotation",
            "",
            "[!] This is a defensive policy review only; no login attempts are made and no cracking wordlist is produced.",
            "[!] Password values are never printed, stored, or uploaded by this tool.",
        ])
        if common_hits:
            self.finding(
                "Dataset contains well-known common passwords",
                f"{len(common_hits):,} of {total:,} entries match a public common-password list; reused values: {len(repeated):,}.",
                "HIGH", "credentials", tags=["password-policy", "defensive"],
            )
        elif weak:
            self.finding(
                "Dataset contains weak passwords",
                f"{weak:,} of {len(samples):,} sampled entries look weak by length/entropy.",
                "MEDIUM", "credentials", tags=["password-policy", "defensive"],
            )
        return "\n".join(lines)
