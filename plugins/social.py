from __future__ import annotations

import asyncio
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

from core import netutils as net

from .base import BasePlugin

USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
METHOD_ALIASES = {
    "": "auto",
    "auto": "auto",
    "both": "both",
    "s": "sherlock",
    "sh": "sherlock",
    "sherlock": "sherlock",
    "sherlock-project": "sherlock",
    "m": "maigret",
    "mg": "maigret",
    "maigret": "maigret",
}
SOCIAL_SUB_IDS = {
    "sub_sherlock", "sherlock", "maigret", "alias_search",
    "username_search", "username", "sub_username",
}


class SocialIntel(BasePlugin):
    """Public username footprint using the real Sherlock and Maigret engines.

    Sherlock is the default engine. It is executed as a subprocess (module or
    console script), its JSON + text reports are parsed into structured
    results, and each confirmed profile URL is recorded as graph intelligence.
    """

    SHERLOCK_TIMEOUT = 300
    MAIGRET_TIMEOUT = 900
    MAX_LISTED = 150

    # ------------------------------------------------------------- dispatch

    async def run_all(self, target):
        return await self.search(target)

    async def run_sub(self, sub_id, target):
        if sub_id in SOCIAL_SUB_IDS:
            return await self.search(target)
        return "[!] Social tool is not registered."

    async def search(self, target):
        values = getattr(self, "values", {}) or {}
        hint = str(values.get("method") or "").strip().lower()
        target_text = str(target or "").strip()

        # Allow "run sherlock" / "run maigret" straight from the tool prompt.
        if target_text.lower() in METHOD_ALIASES:
            hint = hint or target_text.lower()
            target_text = ""

        username = str(values.get("username") or target_text).strip().lstrip("@")
        if " " in username:
            username = username.split()[0]
        if not username:
            return "[!] Provide one public username, for example: set username example"
        if not USERNAME_PATTERN.match(username):
            return (
                "[!] Invalid username. Use 1-64 characters of letters, digits, dot, "
                "underscore or hyphen; never enter a password or an email address."
            )

        method = METHOD_ALIASES.get(hint)
        if method is None:
            return f"[!] Unknown search method '{hint}'. Use: sherlock, maigret, auto, or both."

        sherlock, maigret = self._sherlock_command(), self._maigret_command()
        if method == "auto":
            # Sherlock is the default: fast, no API key, and installed via requirements.
            method = "sherlock" if sherlock[0] else "maigret" if maigret[0] else ""
            if not method:
                return self._missing_engine(username)
        if method == "sherlock" and not sherlock[0]:
            method = "maigret" if maigret[0] else ""
            if not method:
                return self._missing_engine(username)
        if method == "maigret" and not maigret[0]:
            method = "sherlock" if sherlock[0] else ""
            if not method:
                return self._missing_engine(username)

        if method == "both":
            parts = []
            if sherlock[0]:
                parts.append(await self._run_sherlock(username, sherlock))
            if maigret[0]:
                parts.append(await self._run_maigret(username, maigret))
            if not parts:
                return self._missing_engine(username)
            return "\n\n".join(parts)

        if method == "sherlock" and sherlock[0]:
            return await self._run_sherlock(username, sherlock)
        return await self._run_maigret(username, maigret)

    # --------------------------------------------------------- engine setup

    @staticmethod
    def _sherlock_command() -> tuple[list[str], str]:
        if importlib.util.find_spec("sherlock_project") is not None:
            return [sys.executable, "-m", "sherlock_project"], "python -m sherlock_project"
        executable = shutil.which("sherlock")
        if executable:
            return [executable], executable
        return [], ""

    @staticmethod
    def _maigret_command() -> tuple[list[str], str]:
        if importlib.util.find_spec("maigret") is not None:
            return [sys.executable, "-m", "maigret"], "python -m maigret"
        executable = shutil.which("maigret")
        if executable:
            return [executable], executable
        return [], ""

    @staticmethod
    def _output_dir(engine: str) -> Path:
        base = Path(os.environ.get("VELT_OUTPUT_DIR", "outputs")) / "username_checks" / engine
        base.mkdir(parents=True, exist_ok=True)
        return base

    @staticmethod
    def _missing_engine(username: str) -> str:
        return "\n".join([
            "[!] Neither Sherlock nor Maigret is installed, so no username search was run.",
            "[>] Install Sherlock (recommended, no API key): pip install sherlock-project",
            "[>] Install Maigret (larger site database): pip install maigret",
            f"[>] Then run again: set username {username} | run",
            "[!] No results were invented.",
        ])

    async def _invoke(self, command: list[str], timeout: int) -> tuple[subprocess.CompletedProcess | None, bool]:
        """Run a CLI engine off the event loop. Returns (process, timed_out)."""

        def run():
            env = os.environ.copy()
            env.update({"PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1", "NO_COLOR": "1"})
            return subprocess.run(
                command, capture_output=True, text=True, encoding="utf-8",
                errors="replace", env=env, timeout=timeout,
            )

        try:
            return await asyncio.to_thread(run), False
        except subprocess.TimeoutExpired:
            return None, True
        except FileNotFoundError:
            return None, False
        except OSError:
            return None, False

    # -------------------------------------------------------------- sherlock

    async def _run_sherlock(self, username: str, engine: tuple[list[str], str]) -> str:
        command_base, label = engine
        output_dir = self._output_dir("sherlock")
        text_report = output_dir / f"{username}.txt"
        try:
            text_report.unlink()
        except OSError:
            pass

        per_site = int((getattr(self, "config", None) and self.config.setting("sherlock_site_timeout", 15)) or 15)
        # ``--json`` means "load a data file" in Sherlock 0.16.0 and only writes
        # results in later releases, so the stable contract is the text report
        # plus --print-found on stdout (which carries the platform names).
        command = [
            *command_base, username,
            "--output", str(text_report),
            "--print-found", "--no-color",
            "--timeout", str(per_site),
        ]
        sites = str((getattr(self, "values", {}) or {}).get("site") or "").strip()
        for site in [item.strip() for item in sites.split(",") if item.strip()]:
            command.extend(["--site", site])

        completed, timed_out = await self._invoke(command, self.SHERLOCK_TIMEOUT)
        if timed_out:
            partial = self._sherlock_results(text_report, "", username)
            head = [f"[!] Sherlock exceeded {self.SHERLOCK_TIMEOUT}s and was stopped."]
            if partial:
                head.append(f"[+] Partial results recovered from the report file: {len(partial)} profiles.")
            head.append(f"[>] Narrow it with: set site github,twitter (then run again)")
            return "\n".join(head) + ("\n" + self._render(f"Sherlock (partial)", username, partial, output_dir, {}, None) if partial else "")

        results = self._sherlock_results(
            text_report, (completed.stdout or "") if completed else "", username
        )

        if completed is None:
            return self._missing_engine(username)
        if not results:
            return self._sherlock_failure(completed, username, output_dir, text_report)

        live = await self._probe_profiles(results)
        return self._render("Sherlock", username, results, output_dir, {
            "declared": self._sherlock_declared(completed.stdout or ""),
            "version": self._sherlock_version(),
        }, completed, live)

    @staticmethod
    def _sherlock_version() -> str:
        """Installed sherlock-project version, read from package metadata."""
        try:
            from importlib.metadata import version
            return version("sherlock-project")
        except Exception:
            return ""

    def _sherlock_results(self, text_report: Path, stdout: str, username: str) -> dict[str, tuple[str, str]]:
        """Merge Sherlock's text report with its --print-found stdout."""
        results: dict[str, tuple[str, str]] = {}

        # "Site: https://url" lines carry the human-readable platform names.
        seen_urls: set[str] = set()
        for line in stdout.splitlines():
            # Platform names are free-form (unicode, digits, dots), so anchor on
            # the first ": http" instead of restricting the name characters.
            match = re.match(r"^\s*(?:\[\+\]\s*)?(.{1,80}?):\s*(https?://\S+)\s*$", line)
            if not match:
                continue
            site, url = match.group(1).strip(), match.group(2).strip()
            if site.lower().startswith(("http", "checking", "search")):
                continue
            results.setdefault(site, (url, "Claimed"))
            seen_urls.add(url.rstrip("/").lower())

        if text_report.exists():
            for line in text_report.read_text(encoding="utf-8", errors="replace").splitlines():
                url = line.strip()
                if not url.startswith(("http://", "https://")):
                    continue
                key = url.rstrip("/").lower()
                if key in seen_urls:
                    continue  # already counted with its platform name
                seen_urls.add(key)
                results.setdefault(self._site_from_url(url, username), (url, "Claimed"))
        return results

    @staticmethod
    def _site_from_url(url: str, username: str) -> str:
        host = net.host_of(url) or url
        return host.removeprefix("www.")

    @staticmethod
    def _sherlock_declared(stdout: str) -> int:
        match = re.search(r"Search completed with (\d+) results", stdout)
        return int(match.group(1)) if match else 0

    def _sherlock_failure(self, completed, username: str, output_dir: Path, report: Path) -> str:
        details = ((completed.stderr or "") + "\n" + (completed.stdout or "")).strip()
        if completed.returncode != 0:
            if "No module named" in details:
                return self._missing_engine(username)
            return "\n".join([
                "[!] Sherlock exited with an error and produced no results.",
                details[-2000:] or "No output returned.",
                f"[>] Try a direct run to confirm the install: sherlock {username} --print-found",
                "[!] No results were invented.",
            ])
        return "\n".join([
            f"[!] Sherlock completed but confirmed no public profiles for {username}.",
            f"[>] Report folder: {output_dir}",
            "[>] Try method maigret for a larger site database: set method maigret",
        ])

    # --------------------------------------------------------------- maigret

    async def _run_maigret(self, username: str, engine: tuple[list[str], str]) -> str:
        command_base, _label = engine
        output_dir = self._output_dir("maigret")
        command = [
            *command_base, username,
            "--json", "ndjson",
            "--folderoutput", str(output_dir),
            "--no-progressbar",
        ]
        completed, timed_out = await self._invoke(command, self.MAIGRET_TIMEOUT)
        if timed_out:
            return f"[!] Maigret exceeded {self.MAIGRET_TIMEOUT}s and was stopped. Try method sherlock for a faster run."
        if completed is None:
            return self._missing_engine(username)

        results, checked = self._maigret_results(output_dir, username)
        if not results:
            details = ((completed.stderr or "") + "\n" + (completed.stdout or "")).strip()
            if completed.returncode != 0 and not details:
                return self._missing_engine(username)
            return "\n".join([
                f"[!] Maigret confirmed no public profiles for {username}.",
                (details[-1500:] if details else "[>] No engine output was returned."),
                "[>] Try method sherlock: set method sherlock",
            ])
        live = await self._probe_profiles(results)
        return self._render("Maigret", username, results, output_dir, {"checked": checked, "declared": len(results)}, completed, live)

    def _maigret_results(self, output_dir: Path, username: str) -> tuple[dict[str, tuple[str, str]], int]:
        results: dict[str, tuple[str, str]] = {}
        checked = 0
        candidates = sorted(
            (path for path in output_dir.glob("*.json*") if username.lower() in path.name.lower()),
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )[:4]
        if not candidates:
            candidates = sorted(output_dir.glob("*.json*"), key=lambda path: path.stat().st_mtime, reverse=True)[:4]

        entries: list[tuple[str, dict]] = []
        for path in candidates:
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if path.suffix == ".ndjson" or path.name.endswith(".ndjson"):
                for line in text.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    for site, payload in (record.items() if isinstance(record, dict) else []):
                        if isinstance(payload, dict):
                            entries.append((str(site), payload))
            else:
                try:
                    data = json.loads(text)
                except json.JSONDecodeError:
                    continue
                sites = data.get("sites", data) if isinstance(data, dict) else {}
                if isinstance(sites, dict):
                    entries.extend((str(site), payload) for site, payload in sites.items() if isinstance(payload, dict))

        for site, payload in entries:
            checked += 1
            raw = payload.get("status")
            status = str(raw.get("status") if isinstance(raw, dict) else raw or "").strip()
            url = str(payload.get("url_user") or (raw.get("url") if isinstance(raw, dict) else "") or "")
            if url and status.lower() in {"claimed", "found", "true"}:
                results[site] = (url, status)
        return results, checked

    # ---------------------------------------------------------------- render

    async def _probe_profiles(self, results: dict[str, tuple[str, str]]) -> dict[str, str]:
        """Confirm sampled profile URLs still answer (bounded and polite)."""
        sample = [url for url, _status in list(results.values())[:30]]
        if not sample:
            return {}

        async def probe(url: str):
            response, error = await net.get(self.client, url, timeout=10)
            if response is None:
                return url, f"unreachable ({error})"
            return url, f"HTTP {response.status_code}"

        states = await net.gather_limited((probe(url) for url in sample), limit=6)
        live: dict[str, str] = {}
        for result in states:
            if isinstance(result, Exception):
                continue
            url, state = result
            live[url] = state
        return live

    def _render(self, engine: str, username: str, results: dict[str, tuple[str, str]],
                output_dir: Path, counts: dict, completed=None, live: dict[str, str] | None = None) -> str:
        ordered = sorted(results.items(), key=lambda item: item[0].lower())
        declared = counts.get("declared") or 0
        checked = counts.get("checked") or 0

        lines = [
            f"[>] {engine} public username search: {username}",
            f"[+] Engine: {engine}" + (f" {counts['version']}" if counts.get("version") else ""),
            "[!] Results are public-page matches, not proof of identity or account ownership.",
            f"[+] Confirmed public profiles: {len(ordered)}",
        ]
        if checked:
            lines.append(f"[+] Sites checked: {checked}")
        if declared and declared != len(ordered):
            lines.append(f"[+] Engine reported: {declared} results")
        if live:
            responding = sum(1 for state in live.values() if state.startswith(("HTTP 2", "HTTP 3")))
            lines.append(f"[+] Live URL check: {responding} of {len(live)} sampled profiles still respond")

        for site, (url, status) in ordered[: self.MAX_LISTED]:
            state = (live or {}).get(url, "")
            suffix = ""
            if state:
                suffix = " [verified]" if state.startswith(("HTTP 2", "HTTP 3")) else f" [{state}]"
            lines.append(f"[+] {site}: {url}{suffix}")
        if len(ordered) > self.MAX_LISTED:
            lines.append(f"[!] {len(ordered) - self.MAX_LISTED} more results are in the report file.")

        lines.extend([
            f"[>] Report folder: {output_dir}",
            "[>] Compare engines for coverage: set method both",
        ])

        # Structured intelligence for the evidence/graph/finding stores.
        self.node(username, "username", {"engine": engine})
        for site, (url, status) in ordered:
            self.node(url, "url", {"site": site, "status": status, "engine": engine})
            self.edge(username, url, "related_to", "username", "url")
        self.finding(
            f"Public username footprint: {username}",
            f"{engine} matched {len(ordered)} public profiles for the username '{username}'. "
            "These are leads for authorized research, not proof of identity.",
            "INFO", "social", tags=[engine.lower(), "username", "public-profile"],
        )
        return "\n".join(lines)
