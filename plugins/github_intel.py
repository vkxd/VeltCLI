"""Public GitHub intelligence through the REST API.

Works anonymously (60 requests/hour) and uses GITHUB_TOKEN from SETTINGS when
configured (5000 requests/hour). Only public data is read.
"""
from __future__ import annotations

import asyncio

from core import netutils as net

from .base import BasePlugin


class GitHubIntel(BasePlugin):
    API = "https://api.github.com"

    async def run_all(self, target):
        return await self.profile(target)

    async def run_sub(self, sub_id, target):
        handlers = {
            "github_profile": self.profile,
            "profile_github": self.profile,
            "github_repos": self.repos,
            "github_org": self.organization,
            "github_commit_emails": self.commit_emails,
        }
        handler = handlers.get(sub_id)
        if handler is None:
            return f"[!] GitHub tool '{sub_id}' is not registered."
        return await handler(target)

    # ------------------------------------------------------------- plumbing

    def _headers(self) -> dict:
        token = self.config.provider_key("github") if self.config is not None else ""
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return headers

    async def _get(self, path: str, params: dict | None = None):
        response, error = await net.get(
            self.client, f"{self.API}{path}", timeout=25, params=params or {}, headers=self._headers()
        )
        if response is None:
            return None, f"request failed ({error})"
        if response.status_code == 404:
            return None, "not found (GitHub answers 404 for missing and private accounts)"
        if response.status_code in {403, 429}:
            remaining = response.headers.get("x-ratelimit-remaining", "?")
            return None, (
                f"rate limited or forbidden (HTTP {response.status_code}, remaining={remaining}). "
                "Add a GITHUB_TOKEN in SETTINGS for 5000 requests/hour"
            )
        if response.status_code != 200:
            return None, f"HTTP {response.status_code}"
        try:
            return response.json(), ""
        except ValueError:
            return None, "GitHub returned invalid JSON"

    @staticmethod
    def _login(target) -> str:
        value = str(target or "").strip().lstrip("@").strip("/")
        if "/" in value:
            value = value.split("/")[0]
        return value

    @staticmethod
    def _repo(target) -> tuple[str, str]:
        value = str(target or "").strip().strip("/")
        if value.endswith(".git"):
            value = value[:-4]
        parts = [part for part in value.split("/") if part]
        if len(parts) < 2:
            return "", ""
        return parts[0], parts[1]

    def _record_identity(self, login: str, payload: dict, platform: str = "github") -> None:
        self.node(login, "username", {"platform": platform})
        for field, typ in (("company", "organization"), ("blog", "url"), ("location", "host")):
            value = str(payload.get(field) or "").strip()
            if value and value.lower() not in {"none", "null"}:
                self.node(value, typ, {"source": platform})
                self.edge(login, value, "related_to", "username", typ)

    # --------------------------------------------------------------- profile

    async def profile(self, target):
        login = self._login(target)
        if not login:
            return "[!] Enter a GitHub username, for example: set target octocat"
        data, error = await self._get(f"/users/{login}")
        if not data:
            return f"[!] GitHub profile lookup for {login} failed: {error}."

        lines = [
            f"[>] GitHub profile: {data.get('login')}",
            f"[+] Type: {data.get('type', 'User')}",
            f"[+] Name: {data.get('name') or 'not published'}",
            f"[+] Company: {data.get('company') or 'not published'}",
            f"[+] Location: {data.get('location') or 'not published'}",
            f"[+] Blog: {data.get('blog') or 'not published'}",
            f"[+] Bio: {(data.get('bio') or 'not published')[:160]}",
            f"[+] Public repos: {data.get('public_repos', 0)} | Gists: {data.get('public_gists', 0)}",
            f"[+] Followers: {data.get('followers', 0)} | Following: {data.get('following', 0)}",
            f"[+] Created: {data.get('created_at', 'unknown')}",
            f"[+] Last updated: {data.get('updated_at', 'unknown')}",
        ]
        self._record_identity(data.get("login", login), data)
        if data.get("email"):
            email = str(data["email"]).strip()
            lines.append(f"[+] Public email: {email}")
            self.node(email.lower(), "email", {"source": "github"})
            self.edge(data.get("login", login), email.lower(), "related_to", "username", "email")

        repos, repo_error = await self._get(f"/users/{login}/repos", {"per_page": 5, "sort": "updated"})
        if repos:
            lines.append("[+] Recently updated repositories:")
            for repo in repos[:5]:
                lines.append(
                    f"    [+] {repo.get('name')} ({repo.get('language') or 'unknown'}, "
                    f"★{repo.get('stargazers_count', 0)}) {repo.get('html_url', '')}"
                )
        elif repo_error and "404" not in repo_error:
            lines.append(f"[!] Repository listing unavailable: {repo_error}")

        self.finding(
            f"GitHub account observed: {data.get('login', login)}",
            f"Public account created {data.get('created_at', 'unknown')} with "
            f"{data.get('public_repos', 0)} public repositories.",
            "INFO", "social", tags=["github", "public-profile"],
        )
        lines.append("[!] Public API data only; no private repositories or emails are accessed.")
        return "\n".join(lines)

    # ---------------------------------------------------------------- repos

    async def repos(self, target):
        login = self._login(target)
        if not login:
            return "[!] Enter a GitHub username."
        data, error = await self._get(f"/users/{login}/repos", {"per_page": 40, "sort": "updated"})
        if not isinstance(data, list) or not data:
            return f"[!] No public repositories could be listed for {login} ({error or 'none published'})."

        languages: dict[str, int] = {}
        for repo in data:
            if repo.get("language"):
                languages[repo["language"]] = languages.get(repo["language"], 0) + 1
        archived = [repo for repo in data if repo.get("archived")]
        lines = [
            f"[>] Public repositories for {login}",
            f"[+] Repositories listed: {len(data)} (showing the {len(data)} most recently updated)",
            f"[+] Languages: {', '.join(f'{name} x{count}' for name, count in sorted(languages.items(), key=lambda i: -i[1])[:8]) or 'none detected'}",
            f"[!] Archived repositories: {len(archived)}",
        ]
        for repo in data[:25]:
            flags = []
            if repo.get("archived"):
                flags.append("archived")
            if repo.get("fork"):
                flags.append("fork")
            lines.append(
                f"[+] {repo.get('name')} | {repo.get('language') or 'unknown'} | "
                f"★{repo.get('stargazers_count', 0)} | forks {repo.get('forks_count', 0)} | "
                f"updated {str(repo.get('pushed_at') or '')[:10]}"
                + (f" | {', '.join(flags)}" if flags else "")
            )
            self.node(repo.get("html_url", repo.get("name", "")), "url", {"language": repo.get("language")})
        if len(data) > 25:
            lines.append(f"[!] {len(data) - 25} more repositories not shown")
        self.finding(
            f"Public repository inventory for {login}",
            f"{len(data)} repositories listed; languages: "
            f"{', '.join(list(languages)[:6]) or 'unknown'}. {len(archived)} archived.",
            "INFO", "asset-inventory", tags=["github", "repository"],
        )
        lines.append("[!] Forks and archived repositories may not reflect current work.")
        return "\n".join(lines)

    # ------------------------------------------------------------ org recon

    async def organization(self, target):
        org = self._login(target)
        if not org:
            return "[!] Enter a GitHub organization name."
        data, error = await self._get(f"/orgs/{org}")
        if not data:
            return f"[!] GitHub organization lookup for {org} failed: {error}."

        lines = [
            f"[>] GitHub organization: {data.get('login', org)}",
            f"[+] Name: {data.get('name') or 'not published'}",
            f"[+] Location: {data.get('location') or 'not published'}",
            f"[+] Blog: {data.get('blog') or 'not published'}",
            f"[+] Public email: {data.get('email') or 'not published'}",
            f"[+] Public repositories: {data.get('public_repos', 0)}",
            f"[+] Created: {data.get('created_at', 'unknown')}",
        ]
        self.node(data.get("login", org), "organization", {"platform": "github"})
        if data.get("email"):
            email = str(data["email"]).lower()
            self.node(email, "email", {"source": "github"})
            self.edge(data.get("login", org), email, "related_to", "organization", "email")
            self.finding(
                f"Organization publishes a contact email: {email}",
                f"GitHub organization {data.get('login', org)} lists {email} publicly.",
                "INFO", "organization", tags=["github", "contact"],
            )

        members, member_error = await self._get(f"/orgs/{org}/members", {"per_page": 40})
        if isinstance(members, list) and members:
            logins = [member.get("login") for member in members if member.get("login")]
            lines.append(f"[+] Public members visible: {len(logins)}")
            lines.extend(f"[+] member: {login}" for login in logins[:20])
            for login in logins[:20]:
                self.node(login, "username", {"platform": "github", "role": "org-member"})
                self.edge(data.get("login", org), login, "contains", "organization", "username")
        elif member_error:
            lines.append(f"[!] Member listing unavailable: {member_error}")

        repos, _repo_error = await self._get(f"/orgs/{org}/repos", {"per_page": 15, "sort": "updated"})
        if isinstance(repos, list) and repos:
            lines.append("[+] Recently updated repositories:")
            for repo in repos[:10]:
                lines.append(
                    f"    [+] {repo.get('name')} ({repo.get('language') or 'unknown'}, "
                    f"★{repo.get('stargazers_count', 0)})"
                )
                self.node(repo.get("html_url", repo.get("name", "")), "url", {"language": repo.get("language")})

        self.finding(
            f"GitHub organization mapped: {data.get('login', org)}",
            f"{data.get('public_repos', 0)} public repositories and "
            f"{len(members) if isinstance(members, list) else 0} publicly listed members.",
            "INFO", "organization", tags=["github", "organization"],
        )
        lines.append("[!] Only publicly visible membership and repositories are listed.")
        return "\n".join(lines)

    # ------------------------------------------------------- commit authors

    async def commit_emails(self, target):
        owner, repo = self._repo(target)
        if not owner or not repo:
            return "[!] Enter a repository as owner/name, for example: octocat/Hello-World"
        commits, error = await self._get(f"/repos/{owner}/{repo}/commits", {"per_page": 100})
        if not isinstance(commits, list) or not commits:
            return f"[!] No public commits could be read for {owner}/{repo} ({error or 'empty repository'})."

        authors: dict[str, set[str]] = {}
        for commit in commits:
            payload = commit.get("commit", {}) or {}
            author = payload.get("author", {}) or {}
            email = str(author.get("email") or "").strip().lower()
            name = str(author.get("name") or "").strip()
            if email:
                authors.setdefault(email, set()).add(name or "unknown")
        lines = [
            f"[>] Public commit identities for {owner}/{repo}",
            f"[+] Commits sampled: {len(commits)}",
            f"[+] Distinct author emails: {len(authors)}",
        ]
        for email, names in sorted(authors.items())[:25]:
            lines.append(f"[+] {email} — {', '.join(sorted(name for name in names if name))[:80]}")
            self.node(email, "email", {"source": "github-commits", "repository": f"{owner}/{repo}"})
            for name in names:
                if name and name != "unknown":
                    self.node(name, "username", {"platform": "github", "role": "commit-author"})
                    self.edge(name, email, "related_to", "username", "email")
        if len(authors) > 25:
            lines.append(f"[!] {len(authors) - 25} more addresses not shown")
        if authors:
            self.finding(
                f"Commit metadata exposes {len(authors)} author email(s)",
                f"Public commits in {owner}/{repo} carry author email addresses. "
                "Use this for defensive audit or authorized research only.",
                "MEDIUM", "exposure", tags=["github", "email", "commit-metadata"],
            )
        lines.append("[!] Commit emails are public history; do not use them for unsolicited contact.")
        return "\n".join(lines)
