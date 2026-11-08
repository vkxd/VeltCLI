import time

import httpx

from config import ConfigStore
from core.reporting import export_report
from core.services.activity import ActivityService
from core.services.dashboard import DashboardService
from core.services.diagnostics import DoctorService
from core.services.evidence import EvidenceService
from core.services.findings import FindingsService
from core.services.graph import GraphService
from plugins.breach import BreachDB
from plugins.general import GeneralOSINT
from plugins.github_intel import GitHubIntel
from plugins.infra import InfraDNS
from plugins.passive_dns import PassiveDNS
from plugins.shodan_intel import ShodanIntel
from plugins.social import SocialIntel
from plugins.temp_mail import TempMail
from plugins.vuln_finder import VulnFinder
from plugins.wayback import Wayback
from plugins.web_copy import WebsiteCopier

CATEGORY_MODULES = {
    "vuln": "vuln",
    "vulnerability": "vuln",
    "social": "social",
    "infra": "infra",
    "dns": "infra",
    "general": "general",
    "breach": "breach",
    "breaches": "breach",
    "temp": "temp",
    "temps": "temp",
    "web": "general",
    "web_copy": "web_copy",
}

# Catalog entries that always belong to a specific implementation, whatever
# category the UI is showing.
MODULE_OVERRIDES = {
    "website_copy": "web_copy",
    "site_copy": "web_copy",
    # GitHub
    "github_profile": "github",
    "profile_github": "github",
    "github_repos": "github",
    "github_org": "github",
    "github_commit_emails": "github",
    # Wayback Machine
    "wayback_overview": "wayback",
    "wayback_urls": "wayback",
    "wayback_deleted": "wayback",
    # Passive DNS + takeover
    "passive_dns": "passive_dns",
    "sub_passive_dns": "passive_dns",
    "sub_takeover": "passive_dns",
    # Shodan
    "shodan_host": "shodan",
    "shodan_search": "shodan",
}

LEGACY_NOTE = "not registered"


class ScyllaEngine:
    def __init__(self):
        self.config = ConfigStore()
        timeout = float(self.config.setting("request_timeout_seconds", 20))
        self.client = httpx.AsyncClient(timeout=timeout, follow_redirects=True)
        self.findings = FindingsService()
        self.evidence = EvidenceService()
        self.graph = GraphService()
        self.activity = ActivityService()
        self.dashboard = DashboardService(self.findings, self.evidence, self.graph, self.activity)
        self.doctor = DoctorService()
        self.modules = {
            "vuln": VulnFinder(self.client),
            "social": SocialIntel(self.client),
            "infra": InfraDNS(self.client),
            "general": GeneralOSINT(self.client),
            "breach": BreachDB(self.client),
            "temp": TempMail(self.client),
            "web_copy": WebsiteCopier(self.client),
            "github": GitHubIntel(self.client),
            "wayback": Wayback(self.client),
            "passive_dns": PassiveDNS(self.client),
            "shodan": ShodanIntel(self.client),
        }

    # ------------------------------------------------------------- execution

    def _module_for(self, category, module_id) -> str:
        if module_id in MODULE_OVERRIDES:
            return MODULE_OVERRIDES[module_id]
        return CATEGORY_MODULES.get(str(category or "").lower(), "general")

    def _prepare(self, module, values: dict) -> None:
        module.values = values
        module.config = self.config
        module.reset_intel()

    async def run_module(self, category, module_id, target, values=None):
        values = dict(values or {})
        module_key = self._module_for(category, module_id)
        module = self.modules.get(module_key)
        if module is None:
            return f"[!] Unknown module category: {category}"

        self.activity.log("tool_executed", f"Started {category}/{module_id} for {target}")
        self._prepare(module, values)
        started = time.perf_counter()
        try:
            if module_id == "run_all":
                result = await module.run_all(target)
            else:
                result = await module.run_sub(module_id, target)
                # Shared catalog entries can fall through to the general module.
                if isinstance(result, str) and LEGACY_NOTE in result.lower():
                    fallback = self.modules["general"]
                    self._prepare(fallback, values)
                    fallback_result = await fallback.run_sub(module_id, target)
                    if isinstance(fallback_result, str) and "not implemented yet" not in fallback_result.lower():
                        result = fallback_result
                        self._harvest(fallback, module_id, target, result)
                    else:
                        self._harvest(module, module_id, target, result)
                else:
                    self._harvest(module, module_id, target, result)
            module.reset_intel()
            elapsed = round((time.perf_counter() - started) * 1000)
            self.activity.log("tool_completed", f"Completed {category}/{module_id} for {target} in {elapsed} ms")
            return result
        except Exception as error:
            self.activity.log("error", f"{category}/{module_id} failed: {type(error).__name__}")
            return f"[!] Error executing module: {type(error).__name__}: {error}"

    # -------------------------------------------------- intelligence harvest

    def _harvest(self, module, module_id, target, result: str = "") -> None:
        intel = module.intel or {}
        findings = intel.get("findings") or []
        nodes = intel.get("nodes") or []
        edges = intel.get("edges") or []
        if not findings and not nodes and not edges:
            return

        evidence_item = None
        evidence_text = str(result or "").strip()[:1900]
        if evidence_text:
            evidence_item = self.evidence.add(
                "tool_output", f"Structured intelligence from {module_id}", evidence_text, target, module_id
            )
            self.activity.log("evidence_collected", f"Evidence {evidence_item['id']} saved from {module_id}")

        evidence_ids = [evidence_item["id"]] if evidence_item else []
        for entry in findings:
            if self.findings.exists(entry["title"], target):
                continue
            finding = self.findings.add(
                entry["title"], entry["description"], entry["severity"], entry["category"],
                target, evidence_ids, module_id, entry.get("tags") or [],
            )
            self.activity.log("finding_created", f"{finding['title']} ({finding['severity']})")

        node_ids: dict[tuple[str, str], str] = {}
        for entry in nodes:
            stored = self.graph.add_node(entry["label"], entry["type"], entry.get("metadata") or {})
            node_ids[(entry["label"].lower(), entry["type"])] = stored["id"]
        for entry in edges:
            source = node_ids.get((entry["source"].lower(), entry["source_type"]))
            target_node = node_ids.get((entry["target"].lower(), entry["target_type"]))
            if not source:
                source = self.graph.add_node(entry["source"], entry["source_type"], {})["id"]
            if not target_node:
                target_node = self.graph.add_node(entry["target"], entry["target_type"], {})["id"]
            self.graph.add_edge(source, target_node, entry["rel"], {"source": module_id})

    # -------------------------------------------------------------- reporting

    def export(self, result, target, tool):
        paths = export_report(result, target, tool)
        self.activity.log("report_generated", f"Report generated by {tool}")
        return paths

    async def close(self):
        await self.client.aclose()
