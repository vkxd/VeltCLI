import re
from typing import Dict

from rich.text import Text
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Input, RichLog, Static

from config import PROVIDER_ENV
from ui.catalog import CATEGORIES, CategorySpec, ToolSpec
from core.services.findings import SEVERITIES


ENGINE_CATEGORIES = {
    "vulnerability": "vuln",
    "dns": "infra",
    "web": "general",
    "social": "social",
    "email": "general",
    "ip": "general",
    "cloud": "general",
    "people": "general",
    "news": "general",
    "business": "general",
    "geospatial": "general",
    "images": "general",
    "documents": "general",
    "monitoring": "general",
    "breaches": "breach",
    "temps": "temp",
    "web_copy": "web_copy",
}


def style_output_line(line: str) -> Text:
    styled = Text(line)
    colors = {"[+]": "#73d6a2", "[-]": "#ff6b7a", "[!]": "#f4c95d"}
    for match in re.finditer(r"\[\+\]|\[-\]|\[!\]", line):
        styled.stylize(colors[match.group()], match.start(), match.end())
    return styled


# Fields an engine can default sensibly, so the operator is not forced to fill them.
OPTIONAL_FIELDS = {"method", "site"}

RISK_COLORS = {
    "low": "#73d6a2",
    "medium": "#f4c95d",
    "high": "#ff6b7a",
}


def make_tool_button_label(tool: ToolSpec, fields: str) -> Text:
    label = Text()
    label.append(f"> {tool.key}", style="bold white")
    label.append("\n")
    label.append(f"  {tool.name} | inputs: {fields} | risk: ", style="white")
    risk_color = RISK_COLORS.get(tool.risk, "#f4c95d")
    label.append(tool.risk, style=f"bold {risk_color}")
    label.append("\n")
    label.append(f"  {tool.description}", style="#7f8b99")
    return label


def find_category(key: str) -> CategorySpec:
    return next(category for category in CATEGORIES if category.key == key)


def find_tool(category: CategorySpec, key: str) -> ToolSpec:
    return next(tool for tool in category.tools if tool.key == key)


class MainMenu(Screen):
    """Discord-style workspace: categories stay pinned on the left, tools on the right."""

    def __init__(self, engine):
        super().__init__()
        self.engine = engine
        self.selected_category = CATEGORIES[0].key
        self._tool_buttons: Dict[str, ToolSpec] = {}

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static(
            "██    ██ ███████ ██      ████████ \n"
            "██    ██ ██      ██         ██    \n"
            "██    ██ █████   ██         ██    \n"
            " ██  ██  ██      ██         ██    \n"
            "  ████   ███████ ███████    ██    ",
            id="brand-art",
        )
        yield Static('✦ ALL IN 1 OSINT TOOL ✦  |  run "help" in any tool to see what it actually does', id="brand-subtitle")
        yield Static(f"[ STATUS: READY ]  [ CATALOG: {sum(len(c.tools) for c in CATEGORIES)} TOOLS ]", id="status-bar")
        with Horizontal(id="category-workspace"):
            with Vertical(id="category-sidebar"):
                yield Static("CATEGORIES", id="sidebar-title")
                with VerticalScroll(id="category-list"):
                    for category in CATEGORIES:
                        yield Button(
                            f" {category.name}",
                            id=f"category-{category.key}",
                            classes="category-card",
                        )
                yield Button("◈ DASHBOARD", id="dashboard", classes="secondary-button")
                yield Button("◇ GRAPH", id="graph", classes="secondary-button")
                yield Button("▣ EVIDENCE", id="evidence", classes="secondary-button")
                yield Button("⌁ ACTIVITY", id="activity", classes="secondary-button")
                yield Button("✓ DOCTOR", id="doctor", classes="secondary-button")
                yield Button("⚙ SETTINGS", id="settings", classes="secondary-button")
            with Vertical(id="tool-directory"):
                yield Static("SELECT A CATEGORY", classes="screen-title", id="directory-title")
                yield Static("Choose a category from the left to view its tools.", classes="muted", id="directory-description")
                for category in CATEGORIES:
                    with VerticalScroll(
                        id=f"category-panel-{category.key}",
                        classes="category-panel",
                    ):
                        yield Static("TOOLS", classes="panel-title")
                        for tool in category.tools:
                            fields = ", ".join(name for name, _, _ in tool.fields) or "no input required"
                            button_id = f"tool-{tool.key.replace('-', '_')}"
                            if button_id in self._tool_buttons:
                                button_id = f"{button_id}-{category.key}"
                            self._tool_buttons[button_id] = tool
                            yield Button(
                                make_tool_button_label(tool, fields),
                                id=button_id,
                                classes="tool-card",
                            )
        yield Footer()

    def on_mount(self) -> None:
        self._show_category(self.selected_category)

    def _show_category(self, category_key: str) -> None:
        category = find_category(category_key)
        self.selected_category = category.key
        self.query_one("#directory-title", Static).update(f"{category.key}")
        self.query_one("#directory-description", Static).update(category.description)
        for candidate in CATEGORIES:
            panel = self.query_one(f"#category-panel-{candidate.key}")
            panel.styles.display = "block" if candidate.key == category.key else "none"
            button = self.query_one(f"#category-{candidate.key}", Button)
            button.set_class(candidate.key == category.key, "active")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id or ""
        if button_id.startswith("category-"):
            self._show_category(button_id.removeprefix("category-"))
        elif button_id == "settings":
            self.app.push_screen(SettingsScreen(self.engine))
        elif button_id == "dashboard":
            self.app.push_screen(IntelligenceScreen(self.engine, "dashboard"))
        elif button_id == "graph":
            self.app.push_screen(IntelligenceScreen(self.engine, "graph"))
        elif button_id == "evidence":
            self.app.push_screen(IntelligenceScreen(self.engine, "evidence"))
        elif button_id == "activity":
            self.app.push_screen(IntelligenceScreen(self.engine, "activity"))
        elif button_id == "doctor":
            self.app.push_screen(IntelligenceScreen(self.engine, "doctor"))
        elif button_id in self._tool_buttons:
            tool = self._tool_buttons[button_id]
            self.app.push_screen(ToolCli(self.engine, find_category(self.selected_category), tool))


class ToolMenu(Screen):
    def __init__(self, engine, category: CategorySpec):
        super().__init__()
        self.engine = engine
        self.category = category

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static(f"VELT / {self.category.key}", classes="screen-title")
        yield Static(self.category.description, classes="muted")
        with VerticalScroll(id="tool-screen"):
            yield Static("SELECT A TOOL", classes="panel-title")
            for tool in self.category.tools:
                fields = ", ".join(name for name, _, _ in tool.fields) or "no input required"
                yield Button(make_tool_button_label(tool, fields), id=f"tool-{tool.key.replace('-', '_')}", classes="tool-card")
        yield Button("BACK TO CATEGORIES", id="back-categories", classes="secondary-button")
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id or ""
        if button_id == "back-categories":
            self.app.pop_screen()
        elif button_id.startswith("tool-"):
            key = button_id.removeprefix("tool-").replace("_", "-")
            self.app.push_screen(ToolCli(self.engine, self.category, find_tool(self.category, key)))


class ToolCli(Screen):
    def __init__(self, engine, category: CategorySpec, tool: ToolSpec):
        super().__init__()
        self.engine = engine
        self.category = category
        self.tool = tool
        self.values: Dict[str, str] = {}
        self.status = "READY"
        self._animation_timer = None
        self._animation_index = 0
        self.output_lines = [
            f"[+] Selected tool: {category.key}/{tool.key}",
            f"[+] {tool.description}",
            "[>] Run 'help' to learn what this tool does.",
        ]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static(f"VELT / {self.category.key} / {self.tool.key}", classes="screen-title")
        yield Static(self.tool.description, classes="muted")
        yield Static("[ STATUS: READY ]", id="tool-status")
        with Vertical(id="cli-layout"):
            yield RichLog(id="tool-log", highlight=True, markup=False, wrap=True)
            with Horizontal(id="tool-command-row"):
                yield Static(f"velt ({self.category.key}/{self.tool.key})>", id="tool-prompt-label")
                yield Input(placeholder=self._placeholder(), id="tool-command-input")
        yield Button("BACK TO TOOLS", id="back-tools", classes="secondary-button")
        yield Footer()

    def on_mount(self) -> None:
        self._render_log()
        self.query_one("#tool-command-input", Input).focus()

    def _placeholder(self) -> str:
        return "run | help | back" if not self.tool.fields else f"set {self.tool.fields[0][0]} <value> | run | help | back"

    def _render_log(self) -> None:
        log = self.query_one("#tool-log", RichLog)
        log.clear()
        for line in self.output_lines:
            log.write(style_output_line(line))

    def _update_status(self) -> None:
        values = ", ".join(f"{key}={value}" for key, value in self.values.items()) or "no inputs set"
        self.query_one("#tool-status", Static).update(f"[ STATUS: {self.status} ]  [ {values} ]")

    def _animate(self) -> None:
        if not self.output_lines or not self.output_lines[-1].startswith("[>] Working"):
            self.output_lines.append("[>] Working")
        self._animation_index = (self._animation_index % 3) + 1
        self.output_lines[-1] = "[>] Working" + "." * self._animation_index
        self._render_log()
        self.query_one("#tool-log", RichLog).scroll_end(animate=False)

    def _start_animation(self) -> None:
        self._stop_animation()
        self._animation_index = 0
        self.output_lines.append("[>] Working.")
        self._render_log()
        self._animation_timer = self.set_interval(0.35, self._animate)

    def _stop_animation(self) -> None:
        if self._animation_timer is not None:
            self._animation_timer.pause()
            self._animation_timer = None
        self.output_lines = [line for line in self.output_lines if not line.startswith("[>] Working")]

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        command = event.value.strip()
        event.input.value = ""
        if command:
            await self.execute_command(command)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "back-tools":
            self._stop_animation()
            self.app.pop_screen()

    async def execute_command(self, command: str) -> None:
        parts = command.split()
        action = parts[0].lower().removeprefix("/") if parts else ""
        self.output_lines.append(f"velt ({self.category.key}/{self.tool.key})> {command}")
        if action == "help":
            self._write_help()
        elif action == "list":
            self._list_providers()
        elif action == "back":
            self._stop_animation()
            self.app.pop_screen()
            return
        elif action == "clear":
            self.output_lines.clear()
        elif action == "set" and len(parts) >= 3:
            self._set_value(parts[1].lower(), " ".join(parts[2:]))
        elif action == "run":
            run_mode = parts[1].lower() if len(parts) > 1 else ""
            await self._run_tool(run_mode)
        elif action == "export":
            self._export_report(parts[1].lower() if len(parts) > 1 else "json")
        else:
            self.output_lines.append("[!] Unknown command. Type 'help' for this tool's commands.")
        self._render_log()
        self._update_status()

    def _list_providers(self) -> None:
        """List available providers for tools that support them (e.g., tempmail)."""
        from plugins.temp_mail import TempMail
        providers = TempMail.PROVIDERS
        self.output_lines.extend([
            "",
            "AVAILABLE PROVIDERS",
            "─" * 40,
        ])
        for p in providers:
            if p == "fake.legal":
                self.output_lines.append(f"  [+] {p:15} Fast, no extra dependencies")
            elif p == "mail.tm":
                self.output_lines.append(f"  [+] {p:15} Fast, no extra dependencies")
            elif p == "maildrop":
                self.output_lines.append(f"  [!] {p:15} Requires Selenium + Chrome")
            else:
                self.output_lines.append(f"  [!] {p}")
        self.output_lines.extend([
            "─" * 40,
            "",
            "Usage: set provider <name>",
        ])

    def _write_help(self) -> None:
        risk_label = {
            "low": "[+] low",
            "medium": "[!] medium",
            "high": "[-] high",
        }.get(self.tool.risk, f"[!] {self.tool.risk}")
        self.output_lines.extend([
            "",
            "═" * 50,
            "ABOUT THIS TOOL",
            "═" * 50,
            "",
            f"What it does:  {self.tool.what_it_does}",
            "",
            f"Why it matters:  {self.tool.why_it_matters}",
            "",
            f"Limitations:  {self.tool.limitations}",
            "",
            f"Risk level:  {risk_label}",
            "",
            "─" * 50,
            "COMMANDS",
            "─" * 50,
        ])
        for name, label, example in self.tool.fields:
            self.output_lines.append(f"  set {name} <value>    {label} (example: {example})")
        self.output_lines.extend([
            "",
            "  run                   Execute the selected tool",
            "  username search: Sherlock by default; set method maigret|sherlock|both",
            "  run provider          Create a new inbox (tempmail)",
            "  run check             Check an existing inbox (tempmail)",
            "  list                  List available providers",
            "  export json|csv|md    Save the current output locally",
            "  clear                 Clear output",
            "  back                  Return to tools",
            "",
        ])

    def _set_value(self, name: str, value: str) -> None:
        if name not in {field[0] for field in self.tool.fields}:
            self.output_lines.append(f"[!] This tool does not accept '{name}'.")
            return
        self.values[name] = value
        self.output_lines.append(f"[+] Set {name}: {value}")

    def _export_report(self, kind: str) -> None:
        if kind not in {"json", "csv", "md"}:
            self.output_lines.append("[!] Export format must be json, csv, or md.")
            return
        result = "\n".join(self.output_lines)
        paths = self.engine.export(result, next(iter(self.values.values()), "no-target"), self.tool.key)
        self.output_lines.append(f"[+] Report saved: {paths[kind]}")

    async def _run_tool(self, run_mode: str = "") -> None:
        # For tools with run modes (like tempmail), skip field validation
        # and pass the run mode to the engine
        if run_mode:
            self.status = "RUNNING"
            self._update_status()
            self.output_lines.append(f"[>] Executing {self.tool.name} ({run_mode})...")
            self._render_log()
            self._start_animation()
            try:
                result = await self.engine.run_module(
                    ENGINE_CATEGORIES[self.category.key],
                    self.tool.module_id,
                    run_mode,
                    self.values
                )
                self.output_lines.extend(str(result).splitlines())
            except Exception as error:
                self.output_lines.append(f"[-] Tool failed: {type(error).__name__}: {error}")
            finally:
                self._stop_animation()
                self.status = "READY"
                self._render_log()
                self._update_status()
            return

        # Standard tool execution — validate required fields
        missing = [
            name for name, _, _ in self.tool.fields
            if not self.values.get(name) and name not in OPTIONAL_FIELDS
        ]
        if missing:
            self.output_lines.extend([f"[!] Missing input: {', '.join(missing)}", f"[>] Set it with: set {missing[0]} <value>"])
            return
        self.status = "RUNNING"
        self._update_status()
        self.output_lines.append(f"[>] Executing {self.tool.name}...")

        self._render_log()
        self._start_animation()
        target = next((self.values[name] for name, _, _ in self.tool.fields), "")
        try:
            result = await self.engine.run_module(ENGINE_CATEGORIES[self.category.key], self.tool.module_id, target, self.values)
            self.output_lines.extend(str(result).splitlines())
        except Exception as error:
            self.output_lines.append(f"[-] Tool failed: {type(error).__name__}: {error}")
        finally:
            self._stop_animation()
            self.status = "READY"
            self._render_log()
            self._update_status()


class IntelligenceScreen(Screen):
    """Command-like views for persisted intelligence systems."""

    def __init__(self, engine, view="dashboard"):
        super().__init__()
        self.engine = engine
        self.view = view
        self.output_lines = []

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static(f"VELT / {self.view.upper()}", classes="screen-title")
        yield Static(self._help_text(), classes="muted")
        with Vertical(id="intelligence-layout"):
            yield RichLog(id="intelligence-log", highlight=True, markup=False, wrap=True)
            yield Input(placeholder="Type a command, then press Enter", id="intelligence-input")
            yield Button("BACK", id="back-intelligence", classes="secondary-button")
        yield Footer()

    def on_mount(self) -> None:
        self._refresh()
        self.call_after_refresh(self._focus_command)

    def _focus_command(self) -> None:
        command_input = self.query_one("#intelligence-input", Input)
        command_input.focus()
        self.app.set_focus(command_input)

    def _help_text(self):
        return {
            "dashboard": "Live local overview. Commands: stats, refresh, back",
            "findings": "Persisted discoveries. Commands: list [--severity LEVEL], view ID, stats, clear, back",
            "graph": "Persisted target relationships. Commands: show, target VALUE, export json|graphml, clear, back",
            "evidence": "Supporting evidence. Commands: list, view ID, export ID, clear, back",
            "activity": "Local history. Commands: recent, clear, back",
            "doctor": "Installation diagnostics. Commands: check, back",
        }.get(self.view, "Type help for commands.")

    def _refresh(self, command=""):
        if command.strip().lower() == "help":
            text = self._help_text()
        elif self.view == "dashboard":
            text = self.engine.dashboard.render(sum(len(c.tools) for c in CATEGORIES))
        elif self.view == "findings":
            text = self._findings(command)
        elif self.view == "graph":
            text = self._graph(command)
        elif self.view == "evidence":
            text = self._evidence(command)
        elif self.view == "activity":
            text = self._activity(command)
        else:
            text = self.engine.doctor.render()
        self.output_lines = text.splitlines()
        log = self.query_one("#intelligence-log", RichLog)
        log.clear()
        for line in self.output_lines:
            log.write(style_output_line(line))

    def _findings(self, command):
        parts = command.split()
        action = parts[0].lower() if parts else "list"
        if action in {"list", "findings"}:
            severity = parts[2] if len(parts) > 2 and parts[1].lower() == "--severity" else None
            items = self.engine.findings.list(severity)
            if not items:
                return "No findings have been recorded yet."
            return "\n".join(f"[{item['severity']}] {item['id']} — {item['title']} | {item['target']}" for item in items)
        if action == "view" and len(parts) >= 2:
            item = self.engine.findings.view(parts[1])
            if not item:
                return f"✗ Finding not found: {parts[1]}"
            evidence = [self.engine.evidence.view(eid) for eid in item.get("evidence_ids", [])]
            evidence = [entry for entry in evidence if entry]
            lines = [f"Finding: {item['title']}", f"Severity: {item['severity']}", f"Target: {item['target']}", f"Description: {item['description']}", f"Category: {item['category']}", f"Source: {item['source']}", f"Status: {item['status']}", f"Timestamp: {item['timestamp']}"]
            if evidence:
                lines.append("Evidence:")
                for entry in evidence:
                    lines.extend([f"  {entry['id']} — {entry['summary']}", f"  Target: {entry['target']}", f"  Observed: {entry['observed']}", f"  Timestamp: {entry['timestamp']}", f"  Source: {entry['source']}"])
            return "\n".join(lines)
        if action == "stats":
            stats = self.engine.findings.stats()
            return "\n".join([f"Total findings: {stats['total']}"] + [f"{key}: {value}" for key, value in stats['by_severity'].items()])
        if action == "clear":
            return f"✓ Cleared {self.engine.findings.clear()} findings."
        return "Usage: list [--severity info|low|medium|high|critical], view ID, stats, clear"

    def _graph(self, command):
        parts = command.split()
        action = parts[0].lower() if parts else "show"
        if action == "help":
            return "Usage: show, target TARGET, export json|graphml, clear"
        if action in {"show", "graph"}:
            return self.engine.graph.text_map()
        if action == "target" and len(parts) >= 2:
            return self.engine.graph.text_map(" ".join(parts[1:]))
        if action == "export" and len(parts) >= 2:
            kind = parts[1].lower()
            if kind == "json":
                import json
                return json.dumps(self.engine.graph.to_json(), indent=2)
            if kind == "graphml":
                return self.engine.graph.to_graphml()
            return "✗ Export format must be json or graphml."
        if action == "clear":
            counts = self.engine.graph.clear()
            return f"✓ Cleared {counts['nodes']} nodes and {counts['edges']} relationships."
        return "Usage: show, target TARGET, export json|graphml, clear"

    def _evidence(self, command):
        parts = command.split()
        action = parts[0].lower() if parts else "list"
        if action == "help":
            return "Usage: list, view ID, export ID, clear"
        if action in {"list", "evidence"}:
            items = self.engine.evidence.list()
            return "No evidence has been collected yet." if not items else "\n".join(f"{item['id']} [{item['kind']}] {item['summary']} — {item['target']}" for item in items)
        if action == "view" and len(parts) >= 2:
            item = self.engine.evidence.view(parts[1])
            return f"✗ Evidence not found: {parts[1]}" if not item else "\n".join(f"{key.replace('_', ' ').title()}: {value}" for key, value in item.items())
        if action == "export" and len(parts) >= 2:
            item = self.engine.evidence.export(parts[1])
            if not item:
                return f"✗ Evidence not found: {parts[1]}"
            import json
            return json.dumps(item, indent=2)
        if action == "clear":
            return f"✓ Cleared {self.engine.evidence.clear()} evidence items."
        return "Usage: list, view ID, export ID, clear"

    def _activity(self, command):
        parts = command.split()
        action = parts[0].lower() if parts else "recent"
        if action == "help":
            return "Usage: recent, clear"
        if action in {"recent", "activity"}:
            events = self.engine.activity.recent(20)
            return "No activity has been recorded yet." if not events else "\n".join(f"[{event['timestamp']}] {event['type']}: {event['description']}" for event in events)
        if action == "clear":
            return f"✓ Cleared {self.engine.activity.clear()} activity events."
        return "Usage: recent, clear"

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        command = event.value.strip()
        event.input.value = ""
        normalized = command.lower()
        if normalized in {"back", "/back", "q", "quit", "/quit"}:
            self.app.pop_screen()
            return
        self._refresh(command.removeprefix("/") if command.startswith("/") else command)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "back-intelligence":
            self.app.pop_screen()


class SettingsScreen(Screen):
    def __init__(self, engine):
        super().__init__()
        self.engine = engine
        self.config = engine.config
        self.inputs: Dict[str, Input] = {}

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static("VELT / SETTINGS", classes="screen-title")
        yield Static("Enter your own optional provider keys. Values are saved locally and displayed masked.", classes="muted")
        with VerticalScroll(id="settings-screen"):
            for provider in PROVIDER_ENV:
                yield Static(f"{provider.upper()} — {self.config.masked_key(provider)}", id=f"provider-label-{provider}", classes="panel-title")
                field = Input(placeholder=f"New {provider} API key/token (leave blank to keep current)", password=True, id=f"provider-{provider}")
                self.inputs[provider] = field
                yield field
            yield Button("SAVE LOCAL SETTINGS", id="save-settings", classes="secondary-button")
            yield Button("BACK", id="back-settings", classes="secondary-button")
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id or ""
        if button_id == "save-settings":
            for provider, field in self.inputs.items():
                if field.value.strip():
                    self.config.set_provider_key(provider, field.value.strip())
                    field.value = ""
            self.config.save()
            self.notify("Settings saved locally. Keys remain masked.")
            for provider in self.inputs:
                self.query_one(f"#provider-label-{provider}", Static).update(f"{provider.upper()} — {self.config.masked_key(provider)}")
        elif button_id == "back-settings":
            self.app.pop_screen()


CategoryMenu = MainMenu
