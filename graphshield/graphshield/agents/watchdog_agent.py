from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from rich.console import Console
from rich.panel import Panel

from graphshield.config import GROQ_MODEL
from graphshield.core.manifest_parser import Dependency, parse_manifest

try:
    from graphshield.core.scanner import SupplyChainDiff
except Exception:
    @dataclass
    class SupplyChainDiff:  # type: ignore[no-redef]
        added: list[Dependency]
        removed: list[Dependency]
        version_changed: list[dict[str, str]]
        safe_to_merge: bool
        risk_summary: str
        suspicious_packages: list[str]
        recommendation: str


class WatchdogAgent:
    def __init__(self, api_key: str, poll_interval_hours: int = 6):
        self.poll_interval_hours = poll_interval_hours
        self.model = GROQ_MODEL
        self.max_tokens = 1024
        self.console = Console()
        self.client = None
        if api_key:
            try:
                from groq import Groq

                self.client = Groq(api_key=api_key)
            except Exception:
                self.client = None

    def compute_supply_chain_diff(
        self,
        old_deps: list[Dependency],
        new_deps: list[Dependency],
    ) -> SupplyChainDiff:
        """
        Compare old and new dependency lists. Compute:
          - added: deps in new not in old (by name+version)
          - removed: deps in old not in new
          - version_changed: deps where name same but version differs

        Then call Groq API with a prompt listing the changes. Ask the model:
          "Given these dependency changes, is this safe to merge?
           Respond ONLY in JSON: { safe_to_merge: bool, risk_summary: str,
           suspicious_packages: list[str], recommendation: str }"

        Parse response. If parsing fails: safe_to_merge=True, risk_summary="Analysis unavailable".
        Return a fully populated SupplyChainDiff dataclass.
        """
        old_pairs = {(d.name, d.version): d for d in old_deps}
        new_pairs = {(d.name, d.version): d for d in new_deps}
        old_by_name = {d.name: d for d in old_deps}
        new_by_name = {d.name: d for d in new_deps}

        added = [new_pairs[k] for k in sorted(new_pairs.keys() - old_pairs.keys())]
        removed = [old_pairs[k] for k in sorted(old_pairs.keys() - new_pairs.keys())]

        version_changed: list[dict[str, str]] = []
        for name in sorted(set(old_by_name.keys()) & set(new_by_name.keys())):
            if old_by_name[name].version != new_by_name[name].version:
                version_changed.append(
                    {
                        "name": name,
                        "old_version": old_by_name[name].version,
                        "new_version": new_by_name[name].version,
                    }
                )

        safe_to_merge = True
        risk_summary = "Analysis unavailable"
        suspicious_packages: list[str] = []
        recommendation = "Proceed with standard review."

        if self.client is not None:
            prompt = (
                "Given these dependency changes, is this safe to merge?\n"
                "Respond ONLY in JSON: { safe_to_merge: bool, risk_summary: str, "
                "suspicious_packages: list[str], recommendation: str }\n\n"
                f"Added: {[f'{d.name}@{d.version}' for d in added]}\n"
                f"Removed: {[f'{d.name}@{d.version}' for d in removed]}\n"
                f"Version changed: {version_changed}\n"
            )
            try:
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=[{"role": "user", "content": prompt}],
                    max_tokens=self.max_tokens,
                    temperature=0.1,
                )
                raw = (response.choices[0].message.content or "").strip()
                data = self._parse_json(raw)
                safe_to_merge = bool(data.get("safe_to_merge", True))
                risk_summary = str(data.get("risk_summary", "Analysis unavailable"))
                suspicious_packages = [
                    str(p) for p in data.get("suspicious_packages", []) if str(p).strip()
                ]
                recommendation = str(
                    data.get("recommendation", "Proceed with standard review.")
                )
            except Exception:
                safe_to_merge = True
                risk_summary = "Analysis unavailable"

        return SupplyChainDiff(
            added=added,
            removed=removed,
            version_changed=version_changed,
            safe_to_merge=safe_to_merge,
            risk_summary=risk_summary,
            suspicious_packages=suspicious_packages,
            recommendation=recommendation,
        )

    def watch(self, manifest_path: str):
        """
        Polling loop. Every poll_interval_hours hours:
          1. Re-parse the manifest at manifest_path
          2. Compare against last known state
          3. If changes: call compute_supply_chain_diff()
          4. Print result to console using Rich
          5. Update last known state
        Use time.sleep(poll_interval_hours * 3600). Loop forever until KeyboardInterrupt.
        """
        path = Path(manifest_path)
        last_state: list[Dependency] = []
        try:
            last_state = parse_manifest(path)
        except Exception:
            last_state = []

        try:
            while True:
                time.sleep(self.poll_interval_hours * 3600)
                try:
                    current_state = parse_manifest(path)
                except Exception:
                    continue
                diff = self.compute_supply_chain_diff(last_state, current_state)
                has_changes = bool(diff.added or diff.removed or diff.version_changed)
                if has_changes:
                    title = (
                        "[green]Dependency changes look safe[/green]"
                        if diff.safe_to_merge
                        else "[red]Dependency changes need review[/red]"
                    )
                    body = (
                        f"Added: {len(diff.added)}\n"
                        f"Removed: {len(diff.removed)}\n"
                        f"Version changes: {len(diff.version_changed)}\n"
                        f"Risk: {diff.risk_summary}\n"
                        f"Suspicious: {', '.join(diff.suspicious_packages) or 'none'}\n"
                        f"Recommendation: {diff.recommendation}"
                    )
                    self.console.print(Panel(body, title=title))
                    last_state = current_state
        except KeyboardInterrupt:
            return

    def _parse_json(self, text: str) -> dict[str, Any]:
        cleaned = re.sub(r"^```json|```$", "", text, flags=re.MULTILINE).strip()
        if cleaned.startswith("{") and cleaned.endswith("}"):
            return json.loads(cleaned)
        match = re.search(r"\{.*\}", cleaned, flags=re.DOTALL)
        if not match:
            raise ValueError("No JSON found")
        return json.loads(match.group(0))
