import json
import logging
import re
from typing import Any, Dict

from graphshield.config import GROQ_MODEL
from graphshield.exceptions import AgentError

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = """\
You are a senior software supply chain security engineer with deep expertise
in vulnerability remediation, semantic versioning, and package management.

You will be given details about a vulnerable software dependency and must
produce a structured JSON patch recommendation.  Follow the JSON schema
EXACTLY — do not add extra keys, do not omit required keys, use the types
shown.  Respond with ONLY the JSON object — no markdown, no explanation.

JSON schema:
{
  "recommended_version": "<string: exact safe version, e.g. '4.18.3'>",
  "threat_explanation": "<string: 3 sentences — what the vuln is, how it's exploited, why this graph position makes it worse>",
  "breaking_changes": "<string: known breaking changes or 'None detected'>",
  "upgrade_command": "<string: exact CLI command, e.g. 'npm install express@4.18.3'>",
  "confidence": "<string: HIGH | MEDIUM | LOW>",
  "attack_path_summary": "<string: single sentence describing the worst attack path>"
}
"""

_USER_TEMPLATE = """\
Package: {package_name}
Ecosystem: {ecosystem}
Installed version: {current_version}
CVE IDs: {cve_ids}
CVSS score: {cvss_score}
Blast radius: {reachable_count} downstream packages
Data sensitivity: {data_sensitivity}
Sink types reachable: {sink_types}
Topological rank: {topological_rank} (lower = loaded earlier)
Top attack path: {attack_path}

Please produce the JSON patch recommendation now.
"""

class PatchAgent:
    def __init__(self, groq_api_key: str, model: str = GROQ_MODEL, temperature: float = 0.1):
        if not groq_api_key:
            raise AgentError("GROQ_API_KEY is required")
        try:
            from groq import Groq
        except ImportError as exc:
            raise AgentError("groq not installed", cause=exc) from exc
        self._client = Groq(api_key=groq_api_key)
        self.model = model
        self.temperature = temperature

    def analyze_vulnerability(self, blast_result, dag) -> "PatchRecommendation":
        meta = dag.metadata.get(blast_result.source_node)
        ecosystem = meta.ecosystem if meta else "unknown"
        attack_path = "N/A"
        if blast_result.attack_paths:
            ap = blast_result.attack_paths[0]
            attack_path = " → ".join(ap.path)

        cve_ids = getattr(blast_result, "cve_ids", None)
        if not cve_ids:
            single_cve = getattr(blast_result, "cve_id", None)
            cve_ids = [single_cve] if single_cve else []

        user_msg = _USER_TEMPLATE.format(
            package_name=blast_result.source_node,
            ecosystem=ecosystem,
            current_version=meta.version if meta else "unknown",
            cve_ids=", ".join(cve_ids) if cve_ids else "unknown",
            cvss_score=blast_result.cvss_score,
            reachable_count=blast_result.reachable_count,
            data_sensitivity=blast_result.data_sensitivity,
            sink_types=", ".join(blast_result.sink_types) if blast_result.sink_types else "none",
            topological_rank=getattr(blast_result, "topological_rank", 0),
            attack_path=attack_path,
        )

        try:
            response = self._client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": _SYSTEM_PROMPT},
                    {"role": "user", "content": user_msg},
                ],
                temperature=self.temperature,
                max_tokens=512,
            )
            raw_text = response.choices[0].message.content or ""
            parsed = self._parse_response(raw_text)
        except AgentError:
            raise
        except Exception as exc:
            logger.warning(
                "Groq API call failed for %s: %s. Using heuristic fallback.",
                blast_result.source_node,
                exc,
            )
            parsed = self._heuristic_fallback(blast_result)

        return self._build_recommendation(blast_result, meta, parsed)

    def _parse_response(self, text: str) -> Dict[str, Any]:
        text = re.sub(r"```(?:json)?", "", text).strip()
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if not match:
            raise AgentError(f"No JSON in LLM response: {text[:200]!r}")
        try:
            data = json.loads(match.group(0))
        except json.JSONDecodeError as exc:
            raise AgentError(f"Failed to parse JSON: {exc}") from exc
        required = {"recommended_version", "threat_explanation", "breaking_changes",
                    "upgrade_command", "confidence", "attack_path_summary"}
        missing = required - set(data.keys())
        if missing:
            raise AgentError(f"Missing keys: {missing}")
        return data

    def _heuristic_fallback(self, blast_result) -> Dict[str, Any]:
        pkg = blast_result.source_node
        eco_cmd = f"pip install --upgrade {pkg}"
        return {
            "recommended_version": "latest",
            "threat_explanation": (
                f"{pkg} has CVE with CVSS {blast_result.cvss_score}. "
                f"Reaches {blast_result.reachable_count} downstream packages. "
                f"Sensitivity: {blast_result.data_sensitivity}."
            ),
            "breaking_changes": "Unknown — review changelog.",
            "upgrade_command": eco_cmd,
            "confidence": "LOW",
            "attack_path_summary": f"Attacker exploits {pkg} to reach application code.",
        }

    def _build_recommendation(self, blast_result, meta, parsed) -> "PatchRecommendation":
        from graphshield.core.scanner import PatchRecommendation

        cve_ids = getattr(blast_result, "cve_ids", None)
        if not cve_ids:
            single_cve = getattr(blast_result, "cve_id", None)
            cve_ids = [single_cve] if single_cve else []

        return PatchRecommendation(
            package_name=blast_result.source_node,
            current_version=meta.version if meta else "unknown",
            cve_ids=cve_ids,
            cvss_score=blast_result.cvss_score,
            recommended_version=str(parsed.get("recommended_version", "latest")),
            threat_explanation=str(parsed.get("threat_explanation", "")),
            breaking_changes=str(parsed.get("breaking_changes", "Unknown")),
            upgrade_command=str(parsed.get("upgrade_command", "")),
            confidence=str(parsed.get("confidence", "LOW")),
            attack_path_summary=str(parsed.get("attack_path_summary", "")),
            blast_radius_score=getattr(blast_result, "blast_radius_score", 0.0),
        )
