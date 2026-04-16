"""
SENTINEL-X AI Narrator — LLM-powered alert explainability engine.
Generates human-language narratives for every confirmed alert.
Supports Anthropic Claude and Ollama (local LLM) with template fallback.
"""
import json
import logging
from datetime import datetime, timezone
from typing import Optional

from correlation.engine import CorrelatedAlert
from explainability.mitre_mapper import MitreMapper

logger = logging.getLogger("sentinel.narrator")


NARRATIVE_PROMPT = """You are a Senior Threat Hunter and SOC Analyst. Analyze this security alert and provide a deep-dive explanation.

Alert Data:
  Rule: {rule_name} (ID: {rule_id})
  Severity: {severity}  |  Confidence: {confidence}%
  MITRE ATT&CK: {mitre_tactic} > {mitre_technique} ({mitre_name})
  Source IP: {source_ip}
  Destination: {dest_ip}
  Event Count: {event_count} events in {time_window_seconds}s
  Platform/OS: {platform}
  Correlated With: {correlated_rules}
  Technique Description: {mitre_description}

Evidence Sample (last 5 events):
{evidence_summary}

Your response must be in this exact JSON format (raw JSON, no markdown):
{{
  "what_happened": "<Detailed technical summary of the observed behavior>",
  "why_suspicious": "<Technical analysis of why this violates security baselines>",
  "attacker_objective": "<Probable goal such as persistence, exfiltration, or recon>",
  "false_positive_indicators": "<List specific indicators that would suggest this is legitimate activity>",
  "fp_probability": <Integer 0-100 indicating likelihood this is a false positive>,
  "mitigation_playbook": [
    {{
      "step": "<Short description>",
      "command": "<The exact CLI command to run on the {platform} terminal to mitigate this specific threat>",
      "logic": "<Briefly explain what the command does>"
    }}
  ]
}}"""


# ─── Template-based fallback narratives ─────────────────

TEMPLATE_NARRATIVES = {
    "BF-001": {
        "what_happened": "Multiple failed login attempts ({event_count}) were detected from IP {source_ip} within {time_window_seconds} seconds, targeting the SSH/RDP service.",
        "why_suspicious": "This pattern of rapid, repeated authentication failures from a single source is characteristic of an automated credential stuffing or brute force attack.",
        "attacker_objective": "Gain unauthorized access to the system by guessing valid credentials through exhaustive password attempts.",
        "false_positive_indicators": "Legitimate admin performing a script verify or a misconfigured service account with an expired password.",
        "fp_probability": 15,
        "mitigation_playbook": [
            {"step": "Block IP", "command": "iptables -A INPUT -s {source_ip} -j DROP", "logic": "Prevent further attempts from source"},
            {"step": "Account Audit", "command": "lastlog | grep {source_ip}", "logic": "Check if any attempts succeeded"}
        ],
    },
    "EX-001": {
        "what_happened": "Unusually large outbound data transfer detected to external IP {dest_ip}. Total volume exceeds normal thresholds.",
        "why_suspicious": "Large outbound data transfers to external hosts may indicate data exfiltration — an attacker stealing sensitive data.",
        "attacker_objective": "Exfiltrate stolen data, intellectual property, or credentials to an attacker-controlled server.",
        "false_positive_indicators": "Planned server backup, large OS update distribution, or legitimate bulk data migration to cloud storage.",
        "fp_probability": 25,
        "mitigation_playbook": [
            {"step": "Terminate Flow", "command": "conntrack -D -s {source_ip} -d {dest_ip}", "logic": "Immediately sever the network connection"},
            {"step": "Identify Process", "command": "lsof -i @{dest_ip}", "logic": "Find which process is sending the data"}
        ],
    },
    "C2-001": {
        "what_happened": "Periodic network connections detected to external IP {dest_ip} at regular intervals, consistent with C2 beacon behavior.",
        "why_suspicious": "Regular, periodic connections to a single external host is a hallmark of command-and-control malware phoning home for instructions.",
        "attacker_objective": "Maintain persistent remote access to the compromised system, receive commands, and exfiltrate data.",
        "false_positive_indicators": "Software telemetry, NTP synchronization, or legitimate heartbeats for cloud-managed applications.",
        "fp_probability": 10,
        "mitigation_playbook": [
            {"step": "Block C2", "command": "route add -host {dest_ip} reject", "logic": "Blackhole the command and control destination IP"},
            {"step": "Check Persistence", "command": "systemctl list-unit-files --type=service | grep enabled", "logic": "Check for suspicious new services"}
        ],
    },
    "RW-001": {
        "what_happened": "Rapid mass file operations detected: {event_count} files were modified/renamed/created in {time_window_seconds} seconds by a single process.",
        "why_suspicious": "Mass file encryption or modification in a very short time window is a critical indicator of ransomware execution.",
        "attacker_objective": "Encrypt files across the system to deny access, then demand ransom payment for the decryption key.",
        "false_positive_indicators": "Bulk rename operations by user, directory compression/archiving, or legitimate antivirus scanning/cleaning.",
        "fp_probability": 5,
        "mitigation_playbook": [
            {"step": "Halt System", "command": "reboot --force", "logic": "Immediate shutdown to stop the encryption process (High Risk)"},
            {"step": "Snapshot", "command": "zfs snapshot data@now", "logic": "Take instant backup of unaffected directories if possible"}
        ],
    },
}

# Default for correlated alerts and unknowns
DEFAULT_NARRATIVE = {
    "what_happened": "A security event matching rule {rule_name} ({rule_id}) was detected with {event_count} supporting events.",
    "why_suspicious": "The detected behavior pattern matches known attack techniques documented in the MITRE ATT&CK framework.",
    "attacker_objective": "The specific adversary objective depends on the attack stage — see MITRE technique {mitre_technique} for details.",
    "false_positive_indicators": "Check if this activity matches scheduled maintenance or known administrative workflows.",
    "fp_probability": 50,
    "mitigation_playbook": [
        {"step": "Review Log", "command": "tail -n 100 /var/log/syslog", "logic": "Manual review of system logs for context"},
        {"step": "Isolate Host", "command": "ifconfig eth0 down", "logic": "Disable network interface to contain threat"}
    ],
}


class Narrator:
    """
    AI-powered alert narrative generator.

    Uses Claude API (Anthropic) or Ollama for LLM-generated explanations.
    Falls back to template-based narratives if LLM is unavailable.
    """

    def __init__(self, config: dict, mitre_mapper: MitreMapper):
        self.config = config
        self.mitre_mapper = mitre_mapper
        self._provider = config.get('provider', 'anthropic')
        self._model = config.get('model', 'claude-haiku-4-5')
        self._api_key = config.get('api_key', '')
        self._ollama_url = config.get('ollama_url', 'http://localhost:11434')
        self._ollama_model = config.get('ollama_model', 'llama3')
        self._fallback_enabled = config.get('fallback_enabled', True)
        self._llm_available = False
        self._client = None

        self._init_llm()

    def _init_llm(self):
        """Initialize LLM client."""
        if self._provider == 'anthropic' and self._api_key:
            try:
                import anthropic
                self._client = anthropic.Anthropic(api_key=self._api_key)
                self._llm_available = True
                logger.info("Anthropic Claude client initialized")
            except Exception as e:
                logger.warning(f"Failed to initialize Anthropic client: {e}")

        elif self._provider == 'ollama':
            try:
                import ollama
                self._llm_available = True
                logger.info(f"Ollama client ready (model: {self._ollama_model})")
            except Exception as e:
                logger.warning(f"Failed to initialize Ollama client: {e}")

        if not self._llm_available:
            logger.info("LLM unavailable — using template-based narratives")

    async def narrate(self, alert: CorrelatedAlert) -> dict:
        """
        Generate a narrative for a correlated alert.
        Tries LLM first, falls back to templates.
        """
        # Get MITRE data
        mitre_data = self.mitre_mapper.lookup(alert.mitre_technique)

        # Try LLM narrative
        if self._llm_available:
            try:
                narrative = await self._llm_narrate(alert, mitre_data)
                if narrative:
                    return narrative
            except Exception as e:
                logger.warning(f"LLM narrative failed: {e}")

        # Fallback to template
        return self._template_narrate(alert, mitre_data)

    async def _llm_narrate(self, alert: CorrelatedAlert, mitre_data: dict) -> Optional[dict]:
        """Generate narrative using LLM."""
        import asyncio

        # Format evidence summary
        evidence_text = json.dumps(alert.evidence_summary[:5], indent=2)

        prompt = NARRATIVE_PROMPT.format(
            rule_name=alert.rule_name,
            rule_id=alert.rule_id,
            severity=alert.severity.upper(),
            confidence=int(alert.confidence * 100),
            mitre_tactic=alert.mitre_tactic,
            mitre_technique=alert.mitre_technique,
            mitre_name=mitre_data.get('name', 'Unknown'),
            source_ip=alert.source_ip or 'N/A',
            dest_ip=alert.dest_ip or 'N/A',
            event_count=alert.event_count,
            time_window_seconds=alert.time_window_seconds,
            correlated_rules=', '.join(alert.correlated_rules),
            platform=alert.platform,
            mitre_description=mitre_data.get('description', '')[:300],
            evidence_summary=evidence_text,
        )

        if self._provider == 'anthropic' and self._client:
            response = await asyncio.get_event_loop().run_in_executor(
                None, self._call_anthropic, prompt
            )
            return response

        elif self._provider == 'ollama':
            response = await asyncio.get_event_loop().run_in_executor(
                None, self._call_ollama, prompt
            )
            return response

        return None

    def _call_anthropic(self, prompt: str) -> Optional[dict]:
        """Call Anthropic Claude API."""
        try:
            message = self._client.messages.create(
                model=self._model,
                max_tokens=500,
                messages=[{"role": "user", "content": prompt}]
            )
            text = message.content[0].text
            return json.loads(text)
        except Exception as e:
            logger.error(f"Anthropic API error: {e}")
            return None

    def _call_ollama(self, prompt: str) -> Optional[dict]:
        """Call Ollama local LLM."""
        try:
            import ollama
            response = ollama.chat(
                model=self._ollama_model,
                messages=[{"role": "user", "content": prompt}]
            )
            text = response['message']['content']
            # Extract JSON from response
            start = text.find('{')
            end = text.rfind('}') + 1
            if start >= 0 and end > start:
                return json.loads(text[start:end])
            return None
        except Exception as e:
            logger.error(f"Ollama API error: {e}")
            return None

    def _template_narrate(self, alert: CorrelatedAlert, mitre_data: dict) -> dict:
        """Generate narrative from templates (fallback)."""
        template = TEMPLATE_NARRATIVES.get(alert.rule_id, DEFAULT_NARRATIVE)

        format_vars = {
            'rule_name': alert.rule_name,
            'rule_id': alert.rule_id,
            'severity': alert.severity,
            'confidence': int(alert.confidence * 100),
            'mitre_technique': alert.mitre_technique,
            'mitre_tactic': alert.mitre_tactic,
            'source_ip': alert.source_ip or 'unknown',
            'dest_ip': alert.dest_ip or 'unknown',
            'event_count': alert.event_count,
            'time_window_seconds': alert.time_window_seconds,
        }

        narrative = {}
        for key, value in template.items():
            if isinstance(value, str):
                try:
                    narrative[key] = value.format(**format_vars)
                except (KeyError, IndexError):
                    narrative[key] = value
            elif isinstance(value, list):
                narrative[key] = []
                for item in value:
                    try:
                        narrative[key].append(item.format(**format_vars))
                    except (KeyError, IndexError):
                        narrative[key].append(item)

        return narrative

    @property
    def is_llm_available(self) -> bool:
        return self._llm_available
