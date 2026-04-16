"""
SENTINEL-X MITRE ATT&CK Mapper
Provides technique lookup from a locally cached MITRE ATT&CK STIX 2.1 bundle.
Falls back to a built-in technique database if the STIX file is not available.
"""
import json
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger("sentinel.mitre")


# ─── Built-in technique database (fallback) ────────────
BUILTIN_TECHNIQUES = {
    "T1110": {
        "id": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained. Brute forcing credentials can take place across various protocols.",
        "data_sources": ["Application Log", "User Account"],
        "url": "https://attack.mitre.org/techniques/T1110",
    },
    "T1110.003": {
        "id": "T1110.003",
        "name": "Password Spraying",
        "tactic": "Credential Access",
        "description": "Adversaries may use a single or small list of commonly used passwords against many different accounts to attempt to acquire valid account credentials.",
        "data_sources": ["Application Log", "User Account"],
        "url": "https://attack.mitre.org/techniques/T1110/003",
    },
    "T1021": {
        "id": "T1021",
        "name": "Remote Services",
        "tactic": "Lateral Movement",
        "description": "Adversaries may use valid accounts to log into a service specifically designed to accept remote connections, such as SSH, RDP, SMB, or WinRM.",
        "data_sources": ["Logon Session", "Network Traffic", "Process"],
        "url": "https://attack.mitre.org/techniques/T1021",
    },
    "T1041": {
        "id": "T1041",
        "name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "description": "Adversaries may steal data by exfiltrating it over an existing command and control channel. The data is encoded into the normal communications channel using the same protocol as C2 communications.",
        "data_sources": ["Command", "Network Traffic", "File"],
        "url": "https://attack.mitre.org/techniques/T1041",
    },
    "T1071": {
        "id": "T1071",
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "description": "Adversaries may communicate using application layer protocols to avoid detection/network filtering by blending in with existing traffic.",
        "data_sources": ["Network Traffic"],
        "url": "https://attack.mitre.org/techniques/T1071",
    },
    "T1046": {
        "id": "T1046",
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to get a listing of services running on remote hosts, including those that may be vulnerable to remote software exploitation.",
        "data_sources": ["Cloud Service", "Command", "Network Traffic"],
        "url": "https://attack.mitre.org/techniques/T1046",
    },
    "T1548": {
        "id": "T1548",
        "name": "Abuse Elevation Control Mechanism",
        "tactic": "Privilege Escalation",
        "description": "Adversaries may circumvent mechanisms designed to control elevate privileges to gain higher-level permissions, such as exploiting SUID/SGID or sudo misconfigurations.",
        "data_sources": ["Command", "File", "Process"],
        "url": "https://attack.mitre.org/techniques/T1548",
    },
    "T1059": {
        "id": "T1059",
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries. These interfaces include PowerShell, bash, Python, and others.",
        "data_sources": ["Command", "Module", "Process", "Script"],
        "url": "https://attack.mitre.org/techniques/T1059",
    },
    "T1486": {
        "id": "T1486",
        "name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "description": "Adversaries may encrypt data on target systems or on large numbers of systems to interrupt availability. In some cases, this is done with ransomware.",
        "data_sources": ["Cloud Storage", "Command", "File", "Process"],
        "url": "https://attack.mitre.org/techniques/T1486",
    },
}


class MitreMapper:
    """
    MITRE ATT&CK technique lookup.
    Loads from local STIX 2.1 bundle if available, otherwise uses built-in database.
    """

    def __init__(self, stix_path: str = 'data/enterprise-attack.json'):
        self._index: dict = {}
        self._stix_loaded = False

        # Try to load STIX bundle
        stix_file = Path(stix_path)
        if stix_file.exists():
            try:
                self._load_stix(stix_file)
                self._stix_loaded = True
                logger.info(f"Loaded MITRE ATT&CK STIX bundle: {len(self._index)} techniques")
            except Exception as e:
                logger.warning(f"Failed to load STIX bundle: {e}")

        if not self._stix_loaded:
            self._index = BUILTIN_TECHNIQUES.copy()
            logger.info(f"Using built-in MITRE ATT&CK database: {len(self._index)} techniques")

    def _load_stix(self, stix_path: Path):
        """Load MITRE ATT&CK STIX 2.1 bundle."""
        with open(stix_path) as f:
            bundle = json.load(f)

        for obj in bundle.get('objects', []):
            if obj.get('type') != 'attack-pattern':
                continue
            ext_refs = obj.get('external_references', [])
            if not ext_refs:
                continue

            technique_id = ext_refs[0].get('external_id', '')
            if not technique_id.startswith('T'):
                continue

            # Find tactic
            tactic = 'Unknown'
            for phase in obj.get('kill_chain_phases', []):
                if phase.get('kill_chain_name') == 'mitre-attack':
                    tactic = phase.get('phase_name', 'Unknown').replace('-', ' ').title()
                    break

            self._index[technique_id] = {
                'id': technique_id,
                'name': obj.get('name', 'Unknown'),
                'tactic': tactic,
                'description': (obj.get('description', '') or '')[:500],
                'data_sources': obj.get('x_mitre_data_sources', []),
                'url': ext_refs[0].get('url', ''),
            }

    def lookup(self, technique_id: str) -> dict:
        """Look up a MITRE ATT&CK technique by ID."""
        if technique_id in self._index:
            return self._index[technique_id]

        return {
            'id': technique_id,
            'name': 'Unknown',
            'tactic': 'Unknown',
            'description': f'Technique {technique_id} not found in database.',
            'data_sources': [],
            'url': f'https://attack.mitre.org/techniques/{technique_id.replace(".", "/")}',
        }

    def get_all_detected(self, technique_ids: list[str]) -> list[dict]:
        """Get details for multiple detected techniques."""
        return [self.lookup(tid) for tid in technique_ids]

    def get_tactic_techniques(self, tactic: str) -> list[dict]:
        """Get all techniques for a given tactic."""
        return [
            t for t in self._index.values()
            if t.get('tactic', '').lower() == tactic.lower()
        ]

    @property
    def all_techniques(self) -> dict:
        """Return the full technique index."""
        return self._index
