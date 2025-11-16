import logging
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

# Note: mitreattack-python would need to be installed
# from mitreattack.stix20 import MitreAttackData

logger = logging.getLogger(__name__)


@dataclass
class ThreatActor:
    """Represents a threat actor"""

    id: str
    name: str
    description: str
    techniques: List[str]
    aliases: List[str]
    country: Optional[str] = None
    motivation: Optional[str] = None


@dataclass
class AttackTechnique:
    """Represents a MITRE ATT&CK technique"""

    id: str
    name: str
    description: str
    tactic: str
    data_sources: List[str]
    detection: str
    platforms: List[str]
    pyramid_level: str


class PyramidOfPain:
    """
    Implements the Pyramid of Pain for prioritizing behavioral hunting over indicators.

    Core Philosophy:
    - TTPs (Behaviors) are at the TOP - hardest for adversaries to change
    - Hash values are at the BOTTOM - trivial for adversaries to change
    - Effective hunting focuses on the top of the pyramid
    """

    def __init__(self):
        self.levels = {
            "hash_values": {
                "pain": 1,
                "examples": ["MD5", "SHA256"],
                "difficulty": "Trivial",
                "adversary_change_time": "Seconds",
                "hunt_value": "Very Low - Avoid IOC-only hunting",
                "recommended": False,
            },
            "ip_addresses": {
                "pain": 2,
                "examples": ["IPv4", "IPv6"],
                "difficulty": "Easy",
                "adversary_change_time": "Minutes",
                "hunt_value": "Low - Infrastructure rotates rapidly",
                "recommended": False,
            },
            "domain_names": {
                "pain": 3,
                "examples": ["C2 domains"],
                "difficulty": "Simple",
                "adversary_change_time": "Hours",
                "hunt_value": "Low-Medium - Disposable infrastructure",
                "recommended": False,
            },
            "network_artifacts": {
                "pain": 4,
                "examples": ["URI patterns", "User-Agent strings"],
                "difficulty": "Annoying",
                "adversary_change_time": "Days",
                "hunt_value": "Medium - Better than atomic IOCs",
                "recommended": False,
            },
            "host_artifacts": {
                "pain": 5,
                "examples": ["Registry keys", "File paths"],
                "difficulty": "Annoying",
                "adversary_change_time": "Days",
                "hunt_value": "Medium - Better than atomic IOCs",
                "recommended": False,
            },
            "tools": {
                "pain": 6,
                "examples": ["Mimikatz", "PsExec", "Cobalt Strike"],
                "difficulty": "Challenging",
                "adversary_change_time": "Weeks",
                "hunt_value": "High - Hunt for tool capabilities, not signatures",
                "recommended": True,
            },
            "ttps": {
                "pain": 7,
                "examples": ["Process Injection (T1055)", "Credential Dumping (T1003)", "Lateral Movement (T1021)"],
                "difficulty": "Tough",
                "adversary_change_time": "Months to Years",
                "hunt_value": "HIGHEST - Primary focus for threat hunting",
                "recommended": True,
            },
        }

    def classify_indicator(self, indicator: str, indicator_type: str) -> Tuple[str, int]:
        """Classifies an indicator in the pyramid"""
        type_mapping = {
            "hash": "hash_values",
            "md5": "hash_values",
            "sha256": "hash_values",
            "ip": "ip_addresses",
            "ipv4": "ip_addresses",
            "domain": "domain_names",
            "url": "network_artifacts",
            "uri": "network_artifacts",
            "registry": "host_artifacts",
            "file_path": "host_artifacts",
            "tool": "tools",
            "technique": "ttps",
            "ttp": "ttps",
        }

        level = type_mapping.get(indicator_type.lower(), "hash_values")
        return level, self.levels[level]["pain"]

    def prioritize_hunts(self, indicators: List[Dict]) -> List[Dict]:
        """
        Prioritizes hunting activities based on pyramid levels.

        Behavioral (TTP) hunts are ALWAYS prioritized over IOC-based hunts.
        Returns hunts sorted with TTPs first, then tools, then artifacts, then IOCs.
        """
        for indicator in indicators:
            level, pain = self.classify_indicator(indicator["value"], indicator["type"])
            indicator["pyramid_level"] = level
            indicator["pain_score"] = pain
            indicator["recommended"] = self.levels[level]["recommended"]
            indicator["hunt_value"] = self.levels[level]["hunt_value"]

            # Add warning for low-value IOC hunts
            if pain <= 3:  # Hash, IP, Domain
                indicator["warning"] = (
                    f"⚠️  LOW HUNT VALUE: {indicator['type']} indicators change in "
                    f"{self.levels[level]['adversary_change_time'].lower()}. "
                    f"Consider hunting for behaviors instead."
                )

        # Sort: TTPs first, then tools, then everything else
        return sorted(indicators, key=lambda x: x["pain_score"], reverse=True)


class DiamondModel:
    """Implements the Diamond Model of intrusion analysis"""

    def __init__(self):
        self.model_elements = ["adversary", "capability", "infrastructure", "victim"]

    def create_diamond_model(self, adversary_data: Dict) -> Dict:
        """Creates a Diamond Model representation of an adversary"""
        return {
            "adversary": {
                "name": adversary_data.get("name", "Unknown"),
                "motivation": adversary_data.get("motivation", "Unknown"),
                "sophistication": adversary_data.get("sophistication", "Medium"),
            },
            "capability": {
                "techniques": adversary_data.get("techniques", []),
                "tools": adversary_data.get("tools", []),
                "malware": adversary_data.get("malware", []),
            },
            "infrastructure": {
                "domains": adversary_data.get("domains", []),
                "ips": adversary_data.get("ips", []),
                "certificates": adversary_data.get("certificates", []),
            },
            "victim": {
                "sectors": adversary_data.get("target_sectors", []),
                "countries": adversary_data.get("target_countries", []),
                "organization_size": adversary_data.get("target_size", "Any"),
            },
        }


class CyberKillChain:
    """Implements the Cyber Kill Chain framework"""

    def __init__(self):
        self.phases = [
            "reconnaissance",
            "weaponization",
            "delivery",
            "exploitation",
            "installation",
            "command_and_control",
            "actions_on_objectives",
        ]

        self.phase_mapping = {
            "TA0043": "reconnaissance",
            "TA0042": "reconnaissance",
            "TA0001": "delivery",
            "TA0002": "exploitation",
            "TA0003": "installation",
            "TA0004": "installation",
            "TA0005": "installation",
            "TA0011": "command_and_control",
            "TA0006": "installation",
            "TA0007": "actions_on_objectives",
            "TA0008": "actions_on_objectives",
            "TA0009": "actions_on_objectives",
            "TA0010": "actions_on_objectives",
            "TA0040": "actions_on_objectives",
        }

    def map_technique_to_kill_chain(self, tactic_id: str) -> str:
        """Maps MITRE ATT&CK tactic to kill chain phase"""
        return self.phase_mapping.get(tactic_id, "unknown")


class ThreatIntelligenceEngine:
    """Integrates multiple threat intelligence frameworks"""

    def __init__(self):
        # In a real implementation, you would load the MITRE ATT&CK data
        # self.mitre_data = MitreAttackData("enterprise-attack.json")
        self.pyramid_of_pain = PyramidOfPain()
        self.diamond_model = DiamondModel()
        self.cyber_kill_chain = CyberKillChain()
        self.techniques_cache = {}
        self.actors_cache = {}

    async def analyze_adversary_behavior(self, adversary_id: str) -> Dict:
        """Comprehensive adversary analysis across frameworks"""
        # In a real implementation, this would query the MITRE ATT&CK database
        adversary = await self._get_adversary_data(adversary_id)
        techniques = await self._get_adversary_techniques(adversary_id)

        analysis = {
            "mitre_attack": {
                "name": adversary["name"],
                "description": adversary["description"],
                "techniques": techniques,
                "tactics": self._group_techniques_by_tactic(techniques),
            },
            "pyramid_of_pain": self._map_to_pyramid(techniques),
            "diamond_model": self.diamond_model.create_diamond_model(adversary),
            "kill_chain_mapping": self._map_to_kill_chain(techniques),
            "hunt_priority": self._calculate_hunt_priority(techniques),
        }

        return analysis

    async def generate_hunt_hypotheses(self, adversary_analysis: Dict) -> List[str]:
        """Generates testable hypotheses based on adversary analysis"""
        hypotheses = []

        # High-priority techniques (top of Pyramid of Pain)
        for technique in adversary_analysis["mitre_attack"]["techniques"]:
            if self._is_high_priority(technique):
                hypotheses.append(
                    f"Adversary will use {
                        technique['name']} ({
                        technique['id']}) "
                    f"for {
                        technique['tactic']} as observed in previous campaigns"
                )

        # Diamond Model-based hypotheses
        infrastructure = adversary_analysis["diamond_model"]["infrastructure"]
        for domain in infrastructure.get("domains", []):
            hypotheses.append(f"Adversary will establish C2 communication with domain {domain}")

        for ip in infrastructure.get("ips", []):
            hypotheses.append(f"Adversary will use IP address {ip} for command and control")

        # Kill Chain-based hypotheses
        kill_chain_phases = adversary_analysis["kill_chain_mapping"]
        for phase, techniques in kill_chain_phases.items():
            if techniques:
                hypotheses.append(
                    f"During {phase} phase, adversary will employ techniques: "
                    f"{', '.join([t['name'] for t in techniques[:3]])}"
                )

        return hypotheses[:10]  # Return top 10 hypotheses

    async def get_detection_opportunities(self, technique_id: str) -> Dict:
        """Identifies detection opportunities for a technique"""
        technique = await self._get_technique_data(technique_id)

        if not technique:
            return {"error": f"Technique {technique_id} not found"}

        opportunities = {
            "technique": technique["name"],
            "data_sources": technique.get("data_sources", []),
            "detection_notes": technique.get("detection", ""),
            "telemetry_requirements": self._map_data_sources_to_telemetry(technique.get("data_sources", [])),
            "example_queries": self._generate_detection_queries(technique_id),
            "pyramid_level": self._get_pyramid_level_for_technique(technique_id),
        }

        return opportunities

    async def enrich_ioc(self, ioc: str, ioc_type: str) -> Dict:
        """
        Enriches an IOC with threat intelligence.

        ⚠️  WARNING: IOC enrichment is useful for context but should NOT be the
        primary hunting focus. Adversaries change IOCs rapidly. Always pivot to
        behavioral hunting when possible.
        """
        level, pain_score = self.pyramid_of_pain.classify_indicator(ioc, ioc_type)

        enrichment = {
            "ioc": ioc,
            "type": ioc_type,
            "pyramid_level": level,
            "pain_score": pain_score,
            "hunt_recommendation": self.pyramid_of_pain.levels[level]["recommended"],
            "adversary_change_time": self.pyramid_of_pain.levels[level]["adversary_change_time"],
            "associated_actors": [],
            "campaigns": [],
            "first_seen": None,
            "last_seen": None,
            "malware_families": [],
            "confidence": "medium",
            "behavioral_pivot_suggestions": [],
        }

        # Add behavioral pivot suggestions
        enrichment["behavioral_pivot_suggestions"] = self._suggest_behavioral_pivots(ioc, ioc_type)

        # Add strong warning for low-value IOCs
        if pain_score <= 3:
            enrichment["warning"] = (
                f"⚠️  This {ioc_type} is at the BOTTOM of the Pyramid of Pain. "
                f"Adversaries can change it in {enrichment['adversary_change_time'].lower()}. "
                f"Instead, hunt for the BEHAVIORS associated with this IOC."
            )

        # In a real implementation, this would query threat intelligence feeds
        # For now, we'll provide a mock response
        if ioc_type.lower() in ["domain", "ip"]:
            enrichment["associated_actors"] = ["APT28", "APT29"]
            enrichment["campaigns"] = ["Operation Ghost", "Red October"]
            enrichment["confidence"] = "high"

        return enrichment

    def _suggest_behavioral_pivots(self, ioc: str, ioc_type: str) -> List[str]:
        """
        Suggests behavioral hunting pivots from an IOC.

        This is KEY to moving from IOC-based hunting to behavioral hunting.
        """
        suggestions = []

        if ioc_type.lower() in ["ip", "domain"]:
            suggestions.extend(
                [
                    "Hunt for C2 beaconing behaviors (T1071.001) - regular intervals, consistent packet sizes",
                    "Hunt for DNS tunneling patterns (T1071.004) - unusual subdomain lengths, high query volumes",
                    "Hunt for protocol anomalies in network traffic - unusual ports, protocols, or traffic patterns",
                ]
            )
        elif ioc_type.lower() in ["hash", "md5", "sha256"]:
            suggestions.extend(
                [
                    "Hunt for execution behaviors (T1059.*) - suspicious process chains, parent-child anomalies",
                    "Hunt for persistence mechanisms (T1547.*) - registry modifications, scheduled tasks",
                    "Hunt for defense evasion behaviors (T1027, T1055) - obfuscation, process injection",
                ]
            )
        elif ioc_type.lower() in ["url", "uri"]:
            suggestions.extend(
                [
                    "Hunt for web shell behaviors (T1505.003) - unusual web server child processes",
                    "Hunt for exploitation patterns (T1190) - web application attack signatures",
                    "Hunt for data exfiltration via web (T1041) - large uploads, unusual POST requests",
                ]
            )

        suggestions.append("⭐ BEST PRACTICE: Always pivot from IOCs to behavioral patterns for durable detection")

        return suggestions

    def get_mitre_attack_matrix(self) -> Dict:
        """Returns the MITRE ATT&CK matrix structure"""
        # This would be populated from actual MITRE data
        return {
            "tactics": [
                {
                    "id": "TA0043",
                    "name": "Reconnaissance",
                    "description": "The adversary is trying to gather information they can use to plan future operations.",
                },
                {
                    "id": "TA0042",
                    "name": "Resource Development",
                    "description": "The adversary is trying to establish resources they can use to support operations.",
                },
                {
                    "id": "TA0001",
                    "name": "Initial Access",
                    "description": "The adversary is trying to get into your network.",
                },
                {"id": "TA0002", "name": "Execution", "description": "The adversary is trying to run malicious code."},
                {
                    "id": "TA0003",
                    "name": "Persistence",
                    "description": "The adversary is trying to maintain their foothold.",
                },
                {
                    "id": "TA0004",
                    "name": "Privilege Escalation",
                    "description": "The adversary is trying to gain higher-level permissions.",
                },
                {
                    "id": "TA0005",
                    "name": "Defense Evasion",
                    "description": "The adversary is trying to avoid being detected.",
                },
                {
                    "id": "TA0006",
                    "name": "Credential Access",
                    "description": "The adversary is trying to steal account names and passwords.",
                },
                {
                    "id": "TA0007",
                    "name": "Discovery",
                    "description": "The adversary is trying to figure out your environment.",
                },
                {
                    "id": "TA0008",
                    "name": "Lateral Movement",
                    "description": "The adversary is trying to move through your environment.",
                },
                {
                    "id": "TA0009",
                    "name": "Collection",
                    "description": "The adversary is trying to gather data of interest to their goal.",
                },
                {
                    "id": "TA0011",
                    "name": "Command and Control",
                    "description": "The adversary is trying to communicate with compromised systems.",
                },
                {"id": "TA0010", "name": "Exfiltration", "description": "The adversary is trying to steal data."},
                {
                    "id": "TA0040",
                    "name": "Impact",
                    "description": "The adversary is trying to manipulate, interrupt, or destroy your systems and data.",
                },
            ],
            "techniques_by_tactic": self._get_techniques_by_tactic(),
        }

    async def _get_adversary_data(self, adversary_id: str) -> Dict:
        """Gets adversary data (mock implementation)"""
        # This would query actual MITRE ATT&CK data
        mock_actors = {
            "G0016": {
                "name": "APT29",
                "description": "APT29 is threat group that has been attributed to Russia's Foreign Intelligence Service.",
                "aliases": ["Cozy Bear", "The Dukes"],
                "country": "Russia",
                "motivation": "Espionage",
                "domains": ["cozy-bear.com", "dukes-apt.org"],
                "ips": ["192.168.1.100", "10.0.0.50"],
                "target_sectors": ["Government", "Technology"],
                "sophistication": "High",
            },
            "G0007": {
                "name": "APT28",
                "description": "APT28 is a threat group that has been attributed to Russia's Main Intelligence Directorate.",
                "aliases": ["Fancy Bear", "Pawn Storm"],
                "country": "Russia",
                "motivation": "Espionage",
                "domains": ["fancy-bear.net", "pawn-storm.ru"],
                "ips": ["203.0.113.1", "198.51.100.2"],
                "target_sectors": ["Military", "Government"],
                "sophistication": "High",
            },
        }

        return mock_actors.get(
            adversary_id,
            {
                "name": "Unknown Actor",
                "description": "No information available",
                "aliases": [],
                "country": "Unknown",
                "motivation": "Unknown",
            },
        )

    async def _get_adversary_techniques(self, adversary_id: str) -> List[Dict]:
        """Gets techniques used by adversary (mock implementation)"""
        mock_techniques = {
            "G0016": [  # APT29
                {"id": "T1566.001", "name": "Spearphishing Attachment", "tactic": "Initial Access"},
                {"id": "T1055", "name": "Process Injection", "tactic": "Defense Evasion"},
                {"id": "T1003.001", "name": "LSASS Memory", "tactic": "Credential Access"},
                {"id": "T1071.001", "name": "Web Protocols", "tactic": "Command and Control"},
            ],
            "G0007": [  # APT28
                {"id": "T1566.002", "name": "Spearphishing Link", "tactic": "Initial Access"},
                {"id": "T1059.003", "name": "Windows Command Shell", "tactic": "Execution"},
                {"id": "T1083", "name": "File and Directory Discovery", "tactic": "Discovery"},
                {"id": "T1021.001", "name": "Remote Desktop Protocol", "tactic": "Lateral Movement"},
            ],
        }

        return mock_techniques.get(adversary_id, [])

    async def _get_technique_data(self, technique_id: str) -> Optional[Dict]:
        """Gets technique data (mock implementation)"""
        mock_techniques = {
            "T1055": {
                "name": "Process Injection",
                "description": "Adversaries may inject code into processes in order to evade process-based defenses.",
                "tactic": "Defense Evasion",
                "data_sources": ["Process", "API calls", "DLL monitoring"],
                "detection": "Monitor for suspicious process access patterns and API calls",
                "platforms": ["Windows", "macOS", "Linux"],
            },
            "T1003.001": {
                "name": "LSASS Memory",
                "description": "Adversaries may attempt to access credential material stored in LSASS memory.",
                "tactic": "Credential Access",
                "data_sources": ["Process", "Process access", "Handle"],
                "detection": "Monitor for processes accessing lsass.exe",
                "platforms": ["Windows"],
            },
        }

        return mock_techniques.get(technique_id)

    def _group_techniques_by_tactic(self, techniques: List[Dict]) -> Dict:
        """Groups techniques by their MITRE ATT&CK tactic"""
        tactics = {}
        for technique in techniques:
            tactic = technique.get("tactic", "Unknown")
            if tactic not in tactics:
                tactics[tactic] = []
            tactics[tactic].append(technique)
        return tactics

    def _map_to_pyramid(self, techniques: List[Dict]) -> Dict:
        """Maps techniques to Pyramid of Pain levels"""
        pyramid_mapping = {}
        for level in self.pyramid_of_pain.levels:
            pyramid_mapping[level] = []

        for technique in techniques:
            # Simple mapping based on technique characteristics
            if "hash" in technique["name"].lower():
                pyramid_mapping["hash_values"].append(technique)
            elif "network" in technique["name"].lower() or "protocol" in technique["name"].lower():
                pyramid_mapping["network_artifacts"].append(technique)
            elif "tool" in technique["name"].lower():
                pyramid_mapping["tools"].append(technique)
            else:
                pyramid_mapping["ttps"].append(technique)

        return pyramid_mapping

    def _map_to_kill_chain(self, techniques: List[Dict]) -> Dict:
        """Maps techniques to Cyber Kill Chain phases"""
        kill_chain_mapping = {phase: [] for phase in self.cyber_kill_chain.phases}

        for technique in techniques:
            tactic = technique.get("tactic", "")
            # Map tactic to kill chain phase (simplified mapping)
            if "initial access" in tactic.lower():
                kill_chain_mapping["delivery"].append(technique)
            elif "execution" in tactic.lower():
                kill_chain_mapping["exploitation"].append(technique)
            elif "persistence" in tactic.lower():
                kill_chain_mapping["installation"].append(technique)
            elif "command and control" in tactic.lower():
                kill_chain_mapping["command_and_control"].append(technique)
            else:
                kill_chain_mapping["actions_on_objectives"].append(technique)

        return kill_chain_mapping

    def _calculate_hunt_priority(self, techniques: List[Dict]) -> List[Dict]:
        """Calculates hunting priority for techniques"""
        priorities = []
        for technique in techniques:
            priority_score = 5  # Base priority

            # Increase priority for high-impact tactics
            high_impact_tactics = ["credential access", "lateral movement", "persistence"]
            if any(tactic in technique.get("tactic", "").lower() for tactic in high_impact_tactics):
                priority_score += 3

            # Increase priority for commonly observed techniques
            common_techniques = ["T1055", "T1003", "T1021", "T1083"]
            if technique["id"] in common_techniques:
                priority_score += 2

            priorities.append(
                {
                    "technique": technique,
                    "priority_score": priority_score,
                    "rationale": self._generate_priority_rationale(technique, priority_score),
                }
            )

        return sorted(priorities, key=lambda x: x["priority_score"], reverse=True)

    def _is_high_priority(self, technique: Dict) -> bool:
        """Determines if a technique is high priority for hunting"""
        high_priority_tactics = ["credential access", "lateral movement", "persistence"]
        return any(tactic in technique.get("tactic", "").lower() for tactic in high_priority_tactics)

    def _map_data_sources_to_telemetry(self, data_sources: List[str]) -> Dict:
        """Maps MITRE data sources to telemetry requirements"""
        telemetry_mapping = {
            "Process": ["Sysmon Event ID 1", "Windows Event ID 4688"],
            "Process access": ["Sysmon Event ID 10"],
            "API calls": ["API Monitoring tools", "EDR solutions"],
            "Network": ["Network flow logs", "Packet capture"],
            "Registry": ["Sysmon Event ID 12, 13, 14"],
            "File": ["Sysmon Event ID 11", "File access logs"],
        }

        requirements = {}
        for source in data_sources:
            requirements[source] = telemetry_mapping.get(source, ["Generic monitoring"])

        return requirements

    def _generate_detection_queries(self, technique_id: str) -> List[str]:
        """Generates detection queries for a technique"""
        # This would contain actual query templates
        query_templates = {
            "T1055": [
                "index=sysmon EventCode=8 | stats count by SourceImage, TargetImage",
                "index=endpoint process_injection=true | stats count by process_name",
            ],
            "T1003.001": [
                'index=sysmon EventCode=10 TargetImage="*lsass.exe" | stats count by SourceImage',
                'index=windows EventCode=4656 Object_Name="*lsass.exe" | stats count by Account_Name',
            ],
        }

        return query_templates.get(technique_id, ["# No queries available"])

    def _get_pyramid_level_for_technique(self, technique_id: str) -> str:
        """Gets pyramid of pain level for a technique"""
        # Simplified mapping
        technique_pyramid_map = {
            "T1055": "ttps",
            "T1003": "ttps",
            "T1083": "host_artifacts",
            "T1021": "network_artifacts",
        }

        return technique_pyramid_map.get(technique_id, "ttps")

    def _get_techniques_by_tactic(self) -> Dict:
        """Returns techniques organized by tactic (mock data)"""
        return {
            "TA0001": [  # Initial Access
                {"id": "T1566.001", "name": "Spearphishing Attachment"},
                {"id": "T1566.002", "name": "Spearphishing Link"},
                {"id": "T1190", "name": "Exploit Public-Facing Application"},
            ],
            "TA0002": [  # Execution
                {"id": "T1059.003", "name": "Windows Command Shell"},
                {"id": "T1059.001", "name": "PowerShell"},
                {"id": "T1204.002", "name": "Malicious File"},
            ],
            # ... more tactics and techniques would be here
        }

    def _generate_priority_rationale(self, technique: Dict, score: int) -> str:
        """Generates rationale for priority scoring"""
        rationales = []

        if score >= 8:
            rationales.append("High-impact technique frequently used by adversaries")
        elif score >= 6:
            rationales.append("Moderate-impact technique with good detection opportunities")
        else:
            rationales.append("Lower-priority technique but still relevant")

        return "; ".join(rationales)
