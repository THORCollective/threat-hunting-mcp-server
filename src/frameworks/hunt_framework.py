import uuid
from datetime import datetime
from typing import Dict, List

from ..models.hunt import HuntMaturityLevel, HuntType, ThreatHunt


class ThreatHuntingFramework:
    """Integrates PEAK, SQRRL, and Intelligence-Driven methodologies"""

    def __init__(self):
        self.active_hunts: Dict[str, ThreatHunt] = {}
        self.hunt_library = self._load_hunt_library()
        self.pyramid_of_pain_levels = [
            "hash_values",
            "ip_addresses",
            "domain_names",
            "network_artifacts",
            "host_artifacts",
            "tools",
            "ttps",
        ]

    def create_hypothesis_driven_hunt(
            self, hypothesis: str, adversary: str, impact_scenario: str) -> ThreatHunt:
        """Creates a hypothesis-driven hunt following Gigamon methodology"""
        if not self._validate_hypothesis(hypothesis):
            raise ValueError("Hypothesis must be specific and testable")

        data_sources = self._identify_data_sources(hypothesis, adversary)
        queries = self._generate_test_queries(hypothesis, data_sources)

        hunt = ThreatHunt(
            hunt_id=self._generate_hunt_id(),
            hunt_type=HuntType.HYPOTHESIS_DRIVEN,
            hypothesis=hypothesis,
            data_sources=data_sources,
            queries=queries,
            phase="prepare",
            maturity_level=self._assess_maturity_level(),
            created_at=datetime.utcnow(),
        )

        self.active_hunts[hunt.hunt_id] = hunt
        return hunt

    def create_baseline_hunt(self, environment: str, metric: str) -> ThreatHunt:
        """Creates a baseline hunt to establish normal patterns"""
        hypothesis = f"Establish baseline for {metric} in {environment}"

        hunt = ThreatHunt(
            hunt_id=self._generate_hunt_id(),
            hunt_type=HuntType.BASELINE,
            hypothesis=hypothesis,
            data_sources=self._get_baseline_sources(environment, metric),
            queries=self._generate_baseline_queries(metric),
            phase="prepare",
            maturity_level=self._assess_maturity_level(),
            created_at=datetime.utcnow(),
        )

        self.active_hunts[hunt.hunt_id] = hunt
        return hunt

    def create_math_hunt(self, algorithm: str, anomaly_type: str) -> ThreatHunt:
        """Creates a Model-Assisted Threat Hunt using ML techniques"""
        hypothesis = f"Detect {anomaly_type} using {algorithm}"

        hunt = ThreatHunt(
            hunt_id=self._generate_hunt_id(),
            hunt_type=HuntType.MODEL_ASSISTED,
            hypothesis=hypothesis,
            data_sources=self._get_ml_data_sources(anomaly_type),
            queries=self._generate_ml_queries(algorithm, anomaly_type),
            phase="prepare",
            maturity_level=self._assess_maturity_level(),
            created_at=datetime.utcnow(),
        )

        self.active_hunts[hunt.hunt_id] = hunt
        return hunt

    def get_sqrrl_methodology(self) -> Dict:
        """Returns SQRRL framework components"""
        return {
            "hunting_maturity_model": {
                "HMM0": {"name": "Initial", "description": "Reactive, no data collection"},
                "HMM1": {"name": "Minimal", "description": "Threat feeds, moderate data collection"},
                "HMM2": {"name": "Procedural", "description": "Data quality, consistent analysis"},
                "HMM3": {"name": "Innovative", "description": "Automation, data science techniques"},
                "HMM4": {"name": "Leading", "description": "Highly automated, predictive capabilities"},
            },
            "hunt_loop": [
                "Create hypotheses based on threat intelligence",
                "Investigate via tools and techniques",
                "Uncover new patterns and TTPs",
                "Inform and enrich analytics",
            ],
            "hunt_matrix": self._get_hunt_matrix(),
        }

    def _validate_hypothesis(self, hypothesis: str) -> bool:
        """Validates hypothesis is testable and specific"""
        required_elements = ["will", "using", "to"]
        return any(element in hypothesis.lower() for element in required_elements)

    def _identify_data_sources(self, hypothesis: str, adversary: str) -> List[str]:
        """Determines required data sources based on hypothesis"""
        data_sources = []

        if "lateral movement" in hypothesis.lower():
            data_sources.extend(["windows_events", "network_logs", "authentication_logs"])
        if "credential" in hypothesis.lower():
            data_sources.extend(["endpoint_logs", "security_logs"])
        if "persistence" in hypothesis.lower():
            data_sources.extend(["registry_events", "file_system_events", "scheduled_tasks"])
        if "command and control" in hypothesis.lower() or "c2" in hypothesis.lower():
            data_sources.extend(["network_traffic", "dns_logs", "proxy_logs"])

        return data_sources if data_sources else ["general_security_logs"]

    def _generate_test_queries(self, hypothesis: str, data_sources: List[str]) -> List[str]:
        """Generates initial test queries based on hypothesis"""
        queries = []

        for source in data_sources:
            if source == "windows_events":
                queries.append(
                    f"index=windows EventCode=4624 OR EventCode=4625 | stats count by Account_Name")
            elif source == "network_logs":
                queries.append(f"index=network | stats count by src_ip, dest_ip")
            elif source == "authentication_logs":
                queries.append(f"index=auth | stats count by user, src_ip")
            else:
                queries.append(f"index={source} | head 100")

        return queries

    def _get_baseline_sources(self, environment: str, metric: str) -> List[str]:
        """Gets data sources needed for baseline establishment"""
        return [f"{environment}_logs", "performance_metrics", "user_behavior"]

    def _generate_baseline_queries(self, metric: str) -> List[str]:
        """Generates queries for baseline establishment"""
        return [
            f"index=* earliest=-30d@d latest=now | bucket _time span=1h | stats avg({metric}) as avg_value by _time",
            f"index=* | eventstats p95({metric}) as p95_baseline, avg({metric}) as avg_baseline",
        ]

    def _get_ml_data_sources(self, anomaly_type: str) -> List[str]:
        """Gets data sources for ML-based hunting"""
        return ["behavioral_data", "network_flows", "system_metrics"]

    def _generate_ml_queries(self, algorithm: str, anomaly_type: str) -> List[str]:
        """Generates queries for ML analysis"""
        return [
            f"index=* | eval ml_features='{algorithm}' | collect index=ml_input",
            f"| inputlookup ml_model_{algorithm}.csv",
        ]

    def _assess_maturity_level(self) -> HuntMaturityLevel:
        """Assesses current organizational maturity level"""
        return HuntMaturityLevel.HMM2_PROCEDURAL

    def _generate_hunt_id(self) -> str:
        """Generates unique hunt identifier"""
        return f"HUNT-{uuid.uuid4().hex[:8].upper()}"

    def _load_hunt_library(self) -> Dict:
        """Loads predefined hunt templates"""
        return {
            "lateral_movement": {
                "hypothesis_template": "Adversary will use {technique} for lateral movement",
                "data_sources": ["windows_events", "network_logs"],
                "queries": ["EventCode=4624 Logon_Type=3"],
            },
            "credential_dumping": {
                "hypothesis_template": "Adversary will dump credentials using {tool}",
                "data_sources": ["endpoint_logs", "process_logs"],
                "queries": ["process_name=lsass.exe action=read"],
            },
        }

    def _get_hunt_matrix(self) -> Dict:
        """Returns hunt matrix mapping activities to maturity levels"""
        return {
            "HMM1": ["Basic IOC searching", "Manual analysis"],
            "HMM2": ["Scripted hunting", "Consistent procedures"],
            "HMM3": ["Automated correlation", "ML-assisted analysis"],
            "HMM4": ["Predictive hunting", "Threat simulation"],
        }
