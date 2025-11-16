"""
TaHiTI (Targeted Hunting integrating Threat Intelligence) Framework
Developed by the Dutch Payments Association (Betaalvereniging)

A standardized, repeatable threat hunting methodology combining threat intelligence
with threat hunting practices across 3 phases and 6 steps.
"""

import uuid
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional


class TaHiTIPhase(Enum):
    """Three phases of TaHiTI methodology"""

    INITIALIZE = "initialize"  # Process input
    HUNT = "hunt"  # Execution phase
    FINALIZE = "finalize"  # Process output


class TaHiTIStep(Enum):
    """Six steps across the three phases"""

    # Initialize Phase
    TRIGGER = "trigger"  # Step 1: Initial trigger/input
    ABSTRACT = "abstract"  # Step 2: Create hunt abstract

    # Hunt Phase
    HYPOTHESIS = "hypothesis"  # Step 3: Formulate hypothesis
    INVESTIGATION = "investigation"  # Step 4: Execute investigation

    # Finalize Phase
    VALIDATION = "validation"  # Step 5: Validate hypothesis
    HANDOVER = "handover"  # Step 6: Hand over results


class TriggerSource(Enum):
    """Sources that can trigger a TaHiTI hunt"""

    THREAT_INTELLIGENCE = "threat_intelligence"
    SECURITY_INCIDENT = "security_incident"
    VULNERABILITY_REPORT = "vulnerability_report"
    ANOMALY_DETECTION = "anomaly_detection"
    PEER_SHARING = "peer_sharing"
    SCHEDULED_BASELINE = "scheduled_baseline"
    RED_TEAM_EXERCISE = "red_team_exercise"


class HandoverProcess(Enum):
    """Processes that receive hunt results"""

    INCIDENT_RESPONSE = "incident_response"
    SECURITY_MONITORING = "security_monitoring"
    THREAT_INTELLIGENCE = "threat_intelligence"
    VULNERABILITY_MANAGEMENT = "vulnerability_management"
    DETECTION_ENGINEERING = "detection_engineering"
    RISK_MANAGEMENT = "risk_management"
    SECURITY_ARCHITECTURE = "security_architecture"


class TaHiTIHunt:
    """Represents a TaHiTI threat hunt investigation"""

    def __init__(self, hunt_id: str, trigger_source: TriggerSource, trigger_description: str):
        self.hunt_id = hunt_id
        self.trigger_source = trigger_source
        self.trigger_description = trigger_description
        self.created_at = datetime.utcnow()

        # Phase tracking
        self.current_phase = TaHiTIPhase.INITIALIZE
        self.current_step = TaHiTIStep.TRIGGER
        self.completed_steps: List[TaHiTIStep] = []

        # Initialize phase data
        self.abstract: Optional[Dict] = None

        # Hunt phase data
        self.hypothesis: Optional[str] = None
        self.investigation_data: Dict = {}
        self.threat_intelligence: List[Dict] = []

        # Finalize phase data
        self.validation_result: Optional[bool] = None
        self.findings: List[Dict] = []
        self.handover_targets: List[HandoverProcess] = []
        self.completed_at: Optional[datetime] = None

    def to_dict(self) -> Dict:
        """Convert hunt to dictionary representation"""
        return {
            "hunt_id": self.hunt_id,
            "trigger_source": self.trigger_source.value,
            "trigger_description": self.trigger_description,
            "current_phase": self.current_phase.value,
            "current_step": self.current_step.value,
            "hypothesis": self.hypothesis,
            "validation_result": self.validation_result,
            "findings_count": len(self.findings),
            "created_at": self.created_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }


class TaHiTIFramework:
    """
    Implementation of TaHiTI (Targeted Hunting integrating Threat Intelligence)

    Core Principles:
    - Intelligence-Driven Focus: Threat intelligence drives hunting activities
    - Contextual Enrichment: Continuous intelligence use during investigation
    - Risk-Based Prioritization: Focus on highest-risk threats
    - Collaborative Foundation: Information sharing within communities
    """

    def __init__(self):
        self.active_hunts: Dict[str, TaHiTIHunt] = {}
        self.hunt_backlog: List[Dict] = []
        self.completed_hunts: List[TaHiTIHunt] = []

    # ===== INITIALIZE PHASE =====

    def initialize_hunt(
        self, trigger_source: TriggerSource, trigger_description: str, threat_intelligence: Optional[List[Dict]] = None
    ) -> TaHiTIHunt:
        """
        STEP 1-2: Initialize phase - Process input

        1. Trigger: Receive initial trigger for hunt
        2. Abstract: Create abstract and add to backlog

        Args:
            trigger_source: Source of the hunt trigger
            trigger_description: Description of what triggered this hunt
            threat_intelligence: Optional TI data associated with trigger

        Returns:
            TaHiTIHunt object representing the new hunt
        """
        hunt_id = self._generate_hunt_id()
        hunt = TaHiTIHunt(hunt_id, trigger_source, trigger_description)

        if threat_intelligence:
            hunt.threat_intelligence.extend(threat_intelligence)

        # Step 2: Create abstract and add to backlog
        abstract = self._create_hunt_abstract(hunt)
        hunt.abstract = abstract
        hunt.completed_steps.append(TaHiTIStep.TRIGGER)
        hunt.completed_steps.append(TaHiTIStep.ABSTRACT)

        # Add to backlog
        self.hunt_backlog.append(
            {
                "hunt_id": hunt_id,
                "abstract": abstract,
                "priority": self._calculate_priority(hunt),
                "added_at": datetime.utcnow(),
            }
        )

        self.active_hunts[hunt_id] = hunt
        return hunt

    def _create_hunt_abstract(self, hunt: TaHiTIHunt) -> Dict:
        """Create standardized hunt abstract"""
        return {
            "title": self._generate_hunt_title(hunt),
            "trigger_source": hunt.trigger_source.value,
            "description": hunt.trigger_description,
            "threat_intel_summary": self._summarize_threat_intel(hunt.threat_intelligence),
            "risk_level": self._assess_risk_level(hunt),
            "estimated_effort": self._estimate_effort(hunt),
            "recommended_data_sources": self._recommend_data_sources(hunt),
        }

    # ===== HUNT PHASE =====

    def formulate_hypothesis(
        self, hunt_id: str, hypothesis: str, supporting_intelligence: Optional[List[Dict]] = None
    ) -> Dict:
        """
        STEP 3: Formulate focused hypothesis based on trigger and intelligence

        Args:
            hunt_id: ID of the hunt
            hypothesis: Testable hypothesis statement
            supporting_intelligence: Additional TI supporting the hypothesis

        Returns:
            Dict containing hypothesis details
        """
        hunt = self.active_hunts.get(hunt_id)
        if not hunt:
            raise ValueError(f"Hunt {hunt_id} not found")

        # Validate we're in correct phase
        if hunt.current_phase != TaHiTIPhase.INITIALIZE:
            if hunt.current_phase != TaHiTIPhase.HUNT:
                raise ValueError(
                    f"Cannot formulate hypothesis in {
                        hunt.current_phase} phase"
                )

        # Validate hypothesis is testable
        if not self._validate_hypothesis(hypothesis):
            raise ValueError("Hypothesis must be specific and testable")

        hunt.hypothesis = hypothesis
        hunt.current_phase = TaHiTIPhase.HUNT
        hunt.current_step = TaHiTIStep.HYPOTHESIS
        hunt.completed_steps.append(TaHiTIStep.HYPOTHESIS)

        if supporting_intelligence:
            hunt.threat_intelligence.extend(supporting_intelligence)

        return {
            "hunt_id": hunt_id,
            "hypothesis": hypothesis,
            "threat_intel_count": len(hunt.threat_intelligence),
            "recommended_queries": self._generate_hypothesis_queries(hypothesis, hunt),
        }

    def execute_investigation(
        self,
        hunt_id: str,
        data_sources: List[str],
        query_results: List[Dict],
        enrichment_intelligence: Optional[List[Dict]] = None,
    ) -> Dict:
        """
        STEP 4: Execute targeted hunting investigation

        Continuous threat intelligence enrichment throughout investigation

        Args:
            hunt_id: ID of the hunt
            data_sources: Data sources queried
            query_results: Results from hunting queries
            enrichment_intelligence: TI used to enrich findings

        Returns:
            Dict containing investigation results
        """
        hunt = self.active_hunts.get(hunt_id)
        if not hunt:
            raise ValueError(f"Hunt {hunt_id} not found")

        if hunt.current_step != TaHiTIStep.HYPOTHESIS:
            raise ValueError("Must formulate hypothesis before investigation")

        # Store investigation data
        hunt.investigation_data = {
            "data_sources": data_sources,
            "query_results": query_results,
            "findings": self._analyze_results(query_results, hunt),
            "investigation_timestamp": datetime.utcnow().isoformat(),
        }

        # Enrich with threat intelligence
        if enrichment_intelligence:
            hunt.threat_intelligence.extend(enrichment_intelligence)
            hunt.investigation_data["enriched_findings"] = self._enrich_with_intelligence(
                hunt.investigation_data["findings"], enrichment_intelligence
            )

        hunt.current_step = TaHiTIStep.INVESTIGATION
        hunt.completed_steps.append(TaHiTIStep.INVESTIGATION)

        return {
            "hunt_id": hunt_id,
            "findings_count": len(hunt.investigation_data["findings"]),
            "data_sources_queried": len(data_sources),
            "intelligence_enrichments": len(enrichment_intelligence) if enrichment_intelligence else 0,
        }

    # ===== FINALIZE PHASE =====

    def validate_hypothesis(
            self, hunt_id: str, validation_evidence: List[Dict], analyst_assessment: str) -> Dict:
        """
        STEP 5: Validate hypothesis based on investigation results

        Args:
            hunt_id: ID of the hunt
            validation_evidence: Evidence supporting/refuting hypothesis
            analyst_assessment: Analyst's conclusion

        Returns:
            Dict containing validation results
        """
        hunt = self.active_hunts.get(hunt_id)
        if not hunt:
            raise ValueError(f"Hunt {hunt_id} not found")

        if hunt.current_step != TaHiTIStep.INVESTIGATION:
            raise ValueError("Must complete investigation before validation")

        # Assess validation
        validation_result = self._assess_hypothesis_validation(
            hunt.hypothesis, validation_evidence, analyst_assessment)

        hunt.validation_result = validation_result["validated"]
        hunt.findings = validation_result["key_findings"]
        hunt.current_phase = TaHiTIPhase.FINALIZE
        hunt.current_step = TaHiTIStep.VALIDATION
        hunt.completed_steps.append(TaHiTIStep.VALIDATION)

        return validation_result

    def handover_results(
        self, hunt_id: str, target_processes: List[HandoverProcess], recommendations: List[Dict]
    ) -> Dict:
        """
        STEP 6: Hand over hunt results to relevant processes

        Args:
            hunt_id: ID of the hunt
            target_processes: Processes that should receive results
            recommendations: Actionable recommendations for each process

        Returns:
            Dict containing handover details
        """
        hunt = self.active_hunts.get(hunt_id)
        if not hunt:
            raise ValueError(f"Hunt {hunt_id} not found")

        if hunt.current_step != TaHiTIStep.VALIDATION:
            raise ValueError("Must validate hypothesis before handover")

        hunt.handover_targets = target_processes
        hunt.current_step = TaHiTIStep.HANDOVER
        hunt.completed_steps.append(TaHiTIStep.HANDOVER)
        hunt.completed_at = datetime.utcnow()

        # Create handover packages for each target process
        handover_packages = {}
        for process in target_processes:
            handover_packages[process.value] = self._create_handover_package(
                hunt, process, recommendations)

        # Move to completed hunts
        self.completed_hunts.append(hunt)
        del self.active_hunts[hunt_id]

        return {
            "hunt_id": hunt_id,
            "handover_processes": [p.value for p in target_processes],
            "packages": handover_packages,
            "hunt_duration": (hunt.completed_at - hunt.created_at).total_seconds() / 3600,
            "completed_at": hunt.completed_at.isoformat(),
        }

    # ===== HELPER METHODS =====

    def _generate_hunt_id(self) -> str:
        """Generate unique TaHiTI hunt identifier"""
        return f"TAHITI-{uuid.uuid4().hex[:8].upper()}"

    def _generate_hunt_title(self, hunt: TaHiTIHunt) -> str:
        """Generate descriptive hunt title"""
        source = hunt.trigger_source.value.replace("_", " ").title()
        return f"{source}: {hunt.trigger_description[:50]}"

    def _summarize_threat_intel(self, intel: List[Dict]) -> str:
        """Summarize threat intelligence for abstract"""
        if not intel:
            return "No threat intelligence available"
        return f"{
            len(intel)} threat intelligence items associated with this hunt"

    def _assess_risk_level(self, hunt: TaHiTIHunt) -> str:
        """Assess risk level based on trigger and intelligence"""
        # Risk-based prioritization principle
        high_risk_sources = [TriggerSource.SECURITY_INCIDENT, TriggerSource.THREAT_INTELLIGENCE]

        if hunt.trigger_source in high_risk_sources:
            return "HIGH"
        elif len(hunt.threat_intelligence) > 3:
            return "MEDIUM"
        return "LOW"

    def _estimate_effort(self, hunt: TaHiTIHunt) -> str:
        """Estimate effort required for hunt"""
        if hunt.trigger_source == TriggerSource.SCHEDULED_BASELINE:
            return "LOW"
        elif len(hunt.threat_intelligence) > 5:
            return "HIGH"
        return "MEDIUM"

    def _recommend_data_sources(self, hunt: TaHiTIHunt) -> List[str]:
        """Recommend data sources based on trigger"""
        # Basic mapping - can be enhanced with intelligence
        return ["endpoint_logs", "network_traffic", "authentication_logs", "threat_intel_feeds"]

    def _calculate_priority(self, hunt: TaHiTIHunt) -> int:
        """Calculate hunt priority for backlog (1=highest, 5=lowest)"""
        risk = self._assess_risk_level(hunt)
        if risk == "HIGH":
            return 1
        elif risk == "MEDIUM":
            return 3
        return 5

    def _validate_hypothesis(self, hypothesis: str) -> bool:
        """Validate hypothesis is specific and testable"""
        required_length = 20
        testable_indicators = ["will", "using", "through", "by", "when"]

        if len(hypothesis) < required_length:
            return False

        return any(indicator in hypothesis.lower() for indicator in testable_indicators)

    def _generate_hypothesis_queries(self, hypothesis: str, hunt: TaHiTIHunt) -> List[str]:
        """Generate queries based on hypothesis and threat intelligence"""
        queries = []

        # Basic query generation - enhanced with TI context
        if "lateral movement" in hypothesis.lower():
            queries.append(
                "index=windows EventCode=4624 Logon_Type=3 | stats count by src_ip, dest_ip")
        if "credential" in hypothesis.lower():
            queries.append("index=endpoint process_name IN (lsass.exe, mimikatz.exe)")
        if "persistence" in hypothesis.lower():
            queries.append(
                "index=windows (EventCode=4698 OR EventCode=4699) | table TaskName, Author")

        # Add intelligence-driven queries from TI
        for intel in hunt.threat_intelligence:
            if "ioc" in intel:
                queries.append(f"search {intel['ioc']}")

        return queries if queries else ["index=* | head 100"]

    def _analyze_results(self, query_results: List[Dict], hunt: TaHiTIHunt) -> List[Dict]:
        """Analyze query results for findings"""
        findings = []

        for result in query_results:
            # Simple finding extraction - can be enhanced
            if result.get("anomaly_score", 0) > 0.7:
                findings.append({"type": "anomaly", "severity": "high", "data": result})

        return findings

    def _enrich_with_intelligence(
            self, findings: List[Dict], intelligence: List[Dict]) -> List[Dict]:
        """Enrich findings with contextual threat intelligence"""
        enriched = []

        for finding in findings:
            enriched_finding = finding.copy()
            enriched_finding["threat_context"] = []

            # Match intelligence to findings
            for intel in intelligence:
                if self._intelligence_matches_finding(intel, finding):
                    enriched_finding["threat_context"].append(intel)

            enriched.append(enriched_finding)

        return enriched

    def _intelligence_matches_finding(self, intel: Dict, finding: Dict) -> bool:
        """Check if intelligence is relevant to finding"""
        # Simple matching - can be enhanced with ML
        return True  # Placeholder

    def _assess_hypothesis_validation(
            self, hypothesis: str, evidence: List[Dict], assessment: str) -> Dict:
        """Assess whether hypothesis was validated"""
        validated = "confirmed" in assessment.lower() or "validated" in assessment.lower()

        return {
            "validated": validated,
            "confidence": self._calculate_validation_confidence(evidence),
            "key_findings": evidence,
            "analyst_assessment": assessment,
            "hypothesis": hypothesis,
        }

    def _calculate_validation_confidence(self, evidence: List[Dict]) -> float:
        """Calculate confidence in validation"""
        if not evidence:
            return 0.0

        # More evidence = higher confidence
        return min(len(evidence) * 0.2, 1.0)

    def _create_handover_package(self, hunt: TaHiTIHunt,
                                 process: HandoverProcess, recommendations: List[Dict]) -> Dict:
        """Create handover package for target process"""
        package = {
            "hunt_id": hunt.hunt_id,
            "hunt_summary": hunt.abstract,
            "hypothesis": hunt.hypothesis,
            "validated": hunt.validation_result,
            "findings": hunt.findings,
            "threat_intelligence": hunt.threat_intelligence,
            "created_at": hunt.created_at.isoformat(),
            "completed_at": hunt.completed_at.isoformat(),
        }

        # Add process-specific recommendations
        process_recs = [r for r in recommendations if r.get("target") == process]
        package["recommendations"] = process_recs

        # Customize based on target process
        if process == HandoverProcess.INCIDENT_RESPONSE:
            package["iocs"] = self._extract_iocs(hunt)
            package["response_priority"] = self._calculate_response_priority(hunt)
        elif process == HandoverProcess.DETECTION_ENGINEERING:
            package["detection_rules"] = self._generate_detection_rules(hunt)
        elif process == HandoverProcess.THREAT_INTELLIGENCE:
            package["intelligence_gaps"] = self._identify_intelligence_gaps(hunt)

        return package

    def _extract_iocs(self, hunt: TaHiTIHunt) -> List[Dict]:
        """Extract IOCs from hunt findings"""
        iocs = []
        for finding in hunt.findings:
            if "ioc" in finding:
                iocs.append(finding["ioc"])
        return iocs

    def _calculate_response_priority(self, hunt: TaHiTIHunt) -> str:
        """Calculate incident response priority"""
        if hunt.validation_result and self._assess_risk_level(hunt) == "HIGH":
            return "CRITICAL"
        elif hunt.validation_result:
            return "HIGH"
        return "MEDIUM"

    def _generate_detection_rules(self, hunt: TaHiTIHunt) -> List[Dict]:
        """Generate detection rules from validated hunt"""
        rules = []
        if hunt.validation_result and hunt.hypothesis:
            rules.append(
                {
                    "name": f"Detection rule from {hunt.hunt_id}",
                    "logic": hunt.hypothesis,
                    "data_sources": hunt.investigation_data.get("data_sources", []),
                }
            )
        return rules

    def _identify_intelligence_gaps(self, hunt: TaHiTIHunt) -> List[str]:
        """Identify gaps in threat intelligence"""
        gaps = []
        if len(hunt.threat_intelligence) < 3:
            gaps.append("Limited threat intelligence available for this hunt")
        return gaps

    def get_hunt_status(self, hunt_id: str) -> Dict:
        """Get current status of a hunt"""
        hunt = self.active_hunts.get(hunt_id)
        if not hunt:
            # Check completed hunts
            for completed in self.completed_hunts:
                if completed.hunt_id == hunt_id:
                    return completed.to_dict()
            raise ValueError(f"Hunt {hunt_id} not found")

        return hunt.to_dict()

    def get_hunt_backlog(self, prioritized: bool = True) -> List[Dict]:
        """Get hunt backlog, optionally prioritized"""
        if prioritized:
            return sorted(self.hunt_backlog, key=lambda x: x["priority"])
        return self.hunt_backlog
