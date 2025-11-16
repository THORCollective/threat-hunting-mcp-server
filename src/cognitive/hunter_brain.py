"""Implements expert threat hunter cognitive patterns"""

import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List

logger = logging.getLogger(__name__)


@dataclass
class Hypothesis:
    """Represents a threat hunting hypothesis"""

    text: str
    confidence: float
    evidence: List[Dict]
    alternative_explanations: List[str]
    created_at: datetime


@dataclass
class BiasIndicator:
    """Indicates potential cognitive bias in analysis"""

    bias_type: str
    severity: float
    description: str
    mitigation: str


class BiasDetector:
    """Detects cognitive biases in threat hunting"""

    def detect_confirmation_bias(self, evidence: Dict) -> bool:
        """Detects if analyst is only seeking confirming evidence"""
        positive_indicators = evidence.get("positive_indicators", [])
        negative_indicators = evidence.get("negative_indicators", [])

        # Confirmation bias if only positive evidence considered
        if len(positive_indicators) > 0 and len(negative_indicators) == 0:
            logger.warning("Potential confirmation bias detected: no negative evidence considered")
            return True

        # Check for evidence imbalance
        if len(positive_indicators) > len(negative_indicators) * 3:
            logger.warning("Evidence imbalance detected - consider alternative explanations")
            return True

        return False

    def detect_anchoring_bias(self, initial_hypothesis: str, current_hypothesis: str) -> bool:
        """Detects if analyst is anchored to initial hypothesis"""
        # If hypotheses are identical after investigation, possible anchoring
        return initial_hypothesis.lower() == current_hypothesis.lower()

    def detect_availability_bias(self, threat_actor: str, recent_news: List[str]) -> bool:
        """Detects if recent news is overly influencing assessment"""
        # Check if threat actor mentioned in recent news
        for news in recent_news:
            if threat_actor.lower() in news.lower():
                logger.warning(f"Availability bias possible: {threat_actor} recently in news")
                return True
        return False


class ThreatHunterCognition:
    """Implements expert threat hunter cognitive patterns"""

    def __init__(self):
        self.hypothesis_confidence_threshold = 0.7
        self.hunt_stop_criteria = {
            "coverage_achieved": 0.8,
            "diminishing_returns": True,
            "time_limit_hours": 4,
            "confidence_threshold": 0.9,
        }
        self.bias_mitigation = BiasDetector()
        self.pyramid_of_pain_weights = {
            "hash_values": 0.1,
            "ip_addresses": 0.2,
            "domain_names": 0.3,
            "network_artifacts": 0.4,
            "host_artifacts": 0.5,
            "tools": 0.7,
            "ttps": 1.0,
        }

    async def generate_competing_hypotheses(self, initial_hypothesis: str, context: Dict) -> List[Hypothesis]:
        """
        Forces consideration of alternative explanations using
        Analysis of Competing Hypotheses (ACH)
        """
        alternatives = []

        # Generate benign explanation
        benign = self._generate_benign_explanation(initial_hypothesis, context)
        alternatives.append(
            Hypothesis(
                text=benign, confidence=0.3, evidence=[], alternative_explanations=[], created_at=datetime.utcnow()
            )
        )

        # Generate insider threat hypothesis
        insider = self._generate_insider_hypothesis(initial_hypothesis, context)
        alternatives.append(
            Hypothesis(
                text=insider, confidence=0.4, evidence=[], alternative_explanations=[], created_at=datetime.utcnow()
            )
        )

        # Generate external threat hypothesis
        external = self._generate_external_hypothesis(initial_hypothesis, context)
        alternatives.append(
            Hypothesis(
                text=external, confidence=0.5, evidence=[], alternative_explanations=[], created_at=datetime.utcnow()
            )
        )

        # Generate supply chain hypothesis
        supply_chain = self._generate_supply_chain_hypothesis(initial_hypothesis, context)
        alternatives.append(
            Hypothesis(
                text=supply_chain,
                confidence=0.3,
                evidence=[],
                alternative_explanations=[],
                created_at=datetime.utcnow(),
            )
        )

        return self._rank_hypotheses_by_evidence(alternatives, context)

    async def assess_hunt_confidence(self, evidence: Dict, hypothesis: str) -> Dict[str, float]:
        """Calculates confidence score accounting for biases"""
        confidence_factors = {}

        # Check for confirmation bias
        has_confirmation_bias = self.bias_mitigation.detect_confirmation_bias(evidence)
        if has_confirmation_bias:
            confidence_factors["confirmation_bias_penalty"] = -0.2
        else:
            confidence_factors["confirmation_bias_penalty"] = 0.0

        # Weight evidence by pyramid of pain level
        weighted_score = self._weight_by_pyramid_level(evidence)
        confidence_factors["pyramid_weighted_score"] = weighted_score

        # Consider negative evidence (what we didn't find)
        absence_factor = self._evaluate_absence_of_expected_indicators(evidence)
        confidence_factors["absence_factor"] = absence_factor

        # Calculate final confidence
        final_confidence = self._calculate_final_confidence(weighted_score, absence_factor, has_confirmation_bias)
        confidence_factors["final_confidence"] = final_confidence

        return confidence_factors

    def should_stop_hunt(self, hunt_data: Dict) -> Dict[str, bool]:
        """Determines if hunt should be stopped based on multiple criteria"""
        stop_reasons = {}

        # Check coverage achieved
        coverage = hunt_data.get("coverage", 0.0)
        stop_reasons["coverage_achieved"] = coverage >= self.hunt_stop_criteria["coverage_achieved"]

        # Check for diminishing returns
        recent_findings = hunt_data.get("recent_findings", [])
        if len(recent_findings) > 5:
            # If last 5 iterations found nothing new
            new_findings = [f for f in recent_findings[-5:] if f.get("is_new", False)]
            stop_reasons["diminishing_returns"] = len(new_findings) == 0
        else:
            stop_reasons["diminishing_returns"] = False

        # Check time limit
        hunt_duration = hunt_data.get("duration_hours", 0)
        stop_reasons["time_limit_exceeded"] = hunt_duration >= self.hunt_stop_criteria["time_limit_hours"]

        # Check confidence threshold
        confidence = hunt_data.get("confidence", 0.0)
        stop_reasons["high_confidence_achieved"] = confidence >= self.hunt_stop_criteria["confidence_threshold"]

        # Overall decision
        stop_reasons["should_stop"] = any(
            [
                stop_reasons["coverage_achieved"],
                stop_reasons["diminishing_returns"],
                stop_reasons["time_limit_exceeded"],
                stop_reasons["high_confidence_achieved"],
            ]
        )

        return stop_reasons

    def _generate_benign_explanation(self, hypothesis: str, context: Dict) -> str:
        """Generates a benign alternative explanation"""
        if "lateral movement" in hypothesis.lower():
            return "Administrative activity: IT staff performing legitimate system maintenance"
        elif "credential access" in hypothesis.lower():
            return "Authorized security tool: Legitimate credential manager or password vault access"
        elif "persistence" in hypothesis.lower():
            return "Software update: Legitimate application creating scheduled tasks for updates"
        elif "exfiltration" in hypothesis.lower():
            return "Backup operation: Scheduled data backup to cloud storage"
        else:
            return "Normal business operations: Legitimate user activity within expected parameters"

    def _generate_insider_hypothesis(self, hypothesis: str, context: Dict) -> str:
        """Generates insider threat hypothesis"""
        return f"Insider threat scenario: Authorized user with legitimate access performing malicious activity related to {
            hypothesis.lower()}"

    def _generate_external_hypothesis(self, hypothesis: str, context: Dict) -> str:
        """Generates external threat hypothesis"""
        return f"External threat actor: Unauthorized access via compromised credentials or vulnerability exploitation for {
            hypothesis.lower()}"

    def _generate_supply_chain_hypothesis(self, hypothesis: str, context: Dict) -> str:
        """Generates supply chain compromise hypothesis"""
        return f"Supply chain compromise: Trusted third-party software or vendor access being abused for {
            hypothesis.lower()}"

    def _rank_hypotheses_by_evidence(self, hypotheses: List[Hypothesis], context: Dict) -> List[Hypothesis]:
        """Ranks hypotheses based on available evidence"""
        # In production, this would use actual evidence matching
        # For now, return sorted by initial confidence
        return sorted(hypotheses, key=lambda h: h.confidence, reverse=True)

    def _weight_by_pyramid_level(self, evidence: Dict) -> float:
        """Weights evidence based on Pyramid of Pain level"""
        total_weight = 0.0
        evidence_count = 0

        for level, weight in self.pyramid_of_pain_weights.items():
            indicators = evidence.get(level, [])
            if indicators:
                total_weight += weight * len(indicators)
                evidence_count += len(indicators)

        if evidence_count == 0:
            return 0.0

        return total_weight / evidence_count

    def _evaluate_absence_of_expected_indicators(self, evidence: Dict) -> float:
        """
        Evaluates the significance of expected indicators that were NOT found.
        Absence of evidence can be evidence of absence in some cases.
        """
        expected_indicators = evidence.get("expected_indicators", [])
        found_indicators = evidence.get("found_indicators", [])

        if not expected_indicators:
            return 0.0

        # Calculate percentage of expected indicators that are missing
        missing_count = len(set(expected_indicators) - set(found_indicators))
        absence_ratio = missing_count / len(expected_indicators)

        # High absence ratio lowers confidence
        return -0.3 * absence_ratio

    def _calculate_final_confidence(
        self, weighted_score: float, absence_factor: float, has_confirmation_bias: bool
    ) -> float:
        """Calculates final confidence score"""
        base_confidence = weighted_score

        # Apply absence factor
        base_confidence += absence_factor

        # Apply bias penalty
        if has_confirmation_bias:
            base_confidence -= 0.2

        # Clamp between 0 and 1
        return max(0.0, min(1.0, base_confidence))

    def generate_investigation_questions(self, hypothesis: str, evidence: Dict) -> List[str]:
        """
        Generates investigative questions to avoid tunnel vision
        and ensure thorough analysis
        """
        questions = []

        # Question the hypothesis
        questions.append(f"What evidence would disprove this hypothesis: {hypothesis}?")
        questions.append("What alternative explanations have we not considered?")

        # Question the evidence
        questions.append("What evidence are we missing that we should have?")
        questions.append("Are we giving too much weight to recent or memorable events?")

        # Question the analysis
        questions.append("What assumptions are we making that might be wrong?")
        questions.append("How would an adversary try to evade this detection?")

        # Contextual questions
        if evidence.get("ttps"):
            questions.append("Are these TTPs consistent with known threat actors in our industry?")

        if evidence.get("tools"):
            questions.append("Could these tools be used for legitimate purposes?")

        questions.append("Have we consulted with system owners about normal behavior?")
        questions.append("What would a false positive look like in this scenario?")

        return questions
