"""
THOR Collective Integration
Community-driven threat hunting initiative

Integrates HEARTH (community hunt repository) and thrunting philosophy
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class HEARTHHunt:
    """Represents a HEARTH community hunt submission"""

    hunt_id: str  # H-001 (Hypothesis), B-002 (Baseline), M-003 (Model-Assisted)
    hunt_type: str  # Hypothesis-Driven, Baseline, Model-Assisted
    title: str
    hypothesis: str
    data_sources: List[str]
    # Platform: Query mapping (splunk, kql, elastic, etc.)
    queries: Dict[str, str]
    peak_phase: str  # Prepare, Execute, Act
    contributor: str
    tags: List[str]
    relevancy_factors: Dict = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)


class ThreatHuntingRelevancyFactors:
    """
    THRF - Threat Hunting Relevancy Factors
    Makes hunts relevant to your specific organization
    From THOR Collective methodology
    """

    def __init__(self, organization_profile: Dict):
        self.profile = organization_profile

        # Core THRF factors (always considered)
        self.core_factors = {
            "industry_vertical": 0.25,
            "geographic_region": 0.15,
            "technology_stack": 0.30,
            "threat_intelligence": 0.20,
            "attack_surface": 0.10,
        }

        # Advanced THRF factors
        self.advanced_factors = {
            "regulatory_compliance": 0.15,
            "supply_chain": 0.10,
            "historical_incidents": 0.20,
            "peer_organizations": 0.10,
            "business_criticality": 0.25,
        }

    def calculate_hunt_relevancy(self, hunt: HEARTHHunt) -> Dict:
        """
        Calculate relevancy score for a hunt based on THRF
        Returns 0.0-1.0 score with factor breakdown
        """
        relevancy_score = 0.0
        factor_breakdown = {}

        # Industry vertical relevancy
        industry_score = self._assess_industry_relevance(hunt)
        relevancy_score += industry_score * self.core_factors["industry_vertical"]
        factor_breakdown["industry"] = industry_score

        # Geographic region relevancy
        geo_score = self._assess_geographic_relevance(hunt)
        relevancy_score += geo_score * self.core_factors["geographic_region"]
        factor_breakdown["geography"] = geo_score

        # Technology stack relevancy
        tech_score = self._assess_tech_relevance(hunt)
        relevancy_score += tech_score * self.core_factors["technology_stack"]
        factor_breakdown["technology"] = tech_score

        # Threat intelligence relevancy
        cti_score = self._assess_cti_relevance(hunt)
        relevancy_score += cti_score * self.core_factors["threat_intelligence"]
        factor_breakdown["threat_intel"] = cti_score

        # Attack surface relevancy
        surface_score = self._assess_attack_surface_relevance(hunt)
        relevancy_score += surface_score * self.core_factors["attack_surface"]
        factor_breakdown["attack_surface"] = surface_score

        return {
            "total_score": min(1.0, relevancy_score),
            "factor_breakdown": factor_breakdown,
            "recommendation": self._get_recommendation(relevancy_score),
            "reasoning": self._explain_score(factor_breakdown),
        }

    def _assess_industry_relevance(self, hunt: HEARTHHunt) -> float:
        """Your business model shapes your threat model"""
        org_industry = self.profile.get("industry", "").lower()
        hunt_industries = [i.lower() for i in hunt.relevancy_factors.get("industries", [])]

        if org_industry in hunt_industries:
            return 1.0  # Direct match
        elif "all" in hunt_industries or "any" in hunt_industries:
            return 0.6  # Generic hunt
        elif self._is_related_industry(org_industry, hunt_industries):
            return 0.7  # Related industry
        return 0.2  # Low relevance

    def _assess_geographic_relevance(self, hunt: HEARTHHunt) -> float:
        """Regional threats matter for your geography"""
        org_regions = [r.lower() for r in self.profile.get("regions", [])]
        hunt_regions = [r.lower() for r in hunt.relevancy_factors.get("regions", [])]

        if set(org_regions).intersection(hunt_regions):
            return 1.0
        elif "global" in hunt_regions or "worldwide" in hunt_regions:
            return 0.7
        return 0.3

    def _assess_tech_relevance(self, hunt: HEARTHHunt) -> float:
        """Focus on platforms that exist in your environment"""
        org_tech = self.profile.get("technology_stack", {})
        required_sources = hunt.data_sources

        available_count = 0
        for source in required_sources:
            if self._has_data_source(source, org_tech):
                available_count += 1

        if available_count == 0:
            return 0.0  # Can't run this hunt

        return available_count / len(required_sources)

    def _assess_cti_relevance(self, hunt: HEARTHHunt) -> float:
        """Align with current threat intelligence"""
        org_threats = self.profile.get("active_threats", [])
        hunt_tags = hunt.tags

        # Check for MITRE ATT&CK technique matches
        technique_matches = sum(
            1 for tag in hunt_tags if tag.startswith("T") and tag in org_threats)

        if technique_matches > 0:
            return min(1.0, technique_matches * 0.3)

        return 0.4  # Default moderate relevance

    def _assess_attack_surface_relevance(self, hunt: HEARTHHunt) -> float:
        """Match hunt to your actual attack surface"""
        attack_surface = self.profile.get("attack_surface", [])

        # Map hunt to attack surface components
        surface_components = {
            "web": ["web", "http", "browser"],
            "email": ["email", "phishing", "smtp"],
            "endpoint": ["endpoint", "workstation", "desktop"],
            "cloud": ["aws", "azure", "gcp", "cloud"],
            "network": ["network", "dns", "firewall"],
        }

        matches = 0
        for surface in attack_surface:
            for component, keywords in surface_components.items():
                if surface.lower() == component:
                    if any(kw in hunt.title.lower() or kw in hunt.hypothesis.lower()
                           for kw in keywords):
                        matches += 1

        return min(1.0, matches * 0.4)

    def _has_data_source(self, source: str, tech_stack: Dict) -> bool:
        """Check if organization has this data source"""
        source_lower = source.lower()

        # Check in various tech stack categories
        for category, tools in tech_stack.items():
            if isinstance(tools, list):
                if source_lower in [t.lower() for t in tools]:
                    return True
            elif isinstance(tools, str):
                if source_lower in tools.lower():
                    return True

        return False

    def _is_related_industry(self, org_industry: str, hunt_industries: List[str]) -> bool:
        """Check if industries are related"""
        industry_groups = {
            "financial": ["banking", "fintech", "insurance", "payments"],
            "healthcare": ["hospital", "pharma", "medical", "health"],
            "technology": ["software", "saas", "tech", "it"],
            "retail": ["ecommerce", "retail", "shopping"],
            "government": ["federal", "state", "local", "public sector"],
        }

        for group, industries in industry_groups.items():
            if org_industry in industries:
                for hunt_ind in hunt_industries:
                    if hunt_ind in industries:
                        return True

        return False

    def _get_recommendation(self, score: float) -> str:
        """Get recommendation based on score"""
        if score >= 0.8:
            return "HIGH PRIORITY - Highly relevant to your organization"
        elif score >= 0.6:
            return "RECOMMENDED - Good fit for your environment"
        elif score >= 0.4:
            return "CONSIDER - May provide value depending on resources"
        else:
            return "LOW PRIORITY - Limited relevance to your context"

    def _explain_score(self, breakdown: Dict) -> str:
        """Explain the relevancy score"""
        top_factors = sorted(breakdown.items(), key=lambda x: x[1], reverse=True)[:3]

        explanation = "Relevancy based on: "
        explanation += ", ".join([f"{factor} ({score:.2f})" for factor, score in top_factors])

        return explanation


class ThruntingPhilosophy:
    """
    Encodes THOR Collective's 'thrunting' philosophy
    Based on Sydney Marrone's Dispatch insights and community wisdom
    """

    def __init__(self):
        self.thrunting_principles = [
            "Hypothesis before query - know what you're looking for",
            "Baseline everything - you can't find weird without knowing normal",
            "Make friends with your data - understand its quirks",
            "Stop chasing ghosts - validate your detections",
            "Purpose doesn't kill creativity - THRF makes hunts matter",
            "Think like an adversary, act like a scientist",
            "Community over competition - share your findings",
        ]

        self.peak_wisdom = {
            "prepare": [
                "Research the adversary TTPs first",
                "Understand your data sources and their limitations",
                "Frame specific, testable hypotheses",
            ],
            "execute": [
                "Follow the data, not your assumptions",
                "Use eventstats for dynamic baselines",
                "Look for statistical outliers (2+ standard deviations)",
            ],
            "act": [
                "Document everything - future you will thank present you",
                "Create detections from validated findings",
                "Share back to the community via HEARTH",
            ],
        }

        self.spl_tricks = self._load_spl_dispatch_tricks()

    def apply_thrunting_wisdom(self, hunt_hypothesis: str, hunt_type: str) -> Dict:
        """Apply THOR Collective wisdom to improve hunt quality"""
        improvements = []
        wisdom_applied = []

        # Check hypothesis quality
        if not self._has_clear_hypothesis(hunt_hypothesis):
            improvements.append(
                {
                    "issue": "Vague hypothesis",
                    "principle": self.thrunting_principles[0],
                    "suggestion": "Be specific: WHO is doing WHAT using WHICH technique",
                    "example": "APT29 will use WMI for lateral movement to domain controllers",
                }
            )
        else:
            wisdom_applied.append("Clear, testable hypothesis ✓")

        # Check for baseline consideration
        if hunt_type == "Hypothesis-Driven":
            if "normal" not in hunt_hypothesis.lower() and "baseline" not in hunt_hypothesis.lower():
                improvements.append(
                    {
                        "issue": "No baseline reference",
                        "principle": self.thrunting_principles[1],
                        "suggestion": "Consider what normal looks like first",
                        "technique": "Use eventstats to calculate baseline in-query",
                    }
                )
        elif hunt_type == "Baseline":
            wisdom_applied.append("Baseline hunt - establishing normal ✓")

        # Check for specificity
        vague_terms = ["something", "anything", "stuff", "things", "activities"]
        if any(term in hunt_hypothesis.lower() for term in vague_terms):
            improvements.append(
                {
                    "issue": "Vague terminology",
                    "principle": "Be precise in your language",
                    "suggestion": "Replace vague terms with specific techniques or indicators",
                }
            )

        return {
            "improvements": improvements,
            "wisdom_applied": wisdom_applied,
            "thrunting_score": (
                len(wisdom_applied) / (len(wisdom_applied) + len(improvements))
                if (wisdom_applied or improvements)
                else 0.5
            ),
            "principles_to_remember": self.thrunting_principles[:3],
        }

    def optimize_spl_query(self, query: str) -> Dict:
        """Apply SPL optimization tricks from THOR Collective Dispatch"""
        optimized = query
        optimizations_applied = []

        # Add eventstats for dynamic baselining
        if "stats" in query and "eventstats" not in query and "by _time" not in query:
            # This is a favorite THOR Collective technique
            if "| stats count" in query:
                optimized = optimized.replace(
                    "| stats count", "| eventstats avg(count) as baseline_count | stats count"
                )
                optimizations_applied.append("Added eventstats for dynamic baseline")

        # Add automatic anomaly detection
        if "| stats count" in query and "where count >" not in query:
            optimized += "\n| where count > (baseline_count * 2)"
            optimizations_applied.append("Added 2x baseline anomaly threshold")

        # Add time bucketing if missing
        if "by _time" in query and "bucket" not in query and "bin" not in query:
            optimized = optimized.replace("by _time", "by _time span=1h")
            optimizations_applied.append("Added time bucketing")

        return {
            "original": query,
            "optimized": optimized,
            "optimizations": optimizations_applied,
            "dispatch_wisdom": "Use eventstats for dynamic baselines - it's faster and more accurate",
        }

    def _has_clear_hypothesis(self, hypothesis: str) -> bool:
        """Check if hypothesis is clear and testable"""
        # Good hypotheses typically have WHO, WHAT, HOW
        indicators = ["will", "using", "to", "via", "through"]

        return any(indicator in hypothesis.lower() for indicator in indicators)

    def _load_spl_dispatch_tricks(self) -> List[Dict]:
        """Load SPL tricks from Dispatch newsletter"""
        return [
            {
                "trick": "eventstats for baselines",
                "description": "Calculate baselines without subsearches",
                "example": "| eventstats avg(count) as avg_count, stdev(count) as stdev_count by user",
            },
            {
                "trick": "statistical outliers",
                "description": "Find anomalies using 2+ standard deviations",
                "example": "| where count > (avg_count + 2*stdev_count)",
            },
            {
                "trick": "streamstats for sequences",
                "description": "Track sequences of events",
                "example": "| streamstats count by user | where count > 5",
            },
        ]


class THORCollectiveIntegration:
    """
    Integration with THOR Collective's HEARTH repository
    Community-driven threat hunting knowledge base
    """

    def __init__(self, organization_profile: Optional[Dict] = None):
        self.organization_profile = organization_profile or self._default_profile()

        # Initialize THRF engine
        self.thrf = ThreatHuntingRelevancyFactors(self.organization_profile)

        # Initialize thrunting wisdom
        self.thrunting = ThruntingPhilosophy()

        # Load community hunts
        self.community_hunts = self._load_hearth_hunts()

        logger.info(
            f"THOR Collective integration initialized with {len(self.community_hunts)} HEARTH hunts")

    def get_relevant_hunts(self, filters: Optional[Dict] = None) -> List[Dict]:
        """
        Get community hunts from HEARTH, sorted by relevancy to your org
        """
        hunts = list(self.community_hunts.values())

        # Apply filters if provided
        if filters:
            if "hunt_type" in filters:
                hunts = [h for h in hunts if h.hunt_type == filters["hunt_type"]]
            if "tags" in filters:
                hunts = [h for h in hunts if any(tag in h.tags for tag in filters["tags"])]
            if "peak_phase" in filters:
                hunts = [h for h in hunts if h.peak_phase == filters["peak_phase"]]

        # Calculate THRF relevancy for each hunt
        hunt_scores = []
        for hunt in hunts:
            relevancy = self.thrf.calculate_hunt_relevancy(hunt)
            hunt_scores.append({"hunt": hunt, "relevancy": relevancy})

        # Sort by relevancy score
        hunt_scores.sort(key=lambda x: x["relevancy"]["total_score"], reverse=True)

        return hunt_scores

    def validate_hunt_quality(self, hypothesis: str, hunt_type: str) -> Dict:
        """Apply thrunting wisdom to validate hunt quality"""
        return self.thrunting.apply_thrunting_wisdom(hypothesis, hunt_type)

    def optimize_query(self, query: str, platform: str = "splunk") -> Dict:
        """Optimize query using THOR Collective techniques"""
        if platform.lower() == "splunk" or "index=" in query:
            return self.thrunting.optimize_spl_query(query)
        else:
            return {
                "original": query,
                "optimized": query,
                "optimizations": [],
                "note": f"Optimizations currently available for Splunk SPL only",
            }

    def _load_hearth_hunts(self) -> Dict[str, HEARTHHunt]:
        """Load HEARTH community hunts (example library)"""
        hunts = {}

        # Example HEARTH hunts following their format
        example_hunts = [
            HEARTHHunt(
                hunt_id="H-001",
                hunt_type="Hypothesis-Driven",
                title="Browser Extension Command Execution",
                hypothesis="Adversary will use malicious browser extension to execute commands on endpoint",
                data_sources=["endpoint_logs", "process_logs", "browser_logs"],
                queries={
                    "splunk": """
index=endpoint (process_name=chrome.exe OR process_name=firefox.exe OR process_name=msedge.exe)
| join type=inner process_id
  [search index=endpoint parent_process_name IN (chrome.exe, firefox.exe, msedge.exe)]
| where child_process_name IN ("cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe")
| eventstats count by extension_id, child_process_name
| where count > 2
| table _time, host, parent_process_name, child_process_name, command_line, extension_id, count
                    """.strip(),
                    "kql": """
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("chrome.exe", "firefox.exe", "msedge.exe")
| where FileName in~ ("cmd.exe", "powershell.exe", "wscript.exe")
| summarize count() by InitiatingProcessCommandLine, FileName, DeviceName
| where count_ > 2
                    """.strip(),
                },
                peak_phase="Execute",
                contributor="thor_collective",
                tags=["T1059", "T1176", "browser", "extension", "execution"],
                relevancy_factors={
                    "industries": ["all"],
                    "regions": ["global"],
                    "tech_stack": ["chrome", "firefox", "edge", "endpoints"],
                },
            ),
            HEARTHHunt(
                hunt_id="B-001",
                hunt_type="Baseline",
                title="DNS Request Pattern Baseline",
                hypothesis="Establish baseline for normal DNS request patterns to identify beaconing",
                data_sources=["dns_logs", "network_logs"],
                queries={
                    "splunk": """
index=dns
| bucket _time span=1h
| stats count by query, _time
| eventstats avg(count) as avg_count, stdev(count) as stdev_count by query
| eval baseline_min=avg_count-2*stdev_count, baseline_max=avg_count+2*stdev_count
| eval is_outlier=if(count < baseline_min OR count > baseline_max, 1, 0)
| where is_outlier=1
| table _time, query, count, avg_count, baseline_min, baseline_max
                    """.strip()
                },
                peak_phase="Prepare",
                contributor="thor_collective",
                tags=["baseline", "dns", "beaconing", "c2", "T1071"],
                relevancy_factors={
                    "industries": ["all"],
                    "regions": ["global"],
                    "tech_stack": [
                        "dns",
                        "network"]},
            ),
            HEARTHHunt(
                hunt_id="M-001",
                hunt_type="Model-Assisted",
                title="DBSCAN Clustering for Lateral Movement",
                hypothesis="Use DBSCAN clustering to identify anomalous authentication patterns indicating lateral movement",
                data_sources=["authentication_logs", "network_logs", "windows_events"],
                queries={
                    "python": """
# After extracting features from Splunk/logs
import pandas as pd
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler

# Feature engineering
features = df[['unique_dest_count', 'auth_count_per_hour', 'failed_auth_ratio', 'time_variance']]
scaler = StandardScaler()
features_scaled = scaler.fit_transform(features)

# DBSCAN clustering
clustering = DBSCAN(eps=0.3, min_samples=5)
df['cluster'] = clustering.fit_predict(features_scaled)

# Outliers (cluster -1) are potential lateral movement
lateral_movement_candidates = df[df['cluster'] == -1]
                    """.strip()
                },
                peak_phase="Execute",
                contributor="thor_collective",
                tags=["T1021", "lateral_movement", "ml", "clustering", "math"],
                relevancy_factors={
                    "industries": ["all"],
                    "regions": ["global"],
                    "tech_stack": ["python", "scikit-learn", "authentication_logs"],
                },
            ),
        ]

        for hunt in example_hunts:
            hunts[hunt.hunt_id] = hunt

        return hunts

    def _default_profile(self) -> Dict:
        """Default organization profile for THRF"""
        return {
            "industry": "technology",
            "regions": ["north_america"],
            "technology_stack": {
                "endpoints": ["windows", "macos", "linux"],
                "siem": ["splunk"],
                "cloud": ["aws"],
                "data_sources": ["endpoint_logs", "network_logs", "dns_logs", "authentication_logs"],
            },
            "attack_surface": ["web", "email", "endpoint", "cloud"],
            "active_threats": [],
        }

    def get_thrunting_mentor_advice(self, question: str) -> str:
        """Get thrunting advice based on question context"""
        advice = f"# Thrunting Wisdom from THOR Collective 🔨\n\n"
        advice += f"**Your Question**: {question}\n\n"

        # Context-specific advice
        if "baseline" in question.lower():
            advice += """
## Baselining Like a Pro

Key principles:
- Use `eventstats` to calculate dynamic baselines (faster than subsearches)
- Look for 2+ standard deviations from the mean for outliers
- Remember: **You can't find weird without knowing normal**
- The five numbers that matter: min, max, mean, median, stdev

Example pattern:
```spl
| eventstats avg(count) as avg_count, stdev(count) as stdev_count by user
| eval is_anomaly=if(count > (avg_count + 2*stdev_count), 1, 0)
```
"""
        elif "hypothesis" in question.lower():
            advice += """
## Crafting Better Hypotheses

A good hypothesis has three parts:
1. **WHO**: Which adversary or threat actor?
2. **WHAT**: What action will they take?
3. **HOW**: Which technique or tool will they use?

❌ Bad: "Find suspicious activity"
✅ Good: "APT29 will use WMI for lateral movement to domain controllers"

Make it:
- **Specific**: Clear target and technique
- **Testable**: You can validate or invalidate it
- **Linked**: Connect to MITRE ATT&CK when possible
- **Relevant**: Apply THRF - does this matter to YOUR org?
"""
        elif "query" in question.lower() or "spl" in question.lower():
            advice += """
## SPL Query Optimization

THOR Collective favorites:
1. **eventstats over subsearches**: Dynamic baselines without performance hit
2. **Statistical outliers**: 2+ standard deviations is your friend
3. **Time bucketing**: Always bucket your time windows
4. **Validate results**: Don't just trust the numbers

Dispatch wisdom: "Make friends with your data - understand its quirks"
"""
        else:
            advice += """
## Core Thrunting Principles

"""
            for i, principle in enumerate(self.thrunting.thrunting_principles[:5], 1):
                advice += f"{i}. {principle}\n"

        advice += """\n\n---\n**Happy Thrunting!** 🔨\n
Want to contribute? Submit your hunt to HEARTH: github.com/THOR-Collective/HEARTH
"""
        return advice
