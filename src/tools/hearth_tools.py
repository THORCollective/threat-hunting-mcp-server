"""
MCP Tools for HEARTH Integration
Community-driven threat hunting knowledge base access
"""

import logging
import os
from typing import Dict, List, Optional

from ..intelligence.hearth_integration import (
    HEARTHIntelligence,
    HEARTHRepository,
    HuntType,
)

logger = logging.getLogger(__name__)


class HEARTHTools:
    """MCP tools for accessing HEARTH threat hunting knowledge base"""

    def __init__(self, hearth_path: Optional[str] = None):
        """
        Initialize HEARTH tools

        Args:
            hearth_path: Path to HEARTH repository (auto-detected if None)
        """
        if hearth_path is None:
            hearth_path = os.path.join(os.path.dirname(__file__), "..", "..", "..", "HEARTH")

        self.repo = HEARTHRepository(hearth_path)
        self.intel = HEARTHIntelligence(self.repo)

    async def search_community_hunts(
        self,
        tactic: Optional[str] = None,
        tags: Optional[List[str]] = None,
        keyword: Optional[str] = None,
        hunt_type: Optional[str] = None,
        limit: int = 20,
    ) -> Dict:
        """
        Search HEARTH community hunt database

        Search through hundreds of community-curated threat hunting hypotheses
        from security professionals worldwide.

        Args:
            tactic: Filter by MITRE ATT&CK tactic (e.g., "Credential Access")
            tags: Filter by tags (e.g., ["lateral_movement", "powershell"])
            keyword: Search keyword in hypothesis and description
            hunt_type: Filter by hunt type: "flame" (hypothesis), "ember" (baseline), "alchemy" (ML)
            limit: Maximum number of results (default 20)

        Returns:
            Dictionary with search results and metadata
        """
        try:
            # Convert hunt type string to enum
            h_type = None
            if hunt_type:
                if hunt_type.lower() in ["flame", "hypothesis"]:
                    h_type = HuntType.FLAME
                elif hunt_type.lower() in ["ember", "baseline"]:
                    h_type = HuntType.EMBER
                elif hunt_type.lower() in ["alchemy", "model"]:
                    h_type = HuntType.ALCHEMY

            # Search hunts
            hunts = self.repo.search_hunts(tactic=tactic, tags=tags, hunt_type=h_type, keyword=keyword, limit=limit)

            return {
                "success": True,
                "count": len(hunts),
                "hunts": [hunt.to_dict() for hunt in hunts],
                "filters": {"tactic": tactic, "tags": tags, "keyword": keyword, "hunt_type": hunt_type},
                "source": "HEARTH Community Repository",
            }

        except Exception as e:
            logger.error(f"Error searching HEARTH hunts: {e}")
            return {"success": False, "error": str(e), "count": 0, "hunts": []}

    async def get_hunt_by_id(self, hunt_id: str) -> Dict:
        """
        Retrieve a specific community hunt by ID

        Get detailed information about a specific hunt from the HEARTH database.

        Args:
            hunt_id: Hunt identifier (e.g., 'H001' for Flame, 'B002' for Ember, 'M003' for Alchemy)

        Returns:
            Dictionary with hunt details
        """
        try:
            hunt = self.repo.get_hunt_by_id(hunt_id)

            if not hunt:
                return {"success": False, "error": f"Hunt {hunt_id} not found in HEARTH repository", "hunt_id": hunt_id}

            return {"success": True, "hunt": hunt.to_dict(), "source": "HEARTH Community Repository"}

        except Exception as e:
            logger.error(f"Error retrieving hunt {hunt_id}: {e}")
            return {"success": False, "error": str(e), "hunt_id": hunt_id}

    async def get_hunts_for_tactic(self, tactic: str, limit: int = 20) -> Dict:
        """
        Get community hunts for a MITRE ATT&CK tactic

        Retrieve hunt hypotheses from the community for a specific tactic.

        Args:
            tactic: MITRE ATT&CK tactic name (e.g., "Credential Access", "Lateral Movement")
            limit: Maximum number of hunts to return (default 20)

        Returns:
            Dictionary with hunt list for the tactic
        """
        try:
            hunts = self.repo.get_hunts_by_tactic(tactic, limit)

            return {
                "success": True,
                "tactic": tactic,
                "count": len(hunts),
                "hunts": [hunt.to_dict() for hunt in hunts],
                "source": "HEARTH Community Repository",
            }

        except Exception as e:
            logger.error(f"Error getting hunts for tactic {tactic}: {e}")
            return {"success": False, "error": str(e), "tactic": tactic, "count": 0, "hunts": []}

    async def get_hunts_for_technique(self, technique_id: str) -> Dict:
        """
        Get community hunts for a MITRE ATT&CK technique

        Find hunts that reference a specific ATT&CK technique ID.

        Args:
            technique_id: MITRE ATT&CK technique ID (e.g., "T1110", "T1078")

        Returns:
            Dictionary with hunt list for the technique
        """
        try:
            hunts = self.repo.get_hunts_by_technique(technique_id)

            return {
                "success": True,
                "technique_id": technique_id,
                "count": len(hunts),
                "hunts": [hunt.to_dict() for hunt in hunts],
                "source": "HEARTH Community Repository",
            }

        except Exception as e:
            logger.error(f"Error getting hunts for technique {technique_id}: {e}")
            return {"success": False, "error": str(e), "technique_id": technique_id, "count": 0, "hunts": []}

    async def recommend_hunts(
        self,
        tactics: Optional[List[str]] = None,
        techniques: Optional[List[str]] = None,
        keywords: Optional[List[str]] = None,
        environment: Optional[str] = None,
        limit: int = 10,
    ) -> Dict:
        """
        Get personalized hunt recommendations from community knowledge

        AI-powered recommendations based on your environment and threat landscape.

        Args:
            tactics: MITRE ATT&CK tactics of interest
            techniques: MITRE ATT&CK technique IDs
            keywords: Keywords describing your concerns (e.g., ["lateral movement", "powershell"])
            environment: Environment description (e.g., "Windows AD environment")
            limit: Maximum recommendations (default 10)

        Returns:
            Dictionary with ranked hunt recommendations
        """
        try:
            context = {
                "tactics": tactics or [],
                "techniques": techniques or [],
                "keywords": keywords or [],
                "environment": environment,
            }

            recommendations = self.repo.recommend_hunts(context, limit)

            return {
                "success": True,
                "count": len(recommendations),
                "recommendations": [
                    {
                        "hunt": hunt.to_dict(),
                        "relevance_score": round(score, 2),
                        "match_reasons": self._explain_match(hunt, context, score),
                    }
                    for hunt, score in recommendations
                ],
                "context": context,
                "source": "HEARTH Community Repository",
            }

        except Exception as e:
            logger.error(f"Error generating recommendations: {e}")
            return {"success": False, "error": str(e), "count": 0, "recommendations": []}

    async def get_recent_community_hunts(self, days: int = 30, limit: int = 20) -> Dict:
        """
        Get recently added community hunts

        Discover the latest threat hunting ideas from the community.

        Args:
            days: Number of days to look back (default 30)
            limit: Maximum number of hunts (default 20)

        Returns:
            Dictionary with recent hunts
        """
        try:
            hunts = self.repo.get_recent_hunts(days, limit)

            return {
                "success": True,
                "days": days,
                "count": len(hunts),
                "hunts": [hunt.to_dict() for hunt in hunts],
                "source": "HEARTH Community Repository",
            }

        except Exception as e:
            logger.error(f"Error getting recent hunts: {e}")
            return {"success": False, "error": str(e), "count": 0, "hunts": []}

    async def analyze_tactic_coverage(self) -> Dict:
        """
        Analyze MITRE ATT&CK tactic coverage in community hunts

        See which tactics have the most community-contributed hunt ideas.

        Returns:
            Dictionary with tactic coverage analysis
        """
        try:
            coverage = self.intel.analyze_tactic_coverage()

            # Calculate overall statistics
            total_hunts = sum(data["hunt_count"] for data in coverage.values())

            return {
                "success": True,
                "total_hunts": total_hunts,
                "total_tactics": len(coverage),
                "coverage_by_tactic": coverage,
                "top_tactics": sorted(coverage.items(), key=lambda x: x[1]["hunt_count"], reverse=True)[:10],
                "source": "HEARTH Community Repository",
            }

        except Exception as e:
            logger.error(f"Error analyzing tactic coverage: {e}")
            return {"success": False, "error": str(e)}

    async def get_hearth_statistics(self) -> Dict:
        """
        Get statistics about HEARTH community repository

        Overview of the community knowledge base size and diversity.

        Returns:
            Dictionary with repository statistics
        """
        try:
            stats = self.repo.get_hunt_statistics()

            return {
                "success": True,
                "statistics": stats,
                "repository_url": "https://github.com/THORCollective/HEARTH",
                "live_database": "https://thorcollective.github.io/HEARTH/",
                "source": "HEARTH Community Repository",
            }

        except Exception as e:
            logger.error(f"Error getting HEARTH statistics: {e}")
            return {"success": False, "error": str(e)}

    async def suggest_hunts_for_incident(self, incident_description: str) -> Dict:
        """
        Get hunt suggestions based on incident description

        Leverages community knowledge to suggest relevant hunts for your incident.

        Args:
            incident_description: Description of the security incident

        Returns:
            Dictionary with suggested hunts
        """
        try:
            hunts = self.intel.suggest_hunt_for_incident(incident_description)

            return {
                "success": True,
                "incident_description": incident_description,
                "count": len(hunts),
                "suggested_hunts": [hunt.to_dict() for hunt in hunts],
                "source": "HEARTH Community Repository",
            }

        except Exception as e:
            logger.error(f"Error suggesting hunts for incident: {e}")
            return {"success": False, "error": str(e), "count": 0, "suggested_hunts": []}

    def _explain_match(self, hunt, context, score) -> List[str]:
        """Generate explanation for why a hunt was recommended"""
        reasons = []

        # Check tactic matches
        if context.get("tactics"):
            for tactic in context["tactics"]:
                if tactic.lower() in hunt.tactic.lower():
                    reasons.append(f"Matches tactic: {tactic}")

        # Check technique matches
        if context.get("techniques"):
            for technique in context["techniques"]:
                if any(technique in ref for ref in hunt.references):
                    reasons.append(f"References technique: {technique}")

        # Check keyword matches
        if context.get("keywords"):
            matched_keywords = []
            for keyword in context["keywords"]:
                if keyword.lower() in hunt.hypothesis.lower() or keyword.lower() in hunt.why_section.lower():
                    matched_keywords.append(keyword)

            if matched_keywords:
                reasons.append(
                    f"Keyword matches: {
                        ', '.join(matched_keywords)}"
                )

        if not reasons:
            reasons.append("General relevance to context")

        return reasons
