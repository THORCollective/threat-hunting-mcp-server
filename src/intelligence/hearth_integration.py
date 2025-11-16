"""
HEARTH Integration Module
Hunting Exchange and Research Threat Hub

Leverages HEARTH's community-driven threat hunting knowledge base as a source
of truth for the MCP server. Provides access to hypothesis-driven hunts (Flames),
baseline hunts (Embers), and model-assisted hunts (Alchemy).
"""

import logging
import re
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class HuntType(Enum):
    """PEAK framework hunt types from HEARTH"""

    FLAME = "flame"  # Hypothesis-driven (H prefix)
    EMBER = "ember"  # Baseline (B prefix)
    ALCHEMY = "alchemy"  # Model-assisted (M prefix)


@dataclass
class HEARTHHunt:
    """Represents a hunt from the HEARTH repository"""

    hunt_id: str
    hunt_type: HuntType
    hypothesis: str
    tactic: str
    notes: str
    tags: List[str]
    submitter: str
    why_section: str
    next_steps: Optional[str]
    references: List[str]
    file_path: str

    def to_dict(self, summary: bool = False) -> Dict:
        """
        Convert to dictionary representation

        Args:
            summary: If True, returns abbreviated version without long text fields

        Returns:
            Dictionary representation of hunt
        """
        base = {
            "hunt_id": self.hunt_id,
            "hunt_type": self.hunt_type.value,
            "hypothesis": self.hypothesis,
            "tactic": self.tactic,
            "tags": self.tags,
            "submitter": self.submitter,
            "source": f"HEARTH/{self.file_path}",
        }

        if summary:
            # Summary mode: truncate long fields
            base["notes_preview"] = self.notes[:100] + "..." if len(self.notes) > 100 else self.notes
            base["has_details"] = bool(self.why_section or self.next_steps or self.references)
        else:
            # Full mode: include everything
            base.update({
                "notes": self.notes,
                "why": self.why_section,
                "next_steps": self.next_steps,
                "references": self.references,
            })

        return base


class HEARTHRepository:
    """
    Integration with HEARTH threat hunting knowledge base

    Provides access to community-curated hunt hypotheses organized by
    the PEAK framework (Flames, Embers, Alchemy).
    """

    def __init__(self, hearth_path: str = None):
        """
        Initialize HEARTH repository integration

        Args:
            hearth_path: Path to the HEARTH repository (defaults to ../HEARTH relative to project root)
        """
        if hearth_path is None:
            # Default to ../HEARTH relative to project root
            project_root = Path(__file__).parent.parent.parent
            hearth_path = project_root.parent / "HEARTH"

        self.hearth_path = Path(hearth_path)
        self.db_path = self.hearth_path / "database" / "hunts.db"

        # Directory mappings
        self.flames_dir = self.hearth_path / "Flames"
        self.embers_dir = self.hearth_path / "Embers"
        self.alchemy_dir = self.hearth_path / "Alchemy"

        # Validate paths
        self._validate_paths()

        # Cache for parsed hunts
        self._hunt_cache: Dict[str, HEARTHHunt] = {}

    def _validate_paths(self):
        """Validate HEARTH repository structure"""
        if not self.hearth_path.exists():
            raise ValueError(
                f"HEARTH repository not found at {
                    self.hearth_path}"
            )

        if not self.flames_dir.exists():
            logger.warning(f"Flames directory not found at {self.flames_dir}")

        if not self.db_path.exists():
            logger.warning(f"HEARTH database not found at {self.db_path}")

    def get_hunt_by_id(self, hunt_id: str) -> Optional[HEARTHHunt]:
        """
        Retrieve a specific hunt by ID

        Args:
            hunt_id: Hunt identifier (e.g., 'H001', 'B002', 'M003')

        Returns:
            HEARTHHunt object or None if not found
        """
        # Check cache first
        if hunt_id in self._hunt_cache:
            return self._hunt_cache[hunt_id]

        # Determine hunt type and directory
        hunt_type, directory = self._get_hunt_location(hunt_id)
        if not directory:
            logger.warning(f"Unknown hunt type for ID: {hunt_id}")
            return None

        # Find the markdown file
        hunt_file = directory / f"{hunt_id}.md"
        if not hunt_file.exists():
            logger.warning(f"Hunt file not found: {hunt_file}")
            return None

        # Parse the hunt
        hunt = self._parse_hunt_file(hunt_file, hunt_type)

        # Cache the result
        if hunt:
            self._hunt_cache[hunt_id] = hunt

        return hunt

    def search_hunts(
        self,
        tactic: Optional[str] = None,
        tags: Optional[List[str]] = None,
        hunt_type: Optional[HuntType] = None,
        keyword: Optional[str] = None,
        limit: int = 50,
    ) -> List[HEARTHHunt]:
        """
        Search for hunts matching criteria

        Args:
            tactic: MITRE ATT&CK tactic to filter by
            tags: Tags to filter by (any match)
            hunt_type: Hunt type to filter by (Flame, Ember, Alchemy)
            keyword: Keyword to search in hypothesis and description
            limit: Maximum number of results

        Returns:
            List of matching HEARTHHunt objects
        """
        results = []

        # Determine which directories to search
        directories = []
        if hunt_type == HuntType.FLAME or hunt_type is None:
            directories.append((self.flames_dir, HuntType.FLAME))
        if hunt_type == HuntType.EMBER or hunt_type is None:
            directories.append((self.embers_dir, HuntType.EMBER))
        if hunt_type == HuntType.ALCHEMY or hunt_type is None:
            directories.append((self.alchemy_dir, HuntType.ALCHEMY))

        # Search through hunt files
        for directory, h_type in directories:
            if not directory.exists():
                continue

            for hunt_file in directory.glob("*.md"):
                # Skip template files
                if "template" in hunt_file.name.lower():
                    continue

                hunt = self._parse_hunt_file(hunt_file, h_type)
                if not hunt:
                    continue

                # Apply filters
                if tactic and tactic.lower() not in hunt.tactic.lower():
                    continue

                if tags and not any(tag.lower() in [t.lower() for t in hunt.tags] for tag in tags):
                    continue

                if keyword:
                    keyword_lower = keyword.lower()
                    if (
                        keyword_lower not in hunt.hypothesis.lower()
                        and keyword_lower not in hunt.why_section.lower()
                        and keyword_lower not in hunt.notes.lower()
                    ):
                        continue

                results.append(hunt)

                if len(results) >= limit:
                    return results

        return results

    def get_hunts_by_tactic(self, tactic: str, limit: int = 20) -> List[HEARTHHunt]:
        """
        Get hunts for a specific MITRE ATT&CK tactic

        Args:
            tactic: MITRE ATT&CK tactic name
            limit: Maximum number of hunts to return

        Returns:
            List of HEARTHHunt objects
        """
        return self.search_hunts(tactic=tactic, limit=limit)

    def get_hunts_by_technique(self, technique_id: str) -> List[HEARTHHunt]:
        """
        Get hunts related to a specific MITRE ATT&CK technique

        Args:
            technique_id: MITRE ATT&CK technique ID (e.g., 'T1110')

        Returns:
            List of HEARTHHunt objects that reference this technique
        """
        results = []

        for directory, h_type in [
            (self.flames_dir, HuntType.FLAME),
            (self.embers_dir, HuntType.EMBER),
            (self.alchemy_dir, HuntType.ALCHEMY),
        ]:
            if not directory.exists():
                continue

            for hunt_file in directory.glob("*.md"):
                if "template" in hunt_file.name.lower():
                    continue

                hunt = self._parse_hunt_file(hunt_file, h_type)
                if not hunt:
                    continue

                # Check if technique ID is in references
                if any(technique_id in ref for ref in hunt.references):
                    results.append(hunt)

        return results

    def get_all_tactics(self) -> List[str]:
        """
        Get all unique tactics from HEARTH hunts

        Returns:
            List of tactic names
        """
        tactics = set()

        for directory in [self.flames_dir, self.embers_dir, self.alchemy_dir]:
            if not directory.exists():
                continue

            for hunt_file in directory.glob("*.md"):
                if "template" in hunt_file.name.lower():
                    continue

                content = hunt_file.read_text()
                tactic = self._extract_tactic(content)
                if tactic:
                    tactics.add(tactic)

        return sorted(list(tactics))

    def get_recent_hunts(self, days: int = 30, limit: int = 20) -> List[HEARTHHunt]:
        """
        Get recently added hunts (based on file modification time)

        Args:
            days: Number of days to look back
            limit: Maximum number of hunts

        Returns:
            List of recent HEARTHHunt objects
        """
        from datetime import timedelta

        cutoff = datetime.now() - timedelta(days=days)
        recent = []

        for directory, h_type in [
            (self.flames_dir, HuntType.FLAME),
            (self.embers_dir, HuntType.EMBER),
            (self.alchemy_dir, HuntType.ALCHEMY),
        ]:
            if not directory.exists():
                continue

            for hunt_file in directory.glob("*.md"):
                if "template" in hunt_file.name.lower():
                    continue

                # Check modification time
                mtime = datetime.fromtimestamp(hunt_file.stat().st_mtime)
                if mtime > cutoff:
                    hunt = self._parse_hunt_file(hunt_file, h_type)
                    if hunt:
                        recent.append((mtime, hunt))

        # Sort by modification time, most recent first
        recent.sort(key=lambda x: x[0], reverse=True)

        return [hunt for _, hunt in recent[:limit]]

    def recommend_hunts(self, context: Dict, limit: int = 10) -> List[Tuple[HEARTHHunt, float]]:
        """
        Recommend hunts based on context

        Args:
            context: Dictionary with keys like 'tactics', 'techniques', 'keywords', 'environment'
            limit: Maximum number of recommendations

        Returns:
            List of (HEARTHHunt, relevance_score) tuples, sorted by relevance
        """
        recommendations = []

        tactics = context.get("tactics", [])
        techniques = context.get("techniques", [])
        keywords = context.get("keywords", [])

        # Search for relevant hunts
        all_hunts = self.search_hunts(limit=200)

        for hunt in all_hunts:
            score = 0.0

            # Score based on tactic match
            if tactics and any(tactic.lower() in hunt.tactic.lower() for tactic in tactics):
                score += 3.0

            # Score based on technique match
            if techniques:
                for technique in techniques:
                    if any(technique in ref for ref in hunt.references):
                        score += 2.0

            # Score based on keyword match
            if keywords:
                for keyword in keywords:
                    keyword_lower = keyword.lower()
                    if keyword_lower in hunt.hypothesis.lower():
                        score += 1.5
                    if keyword_lower in hunt.why_section.lower():
                        score += 1.0
                    if any(keyword_lower in tag.lower() for tag in hunt.tags):
                        score += 0.5

            if score > 0:
                recommendations.append((hunt, score))

        # Sort by score descending
        recommendations.sort(key=lambda x: x[1], reverse=True)

        return recommendations[:limit]

    def get_hunt_statistics(self) -> Dict:
        """
        Get statistics about HEARTH repository

        Returns:
            Dictionary with statistics
        """
        stats = {"total_hunts": 0, "flames": 0, "embers": 0, "alchemy": 0, "tactics": set(), "unique_submitters": set()}

        for directory, h_type in [
            (self.flames_dir, HuntType.FLAME),
            (self.embers_dir, HuntType.EMBER),
            (self.alchemy_dir, HuntType.ALCHEMY),
        ]:
            if not directory.exists():
                continue

            count = len([f for f in directory.glob("*.md") if "template" not in f.name.lower()])
            stats["total_hunts"] += count

            if h_type == HuntType.FLAME:
                stats["flames"] = count
            elif h_type == HuntType.EMBER:
                stats["embers"] = count
            elif h_type == HuntType.ALCHEMY:
                stats["alchemy"] = count

            # Parse for additional stats
            for hunt_file in directory.glob("*.md"):
                if "template" in hunt_file.name.lower():
                    continue

                hunt = self._parse_hunt_file(hunt_file, h_type)
                if hunt:
                    stats["tactics"].add(hunt.tactic)
                    stats["unique_submitters"].add(hunt.submitter)

        # Convert sets to counts
        stats["unique_tactics"] = len(stats["tactics"])
        stats["unique_submitters"] = len(stats["unique_submitters"])
        del stats["tactics"]

        return stats

    def _get_hunt_location(self, hunt_id: str) -> Tuple[Optional[HuntType], Optional[Path]]:
        """Determine hunt type and directory from hunt ID"""
        if hunt_id.startswith("H"):
            return HuntType.FLAME, self.flames_dir
        elif hunt_id.startswith("B"):
            return HuntType.EMBER, self.embers_dir
        elif hunt_id.startswith("M"):
            return HuntType.ALCHEMY, self.alchemy_dir
        return None, None

    def _parse_hunt_file(self, file_path: Path, hunt_type: HuntType) -> Optional[HEARTHHunt]:
        """
        Parse a HEARTH hunt markdown file

        Args:
            file_path: Path to the markdown file
            hunt_type: Type of hunt

        Returns:
            HEARTHHunt object or None if parsing fails
        """
        try:
            content = file_path.read_text()

            # Extract hunt ID from filename
            hunt_id = file_path.stem

            # Extract table data
            hypothesis = self._extract_hypothesis(content)
            tactic = self._extract_tactic(content)
            notes = self._extract_notes(content)
            tags = self._extract_tags(content)
            submitter = self._extract_submitter(content)

            # Extract sections
            why_section = self._extract_section(content, "## Why")
            next_steps = self._extract_section(content, "## Next Steps")
            references = self._extract_references(content)

            if not hypothesis:
                logger.warning(f"Could not extract hypothesis from {file_path}")
                return None

            return HEARTHHunt(
                hunt_id=hunt_id,
                hunt_type=hunt_type,
                hypothesis=hypothesis,
                tactic=tactic or "Unknown",
                notes=notes or "",
                tags=tags,
                submitter=submitter or "Unknown",
                why_section=why_section or "",
                next_steps=next_steps,
                references=references,
                file_path=str(file_path.relative_to(self.hearth_path)),
            )

        except Exception as e:
            logger.error(f"Error parsing hunt file {file_path}: {e}")
            return None

    def _extract_hypothesis(self, content: str) -> Optional[str]:
        """Extract hypothesis from markdown table"""
        # Try to find the table row
        table_match = re.search(r"\|[^|]*\|([^|]+)\|([^|]+)\|", content)
        if table_match:
            # Second column is typically the hypothesis
            hypothesis = table_match.group(2).strip()
            if hypothesis and not hypothesis.startswith("Idea / Hypothesis"):
                return hypothesis

        # Fallback: try to get from first line (description before table)
        lines = content.split("\n")
        for line in lines[1:5]:  # Check first few lines after title
            line = line.strip()
            if line and not line.startswith("#") and not line.startswith("|"):
                return line

        return None

    def _extract_tactic(self, content: str) -> Optional[str]:
        """Extract MITRE ATT&CK tactic from table"""
        table_match = re.search(r"\|[^|]*\|[^|]*\|([^|]+)\|", content)
        if table_match:
            tactic = table_match.group(1).strip()
            if tactic and not tactic.startswith("Tactic"):
                return tactic
        return None

    def _extract_notes(self, content: str) -> Optional[str]:
        """Extract notes from table"""
        table_match = re.search(r"\|[^|]*\|[^|]*\|[^|]*\|([^|]+)\|", content)
        if table_match:
            notes = table_match.group(1).strip()
            if notes and not notes.startswith("Notes"):
                return notes
        return None

    def _extract_tags(self, content: str) -> List[str]:
        """Extract tags from content"""
        tags = []
        # Look for hashtags in the table
        tag_matches = re.findall(r"#(\w+)", content)
        tags.extend(tag_matches)
        return list(set(tags))  # Remove duplicates

    def _extract_submitter(self, content: str) -> Optional[str]:
        """Extract submitter from table"""
        # Look for markdown link pattern or plain name
        submitter_match = re.search(r"\[([^\]]+)\]\([^\)]+\)", content)
        if submitter_match:
            return submitter_match.group(1)

        # Fallback: look for last column in table
        table_match = re.search(r"\|[^|]*\|[^|]*\|[^|]*\|[^|]*\|[^|]*\|([^|]+)\|", content)
        if table_match:
            submitter = table_match.group(1).strip()
            if submitter and not submitter.startswith("Submitter"):
                return submitter

        return None

    def _extract_section(self, content: str, section_header: str) -> Optional[str]:
        """Extract content from a markdown section"""
        pattern = f"{section_header}\\s*\\n\\n(.*?)(?=\\n## |\\n---|\\'\\'\\'|$)"
        match = re.search(pattern, content, re.DOTALL)
        if match:
            section_content = match.group(1).strip()
            # Clean up markdown list formatting
            section_content = re.sub(r"^- ", "", section_content, flags=re.MULTILINE)
            return section_content
        return None

    def _extract_references(self, content: str) -> List[str]:
        """Extract reference URLs from References section"""
        references = []
        ref_section = self._extract_section(content, "## References")
        if ref_section:
            # Find all URLs
            urls = re.findall(r"https?://[^\s\)]+", ref_section)
            references.extend(urls)
        return references


class HEARTHIntelligence:
    """
    Intelligence layer built on HEARTH repository

    Provides high-level intelligence functions for hunt recommendations,
    tactic coverage analysis, and threat landscape insights.
    """

    def __init__(self, hearth_repo: HEARTHRepository):
        self.repo = hearth_repo

    def analyze_tactic_coverage(self) -> Dict:
        """
        Analyze hunt coverage across MITRE ATT&CK tactics

        Returns:
            Dictionary with tactic coverage statistics
        """
        tactics = self.repo.get_all_tactics()
        coverage = {}

        for tactic in tactics:
            hunts = self.repo.get_hunts_by_tactic(tactic)
            coverage[tactic] = {
                "hunt_count": len(hunts),
                "flame_count": sum(1 for h in hunts if h.hunt_type == HuntType.FLAME),
                "ember_count": sum(1 for h in hunts if h.hunt_type == HuntType.EMBER),
                "alchemy_count": sum(1 for h in hunts if h.hunt_type == HuntType.ALCHEMY),
            }

        return coverage

    def suggest_hunt_for_incident(self, incident_description: str) -> List[HEARTHHunt]:
        """
        Suggest relevant hunts based on an incident description

        Args:
            incident_description: Description of the security incident

        Returns:
            List of recommended HEARTHHunt objects
        """
        # Extract keywords from description
        keywords = self._extract_keywords(incident_description)

        context = {"keywords": keywords, "tactics": [], "techniques": []}

        # Get recommendations
        recommendations = self.repo.recommend_hunts(context, limit=10)

        return [hunt for hunt, _ in recommendations]

    def _extract_keywords(self, text: str) -> List[str]:
        """Extract relevant keywords from text"""
        # Simple keyword extraction - can be enhanced with NLP
        keywords = []

        # Common threat hunting keywords
        threat_keywords = [
            "lateral",
            "movement",
            "credential",
            "privilege",
            "escalation",
            "persistence",
            "execution",
            "defense",
            "evasion",
            "exfiltration",
            "command",
            "control",
            "c2",
            "powershell",
            "rundll32",
            "wmi",
            "scheduled",
            "task",
            "registry",
            "service",
            "process",
            "injection",
        ]

        text_lower = text.lower()
        for keyword in threat_keywords:
            if keyword in text_lower:
                keywords.append(keyword)

        return keywords
