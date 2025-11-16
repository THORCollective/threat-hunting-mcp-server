"""
PEAK Hunt Generator

This module generates threat hunting reports using the PEAK Framework template
(Prepare, Execute, Act with Knowledge). It emphasizes behavioral hunting at the
top of the Pyramid of Pain.
"""

import logging
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class ABLEScope:
    """ABLE Methodology scoping for threat hunts"""

    actor: Optional[str] = None  # Optional - focus on behavior first
    behavior: str = ""  # TTPs - REQUIRED (behavioral focus)
    location: str = ""  # Where the activity occurred
    evidence: List[Dict[str, str]] = None  # Log sources and expected findings

    def __post_init__(self):
        if self.evidence is None:
            self.evidence = []


@dataclass
class PEAKHunt:
    """Represents a PEAK Framework threat hunt"""

    hunt_id: str  # H/B/M-XXXX format
    hunt_title: str
    hypothesis: str
    hunter_name: str
    date: str
    requestor: str
    timeframe: str

    # ABLE Scoping
    able_scope: ABLEScope

    # MITRE ATT&CK mappings
    mitre_tactics: List[str]
    mitre_techniques: List[str]

    # Related tickets
    related_tickets: Dict[str, str]

    # Threat intel and research
    threat_intel_sources: List[str]
    historical_context: str

    # Hunt execution details (optional during creation)
    queries: Optional[List[Dict[str, str]]] = None
    findings: Optional[List[Dict[str, str]]] = None
    lessons_learned: Optional[str] = None


class PEAKHuntGenerator:
    """
    Generates PEAK Framework hunt reports with behavioral hunting focus.

    This generator emphasizes hunting for behaviors (TTPs) at the top of the
    Pyramid of Pain, not atomic indicators at the bottom.
    """

    def __init__(self, template_path: Optional[Path] = None):
        if template_path is None:
            # Default to templates/PEAK-Template.md relative to this file
            template_path = Path(__file__).parent.parent.parent / "templates" / "PEAK-Template.md"

        self.template_path = template_path
        self.template_content = self._load_template()

    def _load_template(self) -> str:
        """Loads the PEAK template from file"""
        try:
            with open(self.template_path, "r") as f:
                return f.read()
        except FileNotFoundError:
            logger.error(f"PEAK template not found at {self.template_path}")
            return ""

    def generate_hunt_report(self, hunt: PEAKHunt, output_path: Optional[Path] = None) -> str:
        """
        Generates a complete PEAK hunt report from hunt data.

        Args:
            hunt: PEAKHunt object with hunt details
            output_path: Optional path to save the report

        Returns:
            The generated hunt report as markdown string
        """
        report = self._populate_template(hunt)

        if output_path:
            self._save_report(report, output_path)

        return report

    def _populate_template(self, hunt: PEAKHunt) -> str:
        """Populates the PEAK template with hunt data"""

        # Format ABLE evidence
        evidence_text = self._format_evidence(hunt.able_scope.evidence)

        # Format MITRE techniques
        mitre_text = self._format_mitre_techniques(hunt.mitre_tactics, hunt.mitre_techniques)

        # Format related tickets
        tickets_text = self._format_related_tickets(hunt.related_tickets)

        # Replace template placeholders
        report = self.template_content

        # Basic hunt information
        report = report.replace("H/B/M-XXXX", hunt.hunt_id)
        report = report.replace("*A concise, descriptive name for this hunt.*", hunt.hunt_title)

        # Hunt information table
        report = report.replace("[What are you hunting for and why?]", hunt.hypothesis)
        report = report.replace("[Name of the threat hunter]", hunt.hunter_name)
        report = report.replace("[Date of hunt]", hunt.date)
        report = report.replace("[Person or team requesting the hunt]", hunt.requestor)
        report = report.replace("[Expected duration for the hunt]", hunt.timeframe)

        # ABLE Scoping
        actor_text = hunt.able_scope.actor if hunt.able_scope.actor else "N/A - Hunting behaviors across all actors"
        report = report.replace("`[Threat Actor or N/A]`", f"`{actor_text}`")
        report = report.replace(
            "`[Describe observed or expected behavior]`", f"`{
                hunt.able_scope.behavior}`")
        report = report.replace("`[Location]`", f"`{hunt.able_scope.location}`")

        # Replace evidence section
        evidence_placeholder = (
            "`- Source: [Log Source]`<br>`- Key Fields: [Critical Fields]`<br>"
            "`- Example: [Expected Example of Malicious Activity]`<br><br>"
            "`- Source: [Additional Source]`<br>`- Key Fields: [Critical Fields]`<br>"
            "`- Example: [Expected Example of Malicious Activity]`"
        )
        report = report.replace(evidence_placeholder, evidence_text)

        # MITRE ATT&CK section
        mitre_placeholder = "- `TAxxxx - Tactic Name` \n  - `Txxxx - Technique Name`"
        report = report.replace(mitre_placeholder, mitre_text)

        # Related tickets
        report = self._replace_tickets_table(report, hunt.related_tickets)

        # Threat intel sources
        if hunt.threat_intel_sources:
            sources_text = "\n  - ".join([f"`{source}`" for source in hunt.threat_intel_sources])
            report = report.replace("- `[Link]`\n  - `[Reference]`", f"- {sources_text}")

        # Historical context
        report = report.replace(
            "*(Has this been observed before in your environment? Are there any detections/mitigations for this activity already in place?)*",
            hunt.historical_context if hunt.historical_context else "No historical context provided.",
        )

        # Add queries if provided
        if hunt.queries:
            report = self._populate_queries(report, hunt.queries)

        # Add findings if provided
        if hunt.findings:
            report = self._populate_findings(report, hunt.findings)

        # Add lessons learned if provided
        if hunt.lessons_learned:
            report = report.replace("- **What worked well?**",
                                    f"{hunt.lessons_learned}\n\n- **What worked well?**")

        return report

    def _format_evidence(self, evidence: List[Dict[str, str]]) -> str:
        """Formats evidence section for ABLE methodology"""
        if not evidence:
            return "`- Source: [Log Source]`<br>`- Key Fields: [Critical Fields]`<br>`- Example: [Expected Example]`"

        evidence_parts = []
        for item in evidence:
            source = item.get("source", "[Log Source]")
            key_fields = item.get("key_fields", "[Critical Fields]")
            example = item.get("example", "[Expected Example of Malicious Activity]")

            evidence_parts.append(
                f"`- Source: {source}`<br>`- Key Fields: {key_fields}`<br>`- Example: {example}`")

        return "<br><br>".join(evidence_parts)

    def _format_mitre_techniques(self, tactics: List[str], techniques: List[str]) -> str:
        """Formats MITRE ATT&CK techniques section"""
        lines = []

        # Add tactics
        for tactic in tactics:
            lines.append(f"  - `{tactic}`")

        # Add techniques
        for technique in techniques:
            lines.append(f"  - `{technique}`")

        return "\n".join(
            lines) if lines else "- `TAxxxx - Tactic Name`\n  - `Txxxx - Technique Name`"

    def _format_related_tickets(self, tickets: Dict[str, str]) -> str:
        """Formats related tickets section"""
        # This will be handled by _replace_tickets_table
        return ""

    def _replace_tickets_table(self, report: str, tickets: Dict[str, str]) -> str:
        """Replaces the tickets table in the report"""
        soc_ticket = tickets.get("SOC/IR", "[Insert related ticket or incident details]")
        ti_ticket = tickets.get("Threat Intel (TI)", "[Insert related ticket]")
        de_ticket = tickets.get("Detection Engineering (DE)", "[Insert related ticket]")
        redteam_ticket = tickets.get("Red Team / Pen Testing", "[Insert related ticket]")
        other_ticket = tickets.get("Other", "[Insert related ticket]")

        report = report.replace(
            "| **SOC/IR**                      | [Insert related ticket or incident details] |", f"| **SOC/IR**                      | {soc_ticket} |"
        )
        report = report.replace(
            "| **Threat Intel (TI)**            | [Insert related ticket] |",
            f"| **Threat Intel (TI)**            | {ti_ticket} |")
        report = report.replace(
            "| **Detection Engineering (DE)**   | [Insert related ticket] |", f"| **Detection Engineering (DE)**   | {de_ticket} |"
        )
        report = report.replace(
            "| **Red Team / Pen Testing**       | [Insert related ticket] |", f"| **Red Team / Pen Testing**       | {redteam_ticket} |"
        )
        report = report.replace(
            "| **Other**                        | [Insert related ticket] |",
            f"| **Other**                        | {other_ticket} |")

        return report

    def _populate_queries(self, report: str, queries: List[Dict[str, str]]) -> str:
        """Populates the queries section with actual hunt queries"""
        if not queries:
            return report

        # Replace initial query
        if len(queries) > 0:
            initial_query = queries[0].get("query", "")
            notes = queries[0].get("notes", "")

            report = report.replace(
                'index=main sourcetype=linux:audit "sudo" OR "pkexec"\n| stats count by user, command, parent_process', initial_query
            )

            if notes:
                report = report.replace(
                    "- **Notes:**  \n  - Did this query return expected results?  \n  - Were there false positives or gaps?  \n  - How did you refine the query based on findings?",
                    f"- **Notes:**  \n{notes}",
                )

        # Replace refined query if exists
        if len(queries) > 1:
            refined_query = queries[1].get("query", "")
            rationale = queries[1].get("rationale", "")

            report = report.replace(
                'index=main sourcetype=linux:audit "sudo" OR "pkexec"  \n| stats count by user, command, parent_process, _time  \n| sort - _time',
                refined_query,
            )

            if rationale:
                report = report.replace(
                    "- **Rationale for Refinement:**  \n  - Added `_time` for better event sequencing.  \n  - Applied `sort` to identify patterns in privilege escalation attempts.",
                    f"- **Rationale for Refinement:**  \n{rationale}",
                )

        return report

    def _populate_findings(self, report: str, findings: List[Dict[str, str]]) -> str:
        """Populates the findings table with actual findings"""
        if not findings:
            return report

        findings_rows = []
        for finding in findings:
            description = finding.get("description", "[Describe finding]")
            ticket = finding.get("ticket", "[Insert Ticket Number]")
            details = finding.get("details", "[Brief description]")

            findings_rows.append(f"| {description} | {ticket} | {details} |")

        # Replace the placeholder findings table
        placeholder = (
            "| [Describe finding] | [Insert Ticket Number] | [Brief description of the finding, such as suspicious activity, new detection idea, data gap, etc.] |\n"
            "| [Describe finding] | [Insert Ticket Number] | [Brief description of the finding] |\n"
            "| [Describe finding] | [Insert Ticket Number] | [Brief description of the finding] |"
        )

        findings_text = "\n".join(findings_rows)
        report = report.replace(placeholder, findings_text)

        return report

    def _save_report(self, report: str, output_path: Path):
        """Saves the generated report to a file"""
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w") as f:
                f.write(report)
            logger.info(f"PEAK hunt report saved to {output_path}")
        except Exception as e:
            logger.error(f"Failed to save PEAK hunt report: {e}")

    def create_behavioral_hunt(
        self,
        technique_id: str,
        technique_name: str,
        tactic: str,
        hypothesis: str,
        hunter_name: str,
        location: str,
        data_sources: List[Dict[str, str]],
        **kwargs,
    ) -> PEAKHunt:
        """
        Creates a behavioral hunt focused on a MITRE ATT&CK technique.

        This is a convenience method for creating TTP-focused hunts at the top
        of the Pyramid of Pain.

        Args:
            technique_id: MITRE technique ID (e.g., "T1003.001")
            technique_name: Name of the technique (e.g., "LSASS Memory")
            tactic: MITRE tactic (e.g., "Credential Access")
            hypothesis: Hunt hypothesis
            hunter_name: Name of the threat hunter
            location: Where to hunt (systems, network, etc.)
            data_sources: List of log sources and key fields
            **kwargs: Additional optional parameters

        Returns:
            PEAKHunt object ready to generate a report
        """
        hunt_id = kwargs.get("hunt_id", f"H-{datetime.now().strftime('%Y%m%d-%H%M')}")
        hunt_title = kwargs.get("hunt_title", f"Hunt for {technique_name} ({technique_id})")

        # Create ABLE scope emphasizing behavioral hunting
        able_scope = ABLEScope(
            actor=kwargs.get("actor"),  # Optional - behavior-first approach
            behavior=f"{technique_name} ({technique_id}) - {hypothesis}",
            location=location,
            evidence=data_sources,
        )

        hunt = PEAKHunt(
            hunt_id=hunt_id,
            hunt_title=hunt_title,
            hypothesis=hypothesis,
            hunter_name=hunter_name,
            date=kwargs.get("date", datetime.now().strftime("%Y-%m-%d")),
            requestor=kwargs.get("requestor", "Threat Hunting Team"),
            timeframe=kwargs.get("timeframe", "1-2 days"),
            able_scope=able_scope,
            mitre_tactics=[f"{tactic}"],
            mitre_techniques=[f"{technique_id} - {technique_name}"],
            related_tickets=kwargs.get("related_tickets", {}),
            threat_intel_sources=kwargs.get("threat_intel_sources", []),
            historical_context=kwargs.get(
                "historical_context",
                f"Hunting for {technique_name} behavior patterns across all tools and variants. "
                f"This behavioral hunt focuses on TTPs at the top of the Pyramid of Pain.",
            ),
            queries=kwargs.get("queries"),
            findings=kwargs.get("findings"),
            lessons_learned=kwargs.get("lessons_learned"),
        )

        return hunt
