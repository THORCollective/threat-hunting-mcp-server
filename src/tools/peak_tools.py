"""
PEAK Framework MCP Tools

MCP tools for creating and managing PEAK Framework threat hunting reports.
"""

import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..peak.hunt_generator import ABLEScope, PEAKHunt, PEAKHuntGenerator

logger = logging.getLogger(__name__)


class PEAKTools:
    """MCP tools for PEAK Framework threat hunting"""

    def __init__(self, hunts_directory: Optional[Path] = None):
        """
        Initialize PEAK tools.

        Args:
            hunts_directory: Directory to store generated hunt reports
        """
        if hunts_directory is None:
            hunts_directory = Path("./hunts")

        self.hunts_directory = Path(hunts_directory)
        self.hunts_directory.mkdir(parents=True, exist_ok=True)

        self.generator = PEAKHuntGenerator()
        logger.info(f"PEAK tools initialized with hunts directory: {self.hunts_directory}")

    async def create_behavioral_hunt(
        self,
        technique_id: str,
        technique_name: str,
        tactic: str,
        hypothesis: str,
        hunter_name: str,
        location: str,
        data_sources: List[Dict[str, str]],
        actor: Optional[str] = None,
        threat_intel_sources: Optional[List[str]] = None,
        related_tickets: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """
        Creates a behavioral PEAK hunt focused on a MITRE ATT&CK technique.

        This tool emphasizes hunting for behaviors (TTPs) at the top of the
        Pyramid of Pain, not atomic indicators.

        Args:
            technique_id: MITRE technique ID (e.g., "T1003.001")
            technique_name: Name of the technique (e.g., "LSASS Memory")
            tactic: MITRE tactic (e.g., "Credential Access")
            hypothesis: Hunt hypothesis statement
            hunter_name: Name of the threat hunter
            location: Where to hunt (e.g., "Corporate Windows Servers")
            data_sources: List of log sources with format:
                [{"source": "Sysmon", "key_fields": "process_name, command_line",
                  "example": "mimikatz.exe execution"}]
            actor: Optional threat actor (behavioral hunting doesn't require this)
            threat_intel_sources: Optional list of threat intel sources
            related_tickets: Optional dict of related tickets

        Returns:
            Dictionary with hunt details and file path
        """
        try:
            # Create the hunt
            hunt = self.generator.create_behavioral_hunt(
                technique_id=technique_id,
                technique_name=technique_name,
                tactic=tactic,
                hypothesis=hypothesis,
                hunter_name=hunter_name,
                location=location,
                data_sources=data_sources,
                actor=actor,
                threat_intel_sources=threat_intel_sources or [],
                related_tickets=related_tickets or {},
            )

            # Generate the report
            output_path = self.hunts_directory / f"{hunt.hunt_id}_{technique_id.replace('.', '_')}.md"
            report = self.generator.generate_hunt_report(hunt, output_path)

            return {
                "status": "success",
                "hunt_id": hunt.hunt_id,
                "hunt_title": hunt.hunt_title,
                "technique": f"{technique_id} - {technique_name}",
                "tactic": tactic,
                "file_path": str(output_path),
                "message": f"✅ Behavioral hunt created for {technique_name} ({technique_id})",
                "pyramid_focus": "TTPs (Top of Pyramid) - Behavioral hunting for durable detections",
            }

        except Exception as e:
            logger.error(f"Failed to create behavioral hunt: {e}")
            return {"status": "error", "message": f"Failed to create hunt: {str(e)}"}

    async def create_custom_peak_hunt(
        self,
        hunt_title: str,
        hypothesis: str,
        hunter_name: str,
        behavior_description: str,
        location: str,
        data_sources: List[Dict[str, str]],
        mitre_techniques: List[str],
        mitre_tactics: List[str],
        hunt_type: str = "H",
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Creates a custom PEAK hunt report with full control over all fields.

        Args:
            hunt_title: Title of the hunt
            hypothesis: Hunt hypothesis statement
            hunter_name: Name of the threat hunter
            behavior_description: Description of the behavior being hunted (TTPs)
            location: Where to hunt
            data_sources: List of log sources
            mitre_techniques: List of MITRE technique IDs
            mitre_tactics: List of MITRE tactics
            hunt_type: H (Hypothesis), B (Baseline), or M (Model-Assisted)
            **kwargs: Additional optional parameters

        Returns:
            Dictionary with hunt details and file path
        """
        try:
            hunt_id = kwargs.get("hunt_id", f"{hunt_type}-{datetime.now().strftime('%Y%m%d-%H%M')}")

            # Create ABLE scope
            able_scope = ABLEScope(
                actor=kwargs.get("actor"),
                behavior=behavior_description,
                location=location,
                evidence=data_sources,
            )

            # Create the hunt
            hunt = PEAKHunt(
                hunt_id=hunt_id,
                hunt_title=hunt_title,
                hypothesis=hypothesis,
                hunter_name=hunter_name,
                date=kwargs.get("date", datetime.now().strftime("%Y-%m-%d")),
                requestor=kwargs.get("requestor", "Threat Hunting Team"),
                timeframe=kwargs.get("timeframe", "1-2 days"),
                able_scope=able_scope,
                mitre_tactics=mitre_tactics,
                mitre_techniques=mitre_techniques,
                related_tickets=kwargs.get("related_tickets", {}),
                threat_intel_sources=kwargs.get("threat_intel_sources", []),
                historical_context=kwargs.get("historical_context", ""),
                queries=kwargs.get("queries"),
                findings=kwargs.get("findings"),
                lessons_learned=kwargs.get("lessons_learned"),
            )

            # Generate the report
            output_path = self.hunts_directory / f"{hunt.hunt_id}_{hunt_title.replace(' ', '_')}.md"
            report = self.generator.generate_hunt_report(hunt, output_path)

            return {
                "status": "success",
                "hunt_id": hunt.hunt_id,
                "hunt_title": hunt.hunt_title,
                "hunt_type": hunt_type,
                "file_path": str(output_path),
                "message": f"✅ PEAK hunt report created: {hunt_title}",
            }

        except Exception as e:
            logger.error(f"Failed to create custom PEAK hunt: {e}")
            return {"status": "error", "message": f"Failed to create hunt: {str(e)}"}

    async def get_peak_template(self) -> Dict[str, Any]:
        """
        Returns the PEAK template content for reference.

        Returns:
            Dictionary with template content and usage instructions
        """
        try:
            return {
                "status": "success",
                "template_content": self.generator.template_content,
                "template_path": str(self.generator.template_path),
                "usage": {
                    "description": "PEAK Framework (Prepare, Execute, Act with Knowledge) template",
                    "phases": ["PREPARE: Define the Hunt", "EXECUTE: Run the Hunt", "ACT: Findings & Response", "K: Knowledge"],
                    "behavioral_focus": "Emphasizes hunting for behaviors (TTPs) at the top of the Pyramid of Pain",
                    "able_methodology": "Uses ABLE (Actor, Behavior, Location, Evidence) for scoping",
                },
                "reference": "https://dispatch.thorcollective.com/p/the-peak-threat-hunting-template",
            }

        except Exception as e:
            logger.error(f"Failed to get PEAK template: {e}")
            return {"status": "error", "message": f"Failed to get template: {str(e)}"}

    async def list_hunts(self) -> Dict[str, Any]:
        """
        Lists all PEAK hunts in the hunts directory.

        Returns:
            Dictionary with list of hunts
        """
        try:
            hunt_files = list(self.hunts_directory.glob("*.md"))

            hunts = []
            for hunt_file in hunt_files:
                # Parse hunt ID and basic info from filename
                filename = hunt_file.stem
                hunts.append(
                    {
                        "hunt_id": filename.split("_")[0] if "_" in filename else filename,
                        "filename": hunt_file.name,
                        "path": str(hunt_file),
                        "created": datetime.fromtimestamp(hunt_file.stat().st_ctime).strftime("%Y-%m-%d %H:%M:%S"),
                    }
                )

            return {
                "status": "success",
                "count": len(hunts),
                "hunts": hunts,
                "hunts_directory": str(self.hunts_directory),
            }

        except Exception as e:
            logger.error(f"Failed to list hunts: {e}")
            return {"status": "error", "message": f"Failed to list hunts: {str(e)}"}

    async def suggest_behavioral_hunt_from_ioc(self, ioc: str, ioc_type: str) -> Dict[str, Any]:
        """
        Suggests behavioral hunt alternatives when given an IOC.

        This is a KEY function that pivots from bottom-of-pyramid IOCs to
        top-of-pyramid behavioral hunts.

        Args:
            ioc: The indicator of compromise
            ioc_type: Type of IOC (hash, ip, domain, etc.)

        Returns:
            Dictionary with behavioral hunt suggestions
        """
        try:
            suggestions = []

            if ioc_type.lower() in ["ip", "domain"]:
                suggestions = [
                    {
                        "technique": "T1071.001 - Application Layer Protocol (Web)",
                        "hunt_focus": "C2 beaconing behavior patterns",
                        "hypothesis": "Hunt for regular interval communication patterns with consistent packet sizes indicating C2 beaconing",
                        "data_sources": [
                            {
                                "source": "Network flow logs",
                                "key_fields": "src_ip, dest_ip, bytes_out, bytes_in, timestamp",
                                "example": "Regular 60-second intervals with ~500 byte responses",
                            }
                        ],
                        "pyramid_level": "TTPs (Top)",
                    },
                    {
                        "technique": "T1071.004 - DNS Protocol",
                        "hunt_focus": "DNS tunneling behavior patterns",
                        "hypothesis": "Hunt for DNS queries with unusual subdomain patterns indicating data exfiltration",
                        "data_sources": [
                            {
                                "source": "DNS logs",
                                "key_fields": "query, query_length, response_code, timestamp",
                                "example": "Long subdomain strings >50 chars, high query volumes",
                            }
                        ],
                        "pyramid_level": "TTPs (Top)",
                    },
                ]

            elif ioc_type.lower() in ["hash", "md5", "sha256"]:
                suggestions = [
                    {
                        "technique": "T1055 - Process Injection",
                        "hunt_focus": "Process injection behavior patterns",
                        "hypothesis": "Hunt for process injection techniques regardless of malware hash",
                        "data_sources": [
                            {
                                "source": "Sysmon Event ID 8 (CreateRemoteThread)",
                                "key_fields": "SourceImage, TargetImage, StartAddress",
                                "example": "Injection into system processes (explorer.exe, lsass.exe)",
                            }
                        ],
                        "pyramid_level": "TTPs (Top)",
                    },
                    {
                        "technique": "T1003.001 - LSASS Memory",
                        "hunt_focus": "Credential dumping behavior",
                        "hypothesis": "Hunt for processes accessing LSASS memory for credential theft",
                        "data_sources": [
                            {
                                "source": "Sysmon Event ID 10 (ProcessAccess)",
                                "key_fields": "SourceImage, TargetImage, GrantedAccess",
                                "example": 'TargetImage="*lsass.exe" with suspicious SourceImage',
                            }
                        ],
                        "pyramid_level": "TTPs (Top)",
                    },
                ]

            elif ioc_type.lower() in ["url", "uri"]:
                suggestions = [
                    {
                        "technique": "T1505.003 - Web Shell",
                        "hunt_focus": "Web shell behavior patterns",
                        "hypothesis": "Hunt for web shell execution behaviors via unusual web server child processes",
                        "data_sources": [
                            {
                                "source": "Process creation logs",
                                "key_fields": "parent_process, process_name, command_line",
                                "example": "w3wp.exe spawning cmd.exe, powershell.exe",
                            }
                        ],
                        "pyramid_level": "TTPs (Top)",
                    }
                ]

            return {
                "status": "success",
                "ioc": ioc,
                "ioc_type": ioc_type,
                "pyramid_warning": f"⚠️  {ioc_type.upper()} is at the BOTTOM of the Pyramid of Pain. "
                f"Adversaries change these rapidly. Pivot to behavioral hunting for durable detections.",
                "behavioral_alternatives": suggestions,
                "recommendation": "Create a behavioral PEAK hunt using one of the suggestions above instead of hunting for the specific IOC.",
            }

        except Exception as e:
            logger.error(f"Failed to suggest behavioral hunt: {e}")
            return {"status": "error", "message": f"Failed to generate suggestions: {str(e)}"}
