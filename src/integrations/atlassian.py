import logging
import re
from datetime import datetime
from typing import Dict, List, Optional

from atlassian import Confluence, Jira

from ..models.hunt import ThreatHunt

logger = logging.getLogger(__name__)


class AtlassianThreatIntel:
    """Manages threat hunting documentation and tracking"""

    def __init__(self, url: str, username: str, api_token: str):
        self.confluence = Confluence(url=url, username=username, password=api_token, cloud=True)
        self.jira = Jira(url=url, username=username, password=api_token, cloud=True)

    async def get_hunting_playbooks(self, space: str = "THREATHUNT") -> List[Dict]:
        """Retrieves threat hunting playbooks from Confluence"""
        try:
            cql = f'space = "{space}" AND label = "playbook"'
            results = self.confluence.cql(cql, limit=100)

            playbooks = []
            for page in results["results"]:
                content = self.confluence.get_page_by_id(page["id"], expand="body.storage")
                playbooks.append(
                    {
                        "id": page["id"],
                        "title": page["title"],
                        "content": content["body"]["storage"]["value"],
                        "techniques": self._extract_mitre_techniques(content),
                        "queries": self._extract_spl_queries(content),
                        "last_modified": page.get("lastModified", {}).get("when"),
                    }
                )

            logger.info(
                f"Retrieved {
                    len(playbooks)} hunting playbooks from Confluence"
            )
            return playbooks

        except Exception as e:
            logger.error(f"Error retrieving hunting playbooks: {str(e)}")
            return []

    async def create_hunt_ticket(self, hunt: ThreatHunt, project_key: str = "HUNT") -> Optional[str]:
        """Creates a Jira ticket for tracking a threat hunt"""
        try:
            issue_dict = {
                "project": {"key": project_key},
                "summary": f"Threat Hunt: {hunt.hypothesis[:100]}...",
                "description": self._format_hunt_description(hunt),
                "issuetype": {"name": "Task"},
                "labels": ["threat-hunting", hunt.phase, hunt.hunt_type.value],
            }

            # Add custom fields if they exist
            custom_fields = self._get_hunt_custom_fields(hunt)
            issue_dict.update(custom_fields)

            new_issue = self.jira.create_issue(fields=issue_dict)
            hunt_ticket_key = new_issue["key"]

            logger.info(
                f"Created Jira ticket {hunt_ticket_key} for hunt {
                    hunt.hunt_id}"
            )
            return hunt_ticket_key

        except Exception as e:
            logger.error(f"Error creating hunt ticket: {str(e)}")
            return None

    async def update_hunt_ticket(self, ticket_key: str, hunt: ThreatHunt) -> bool:
        """Updates a Jira ticket with hunt results"""
        try:
            update_dict = {
                "description": self._format_hunt_description(hunt),
                "labels": ["threat-hunting", hunt.phase, hunt.hunt_type.value],
            }

            if hunt.results:
                comment = self._format_hunt_results_comment(hunt.results)
                self.jira.add_comment(ticket_key, comment)

            self.jira.update_issue(ticket_key, fields=update_dict)
            logger.info(f"Updated Jira ticket {ticket_key} with hunt results")
            return True

        except Exception as e:
            logger.error(f"Error updating hunt ticket: {str(e)}")
            return False

    async def create_detection_page(self, detection: Dict, space: str = "THREATHUNT") -> Optional[str]:
        """Creates a Confluence page for a new detection rule"""
        try:
            page_title = f"Detection: {detection['name']}"
            page_content = self._format_detection_page_content(detection)

            new_page = self.confluence.create_page(
                space=space, title=page_title, body=page_content, labels=["detection-rule", "automated"]
            )

            page_url = f"{
                self.confluence.url}/wiki{
                new_page['_links']['webui']}"
            logger.info(f"Created detection page: {page_url}")
            return page_url

        except Exception as e:
            logger.error(f"Error creating detection page: {str(e)}")
            return None

    async def get_threat_intelligence(self, space: str = "THREATINTEL") -> List[Dict]:
        """Retrieves threat intelligence from Confluence"""
        try:
            cql = f'space = "{space}" AND label = "threat-intel"'
            results = self.confluence.cql(cql, limit=50)

            threat_intel = []
            for page in results["results"]:
                content = self.confluence.get_page_by_id(page["id"], expand="body.storage")
                threat_intel.append(
                    {
                        "id": page["id"],
                        "title": page["title"],
                        "content": content["body"]["storage"]["value"],
                        "iocs": self._extract_iocs(content),
                        "techniques": self._extract_mitre_techniques(content),
                        "actors": self._extract_threat_actors(content),
                    }
                )

            return threat_intel

        except Exception as e:
            logger.error(f"Error retrieving threat intelligence: {str(e)}")
            return []

    def _extract_mitre_techniques(self, content: Dict) -> List[str]:
        """Extracts MITRE ATT&CK techniques from documentation"""
        pattern = r"T\d{4}(?:\.\d{3})?"
        html_content = content["body"]["storage"]["value"]
        return list(set(re.findall(pattern, html_content)))

    def _extract_spl_queries(self, content: Dict) -> List[str]:
        """Extracts Splunk queries from documentation"""
        html_content = content["body"]["storage"]["value"]
        # Look for code blocks that might contain SPL
        code_pattern = r'<ac:structured-macro.*?name="code".*?>(.*?)</ac:structured-macro>'
        code_blocks = re.findall(code_pattern, html_content, re.DOTALL)

        spl_queries = []
        for block in code_blocks:
            # Extract the actual code content
            content_match = re.search(r"<!\[CDATA\[(.*?)\]\]>", block, re.DOTALL)
            if content_match:
                query = content_match.group(1).strip()
                if "index=" in query or "|" in query:  # Likely SPL
                    spl_queries.append(query)

        return spl_queries

    def _extract_iocs(self, content: Dict) -> Dict[str, List[str]]:
        """Extracts IOCs from content"""
        html_content = content["body"]["storage"]["value"]

        iocs = {
            "ips": re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", html_content),
            "domains": re.findall(r"\b[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}\b", html_content),
            "hashes": {
                "md5": re.findall(r"\b[a-f0-9]{32}\b", html_content, re.IGNORECASE),
                "sha256": re.findall(r"\b[a-f0-9]{64}\b", html_content, re.IGNORECASE),
            },
            "urls": re.findall(r'https?://[^\s<>"\']+', html_content),
        }

        return iocs

    def _extract_threat_actors(self, content: Dict) -> List[str]:
        """Extracts threat actor names from content"""
        html_content = content["body"]["storage"]["value"]
        # Common threat actor naming patterns
        actor_patterns = [r"\bAPT\d+\b", r"\bFIN\d+\b", r"\bTA\d+\b", r"\bG\d{4}\b"]  # MITRE group IDs

        actors = []
        for pattern in actor_patterns:
            actors.extend(re.findall(pattern, html_content, re.IGNORECASE))

        return list(set(actors))

    def _format_hunt_description(self, hunt: ThreatHunt) -> str:
        """Formats hunt information for Jira description"""
        description = f"""
## Threat Hunt Details

**Hunt ID:** {hunt.hunt_id}
**Type:** {hunt.hunt_type.value}
**Phase:** {hunt.phase}
**Maturity Level:** HMM{hunt.maturity_level.value}
**Created:** {hunt.created_at.isoformat() if hunt.created_at else 'Unknown'}

## Hypothesis
{hunt.hypothesis}

## Data Sources
{chr(10).join(f"* {source}" for source in hunt.data_sources)}

## Queries
{chr(10).join(f"```{chr(10)}{query}{chr(10)}```" for query in hunt.queries)}

## Results
{self._format_results_summary(hunt.results) if hunt.results else 'Hunt in progress...'}
"""
        return description

    def _format_results_summary(self, results: Dict) -> str:
        """Formats hunt results for display"""
        if not results:
            return "No results available"

        summary = f"""
**Success:** {'Yes' if results.get('success') else 'No'}
**Confidence:** {results.get('confidence', 0):.2f}
**Findings:** {len(results.get('findings', []))}
**Recommendations:** {len(results.get('recommendations', []))}
"""
        return summary

    def _format_hunt_results_comment(self, results: Dict) -> str:
        """Formats hunt results as Jira comment"""
        comment = f"""
Hunt execution completed with the following results:

**Success:** {'✅ Yes' if results.get('success') else '❌ No'}
**Confidence Score:** {results.get('confidence', 0):.2f}

**Key Findings:**
{chr(10).join(f"• {finding.get('description', 'Finding')}" for finding in results.get('findings', [])[:5])}

**Recommendations:**
{chr(10).join(f"• {rec}" for rec in results.get('recommendations', [])[:5])}

*Updated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC*
"""
        return comment

    def _format_detection_page_content(self, detection: Dict) -> str:
        """Formats detection rule as Confluence page content"""
        content = f"""
<h1>Detection Rule: {detection['name']}</h1>

<h2>Description</h2>
<p>{detection.get('description', 'Automated detection rule')}</p>

<h2>Query</h2>
<ac:structured-macro ac:name="code" ac:schema-version="1">
<ac:parameter ac:name="language">sql</ac:parameter>
<ac:plain-text-body><![CDATA[
{detection['query']}
]]></ac:plain-text-body>
</ac:structured-macro>

<h2>Details</h2>
<ul>
<li><strong>Severity:</strong> {detection.get('severity', 'Medium')}</li>
<li><strong>Threshold:</strong> {detection.get('threshold', 'N/A')}</li>
<li><strong>Created:</strong> {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC</li>
</ul>

<h2>MITRE ATT&CK Techniques</h2>
<ul>
{chr(10).join(f"<li>{technique}</li>" for technique in detection.get('mitre_techniques', []))}
</ul>

<p><em>This page was automatically generated from a successful threat hunt.</em></p>
"""
        return content

    def _get_hunt_custom_fields(self, hunt: ThreatHunt) -> Dict:
        """Returns custom field mappings for hunt tickets"""
        # These would need to be configured based on your Jira instance
        custom_fields = {}

        # Example custom field mappings (adjust field IDs as needed)
        # custom_fields['customfield_10001'] = hunt.hunt_type.value  # Hunt Type
        # custom_fields['customfield_10002'] = hunt.maturity_level.value  #
        # Maturity Level

        return custom_fields
