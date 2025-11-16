from datetime import datetime
from typing import Dict, List, Optional

import structlog
from mcp.server.fastmcp import FastMCP

from .config import settings
from .frameworks.hunt_framework import ThreatHuntingFramework
from .intelligence.threat_intel import ThreatIntelligenceEngine

try:
    from .nlp.hunt_nlp import ThreatHuntingNLP

    NLP_AVAILABLE = True
except ImportError:
    NLP_AVAILABLE = False
from .models.hunt import HuntType, ThreatHunt
from .security.security_manager import CacheManager, SecurityManager
from .tools.hearth_tools import HEARTHTools

# # Configure logging - write to file instead of stdout to avoid interfering with MCP stdio protocol
# import sys
# structlog.configure(
#     processors=[
#         structlog.stdlib.filter_by_level,
#         structlog.stdlib.add_logger_name,
#         structlog.stdlib.add_log_level,
#         structlog.stdlib.PositionalArgumentsFormatter(),
#         structlog.processors.TimeStamper(fmt="iso"),
#         structlog.processors.StackInfoRenderer(),
#         structlog.processors.format_exc_info,
#         structlog.processors.UnicodeDecoder(),
#         structlog.processors.JSONRenderer()
#     ],
#     context_class=dict,
#     logger_factory=structlog.stdlib.LoggerFactory(),
#     wrapper_class=structlog.stdlib.BoundLogger,
#     cache_logger_on_first_use=True,
# )

# # Redirect all logs to stderr to keep stdout clean for MCP JSON-RPC protocol
# logging.basicConfig(
#     stream=sys.stderr,
#     level=logging.INFO,
#     format='%(message)s'
# )

logger = structlog.get_logger()

# # Log NLP availability after logger is defined
# if not NLP_AVAILABLE:
#     logger.warning("NLP module not available - spacy not installed. NLP features will be disabled.")


class ThreatHuntingMCPServer:
    """Production-ready MCP server for threat hunting"""

    def __init__(self):
        # Initialize MCP
        self.mcp = FastMCP(settings.server_name)

        # Initialize components
        self.framework = ThreatHuntingFramework()

        # Initialize integrations - commented out to avoid requiring credentials
        # self.atlassian = AtlassianThreatIntel(
        #     settings.atlassian_url,
        #     settings.atlassian_username,
        #     settings.atlassian_api_token
        # )
        self.atlassian = None

        # self.splunk = SplunkHuntingEngine(
        #     settings.splunk_host,
        #     settings.splunk_port,
        #     settings.splunk_token
        # )
        self.splunk = None

        self.threat_intel = ThreatIntelligenceEngine()
        self.nlp = ThreatHuntingNLP() if NLP_AVAILABLE else None

        # Initialize HEARTH community integration
        hearth_path = getattr(settings, "hearth_path", None)
        self.hearth = HEARTHTools(hearth_path) if hearth_path else None

        # Initialize security and caching
        security_config = {
            "jwt_secret": settings.jwt_secret,
            "encryption_key": settings.encryption_key,
            "audit_config": {"log_file": settings.audit_log_path},
            "redis": {
                "host": settings.redis_host,
                "port": settings.redis_port,
                "db": settings.redis_db,
                "password": settings.redis_password,
            },
        }

        self.security = SecurityManager(security_config)
        self.cache = CacheManager(security_config["redis"])

        # Register MCP tools, resources, and prompts
        self._register_tools()
        self._register_resources()
        self._register_prompts()

        # logger.info("ThreatHuntingMCPServer initialized successfully")

    def _register_tools(self):
        """Registers all MCP tools"""

        @self.mcp.tool()
        @self.security.rate_limit("hunt_threats", max_requests=50, window_seconds=3600)
        @self.security.require_permission("hunt:execute")
        async def hunt_threats(query: str, framework: str = "PEAK") -> Dict:
            """Natural language threat hunting interface

            Args:
                query: Natural language description of what to hunt for
                framework: Hunting framework to use (PEAK, SQRRL, Intelligence)

            Returns:
                Dictionary containing hunt results and analysis
            """
            user = self.security.get_current_user()
            await self.security.audit_log("hunt_threats", user, {"query": query, "framework": framework})

            try:
                # Sanitize input
                query = self.security.sanitize_input(query)

                # Process query through NLP
                processed = await self.nlp.process_hunt_query(query)

                if processed["status"] == "needs_clarification":
                    return processed

                # Create hunt based on framework
                hunt = await self._create_hunt_by_framework(processed, framework)

                # Execute hunt
                results = await self._execute_hunt(hunt)

                # Analyze results
                analysis = await self._analyze_hunt_results(hunt, results)

                # Create detections if successful
                detections = []
                if analysis.get("success"):
                    detections = await self._create_detections(hunt, analysis)

                return {
                    "hunt_id": hunt.hunt_id,
                    "framework": framework,
                    "hypothesis": hunt.hypothesis,
                    "results": analysis,
                    "detections_created": detections,
                    "recommendations": analysis.get("recommendations", []),
                }

            except Exception as e:
                logger.error("Error in hunt_threats", error=str(e), user=user)
                await self.security.audit_log("hunt_threats_error", user, {"query": query, "error": str(e)}, "ERROR")
                return {"error": str(e), "status": "failed"}

        @self.mcp.tool()
        @self.security.require_permission("hunt:create")
        async def create_baseline(environment: str, metrics: List[str]) -> Dict:
            """Creates baselines for normal behavior (PEAK Baseline Hunt)

            Args:
                environment: Environment to baseline (e.g., 'prod', 'dev')
                metrics: List of metrics to baseline

            Returns:
                Dictionary containing baseline statistics
            """
            user = self.security.get_current_user()
            await self.security.audit_log("create_baseline", user, {"environment": environment, "metrics": metrics})

            try:
                baselines = {}

                for metric in metrics:
                    hunt = self.framework.create_baseline_hunt(environment, metric)
                    results = await self.splunk.execute_baseline_hunt(metric, environment)

                    if "error" not in results:
                        baselines[metric] = {
                            "mean": results.get("baseline_avg", 0),
                            "std_dev": results.get("baseline_stdev", 0),
                            "p95": results.get("p95_value", 0),
                            "anomaly_threshold": results.get("baseline_avg", 0)
                            + (3 * results.get("baseline_stdev", 1)),
                        }
                    else:
                        baselines[metric] = {"error": results["error"]}

                # Store baselines for future hunts
                cache_key = f"baselines:{environment}"
                await self.cache.set(cache_key, baselines, "hunt_results")

                return {"baselines": baselines, "status": "success"}

            except Exception as e:
                logger.error("Error creating baseline", error=str(e))
                return {"error": str(e), "status": "failed"}

        @self.mcp.tool()
        @self.security.require_permission("hunt:execute")
        async def analyze_with_ml(data_source: str, algorithm: str = "isolation_forest") -> Dict:
            """Model-Assisted Threat Hunting (M-ATH) from PEAK framework

            Args:
                data_source: Data source to analyze
                algorithm: ML algorithm to use

            Returns:
                Dictionary containing anomaly detection results
            """
            user = self.security.get_current_user()
            await self.security.audit_log("analyze_with_ml", user, {"data_source": data_source, "algorithm": algorithm})

            try:
                # Retrieve data
                data = await self.splunk.get_data_for_ml(data_source)

                if not data:
                    return {"error": "No data available for analysis", "status": "failed"}

                # Create M-ATH hunt
                hunt = self.framework.create_math_hunt(algorithm, "anomaly")

                # Execute ML analysis
                results = await self.splunk.execute_math_hunt(algorithm, data)

                # Identify high-confidence anomalies
                anomalies = [r for r in results.get("anomalies", []) if r.get("confidence", 0) > 0.8]

                # Create Jira tickets for top anomalies
                tickets_created = []
                for anomaly in anomalies[:5]:  # Top 5
                    ticket_key = await self.atlassian.create_hunt_ticket(hunt)
                    if ticket_key:
                        tickets_created.append(ticket_key)

                return {
                    "hunt_id": hunt.hunt_id,
                    "algorithm": algorithm,
                    "total_anomalies": len(results.get("anomalies", [])),
                    "high_confidence_anomalies": len(anomalies),
                    "tickets_created": tickets_created,
                    "top_anomalies": anomalies[:10],
                    "status": "success",
                }

            except Exception as e:
                logger.error("Error in ML analysis", error=str(e))
                return {"error": str(e), "status": "failed"}

        @self.mcp.tool()
        @self.security.require_permission("query:splunk")
        async def execute_custom_query(query: str, index: str = "*") -> Dict:
            """Executes a custom Splunk query with security validation

            Args:
                query: SPL query to execute
                index: Splunk index to search (default: *)

            Returns:
                Dictionary containing query results
            """
            user = self.security.get_current_user()

            # Validate query for security
            if not self.security.validate_splunk_query(query):
                await self.security.audit_log("dangerous_query_blocked", user, {"query": query}, "WARNING")
                return {"error": "Query blocked for security reasons", "status": "blocked"}

            await self.security.audit_log("execute_custom_query", user, {"query": query, "index": index})

            try:
                # Add index prefix if not present
                if not query.strip().startswith("index="):
                    query = f"index={index} {query}"

                # Create a temporary hunt for tracking
                hunt = ThreatHunt(
                    hunt_id=self.framework._generate_hunt_id(),
                    hunt_type=HuntType.HYPOTHESIS_DRIVEN,
                    hypothesis="Custom query execution",
                    data_sources=[index],
                    queries=[query],
                    phase="execute",
                    maturity_level=self.framework._assess_maturity_level(),
                    created_at=datetime.utcnow(),
                )

                results = await self.splunk.execute_hypothesis_hunt(hunt)

                return {"hunt_id": hunt.hunt_id, "results": results, "status": "success"}

            except Exception as e:
                logger.error("Error executing custom query", error=str(e))
                return {"error": str(e), "status": "failed"}

        @self.mcp.tool()
        @self.security.require_permission("intel:analyze")
        async def analyze_adversary(adversary_id: str) -> Dict:
            """Analyzes a threat actor using multiple intelligence frameworks

            Args:
                adversary_id: MITRE ATT&CK Group ID (e.g., G0016)

            Returns:
                Dictionary containing comprehensive adversary analysis
            """
            user = self.security.get_current_user()
            await self.security.audit_log("analyze_adversary", user, {"adversary_id": adversary_id})

            try:
                # Use cache for adversary data
                cache_key = f"adversary_analysis:{adversary_id}"

                async def compute_analysis():
                    analysis = await self.threat_intel.analyze_adversary_behavior(adversary_id)
                    hypotheses = await self.threat_intel.generate_hunt_hypotheses(analysis)
                    analysis["generated_hypotheses"] = hypotheses
                    return analysis

                analysis = await self.cache.get_or_compute(cache_key, compute_analysis, "threat_actors")

                return {"adversary_id": adversary_id, "analysis": analysis, "status": "success"}

            except Exception as e:
                logger.error("Error analyzing adversary", error=str(e))
                return {"error": str(e), "status": "failed"}

        @self.mcp.tool()
        @self.security.require_permission("intel:enrich")
        async def enrich_ioc(ioc: str, ioc_type: str) -> Dict:
            """Enriches an IOC with threat intelligence

            Args:
                ioc: Indicator of Compromise
                ioc_type: Type of IOC (ip, domain, hash, etc.)

            Returns:
                Dictionary containing IOC enrichment data
            """
            user = self.security.get_current_user()
            await self.security.audit_log("enrich_ioc", user, {"ioc": ioc, "type": ioc_type})

            try:
                # Use cache for IOC enrichment
                cache_key = f"ioc_enrichment:{ioc_type}:{ioc}"

                async def compute_enrichment():
                    return await self.threat_intel.enrich_ioc(ioc, ioc_type)

                enrichment = await self.cache.get_or_compute(cache_key, compute_enrichment, "ioc_lookups")

                return {"ioc": ioc, "type": ioc_type, "enrichment": enrichment, "status": "success"}

            except Exception as e:
                logger.error("Error enriching IOC", error=str(e))
                return {"error": str(e), "status": "failed"}

        # ===== HEARTH COMMUNITY TOOLS =====
        if self.hearth:

            @self.mcp.tool()
            async def search_community_hunts(
                tactic: Optional[str] = None,
                tags: Optional[List[str]] = None,
                keyword: Optional[str] = None,
                hunt_type: Optional[str] = None,
                limit: int = 20,
            ) -> Dict:
                """Search HEARTH community threat hunting hypotheses

                Args:
                    tactic: Filter by MITRE ATT&CK tactic (e.g. "Credential Access")
                    tags: Filter by tags (e.g. ["lateral_movement", "powershell"])
                    keyword: Search keyword in hypothesis and description
                    hunt_type: Filter by hunt type: "flame", "ember", or "alchemy"
                    limit: Maximum number of results (default 20)

                Returns:
                    Dictionary with search results and metadata
                """
                try:
                    return await self.hearth.search_community_hunts(
                        tactic=tactic, tags=tags, keyword=keyword, hunt_type=hunt_type, limit=limit
                    )
                except Exception as e:
                    logger.error("Error searching HEARTH hunts", error=str(e))
                    return {"error": str(e), "status": "failed"}

            @self.mcp.tool()
            async def get_hunt_by_id(hunt_id: str) -> Dict:
                """Retrieve a specific community hunt by ID

                Args:
                    hunt_id: Hunt identifier (e.g. 'H001', 'B002', 'M003')

                Returns:
                    Dictionary with hunt details
                """
                try:
                    return await self.hearth.get_hunt_by_id(hunt_id)
                except Exception as e:
                    logger.error("Error getting hunt by ID", hunt_id=hunt_id, error=str(e))
                    return {"error": str(e), "status": "failed"}

            @self.mcp.tool()
            async def recommend_hunts(
                tactics: Optional[List[str]] = None,
                techniques: Optional[List[str]] = None,
                keywords: Optional[List[str]] = None,
                environment: Optional[str] = None,
                limit: int = 10,
            ) -> Dict:
                """Get AI-powered hunt recommendations from community knowledge

                Args:
                    tactics: MITRE ATT&CK tactics of interest
                    techniques: MITRE ATT&CK technique IDs
                    keywords: Keywords describing your concerns
                    environment: Environment description (e.g. "Windows AD environment")
                    limit: Maximum recommendations (default 10)

                Returns:
                    Dictionary with ranked hunt recommendations
                """
                try:
                    return await self.hearth.recommend_hunts(
                        tactics=tactics, techniques=techniques, keywords=keywords, environment=environment, limit=limit
                    )
                except Exception as e:
                    logger.error("Error generating recommendations", error=str(e))
                    return {"error": str(e), "status": "failed"}

            @self.mcp.tool()
            async def suggest_hunts_for_incident(incident_description: str) -> Dict:
                """Get hunt suggestions based on incident description

                Args:
                    incident_description: Description of the security incident

                Returns:
                    Dictionary with suggested hunts
                """
                try:
                    return await self.hearth.suggest_hunts_for_incident(incident_description)
                except Exception as e:
                    logger.error("Error suggesting hunts for incident", error=str(e))
                    return {"error": str(e), "status": "failed"}

            @self.mcp.tool()
            async def analyze_tactic_coverage() -> Dict:
                """Analyze MITRE ATT&CK tactic coverage in community hunts

                Returns:
                    Dictionary with tactic coverage analysis
                """
                try:
                    return await self.hearth.analyze_tactic_coverage()
                except Exception as e:
                    logger.error("Error analyzing tactic coverage", error=str(e))
                    return {"error": str(e), "status": "failed"}

            @self.mcp.tool()
            async def get_hearth_statistics() -> Dict:
                """Get statistics about HEARTH community repository

                Returns:
                    Dictionary with repository statistics
                """
                try:
                    return await self.hearth.get_hearth_statistics()
                except Exception as e:
                    logger.error("Error getting HEARTH statistics", error=str(e))
                    return {"error": str(e), "status": "failed"}

            @self.mcp.tool()
            async def get_hunts_for_tactic(tactic: str, limit: int = 20) -> Dict:
                """Get community hunts for a MITRE ATT&CK tactic

                Args:
                    tactic: MITRE ATT&CK tactic name (e.g. "Credential Access")
                    limit: Maximum number of hunts (default 20)

                Returns:
                    Dictionary with hunt list for the tactic
                """
                try:
                    return await self.hearth.get_hunts_for_tactic(tactic, limit)
                except Exception as e:
                    logger.error("Error getting hunts for tactic", tactic=tactic, error=str(e))
                    return {"error": str(e), "status": "failed"}

            @self.mcp.tool()
            async def get_hunts_for_technique(technique_id: str) -> Dict:
                """Get community hunts for a MITRE ATT&CK technique

                Args:
                    technique_id: MITRE ATT&CK technique ID (e.g. "T1110")

                Returns:
                    Dictionary with hunt list for the technique
                """
                try:
                    return await self.hearth.get_hunts_for_technique(technique_id)
                except Exception as e:
                    logger.error("Error getting hunts for technique", technique=technique_id, error=str(e))
                    return {"error": str(e), "status": "failed"}

            @self.mcp.tool()
            async def get_recent_community_hunts(days: int = 30, limit: int = 20) -> Dict:
                """Get recently added community hunts

                Args:
                    days: Number of days to look back (default 30)
                    limit: Maximum number of hunts (default 20)

                Returns:
                    Dictionary with recent hunts
                """
                try:
                    return await self.hearth.get_recent_community_hunts(days, limit)
                except Exception as e:
                    logger.error("Error getting recent hunts", error=str(e))
                    return {"error": str(e), "status": "failed"}

    def _register_resources(self):
        """Registers MCP resources"""

        @self.mcp.resource("resource://hunting_playbooks")
        async def get_playbooks() -> List[Dict]:
            """Retrieves hunting playbooks from Confluence"""

            async def fetch_playbooks():
                return await self.atlassian.get_hunting_playbooks(settings.confluence_space)

            return await self.cache.get_or_compute("playbooks:all", fetch_playbooks, "static_playbooks")

        @self.mcp.resource("resource://threat_intelligence")
        async def get_threat_intel() -> List[Dict]:
            """Retrieves threat intelligence from Confluence"""

            async def fetch_threat_intel():
                return await self.atlassian.get_threat_intelligence()

            return await self.cache.get_or_compute("threat_intel:all", fetch_threat_intel, "threat_actors")

        @self.mcp.resource("resource://mitre_attack_matrix")
        async def get_mitre_matrix() -> Dict:
            """Provides MITRE ATT&CK framework data"""
            return self.threat_intel.get_mitre_attack_matrix()

        @self.mcp.resource("resource://hunting_methodologies")
        async def get_methodologies() -> Dict:
            """Provides hunting methodology resources"""
            return {
                "peak": self.nlp._get_peak_methodology(),
                "sqrrl": self.framework.get_sqrrl_methodology(),
                "intelligence_driven": self.nlp._get_intelligence_methodology(),
            }

    def _register_prompts(self):
        """Registers MCP prompts"""

        @self.mcp.prompt("hypothesis_builder")
        async def build_hypothesis(adversary: str, objective: str = "general") -> str:
            """Interactive hypothesis builder following intelligence-driven methodology

            Args:
                adversary: Threat actor to analyze
                objective: Hunting objective
            """
            try:
                # Analyze adversary
                analysis = await self.threat_intel.analyze_adversary_behavior(adversary)

                # Generate hypotheses
                hypotheses = await self.threat_intel.generate_hunt_hypotheses(analysis)

                # Create testable queries
                queries = []
                techniques = analysis.get("mitre_attack", {}).get("techniques", [])
                for technique in techniques[:5]:  # Limit to top 5
                    technique_queries = self.splunk.get_hunt_queries_by_technique(technique["id"])
                    queries.extend(technique_queries)

                prompt_response = f"""
# Threat Hunt Hypothesis Builder

## Adversary Analysis: {adversary}
**Description:** {analysis.get('mitre_attack', {}).get('description', 'No description available')}

## Generated Hypotheses:
{chr(10).join(f"{i + 1}. {h}" for i, h in enumerate(hypotheses[:5]))}

## Recommended Test Queries:
{chr(10).join(f"### Query {i + 1}:{chr(10)}```spl{chr(10)}{q}{chr(10)}```" for i, q in enumerate(queries[:3]))}

## Next Steps:
1. Select a hypothesis to test
2. Customize the queries for your environment
3. Execute the hunt using the hunt_threats tool
4. Analyze results and iterate

Use this information to create targeted threat hunts based on known adversary behavior.
"""

                return prompt_response

            except Exception as e:
                return f"Error building hypothesis: {str(e)}"

        @self.mcp.prompt("hunt_planner")
        async def plan_hunt(threat_scenario: str, data_sources: str = "") -> str:
            """Plans a comprehensive threat hunt based on a scenario

            Args:
                threat_scenario: Description of the threat scenario
                data_sources: Available data sources
            """
            try:
                # Process scenario through NLP
                processed = await self.nlp.process_hunt_query(threat_scenario)

                # Get methodology recommendations
                methodologies = await self.get_methodologies()

                plan = f"""
# Threat Hunt Plan

## Scenario Analysis
**Threat Scenario:** {threat_scenario}
**Available Data Sources:** {data_sources or 'Auto-detected from environment'}

## Recommended Approach
Based on the scenario analysis, here's a structured hunting approach:

### PEAK Framework Application:
1. **Prepare Phase:**
   - Research threat actor TTPs
   - Identify data requirements
   - Frame testable hypotheses

2. **Execute Phase:**
   - Run baseline queries
   - Execute hypothesis tests
   - Follow investigative leads

3. **Act with Knowledge Phase:**
   - Document findings
   - Create automated detections
   - Share intelligence

### Suggested Hunt Types:
"""

                if processed.get("intent") == "baseline_analysis":
                    plan += "\n- **Baseline Hunt:** Establish normal patterns first"
                elif processed.get("entities", {}).get("anomaly_types"):
                    plan += "\n- **Model-Assisted Hunt:** Use ML for anomaly detection"
                else:
                    plan += "\n- **Hypothesis-Driven Hunt:** Test specific adversary behaviors"

                plan += f"""

### Implementation Steps:
1. Use `create_baseline` tool if establishing baselines
2. Use `hunt_threats` tool with natural language query
3. Use `analyze_with_ml` tool for anomaly detection
4. Use `analyze_adversary` tool for threat actor analysis

### Success Criteria:
- Clear hypothesis validation or rejection
- Actionable intelligence gathered
- Detections created for confirmed threats
- Knowledge documented for future hunts
"""

                return plan

            except Exception as e:
                return f"Error planning hunt: {str(e)}"

    async def _create_hunt_by_framework(self, processed_query: Dict, framework: str) -> ThreatHunt:
        """Creates a hunt based on the specified framework"""
        entities = processed_query.get("entities", {})
        intent = processed_query.get("intent", "generate_query")

        if framework.upper() == "PEAK":
            if intent == "baseline_analysis":
                environment = entities.get("platforms", ["general"])[0]
                metric = entities.get("metrics", ["activity_count"])[0]
                return self.framework.create_baseline_hunt(environment, metric)
            elif intent == "anomaly_detection":
                algorithm = "isolation_forest"
                anomaly_type = entities.get("anomaly_types", ["general"])[0]
                return self.framework.create_math_hunt(algorithm, anomaly_type)
            else:
                hypothesis = processed_query.get("hypothesis", "Detect suspicious activity")
                adversary = entities.get("actors", ["unknown"])[0]
                return self.framework.create_hypothesis_driven_hunt(hypothesis, adversary, "security_breach")
        else:
            # Default to hypothesis-driven for other frameworks
            hypothesis = processed_query.get("hypothesis", "Detect suspicious activity")
            adversary = entities.get("actors", ["unknown"])[0]
            return self.framework.create_hypothesis_driven_hunt(hypothesis, adversary, "security_breach")

    async def _execute_hunt(self, hunt: ThreatHunt) -> Dict:
        """Executes a hunt based on its type"""
        user = self.security.get_current_user()
        await self.security.audit_log("execute_hunt", user, {"hunt_id": hunt.hunt_id})

        if hunt.hunt_type == HuntType.HYPOTHESIS_DRIVEN:
            return await self.splunk.execute_hypothesis_hunt(hunt)
        elif hunt.hunt_type == HuntType.BASELINE:
            return await self.splunk.execute_baseline_hunt(hunt.data_sources[0], hunt.queries[0])
        elif hunt.hunt_type == HuntType.MODEL_ASSISTED:
            data = await self.splunk.get_data_for_ml(hunt.data_sources[0])
            return await self.splunk.execute_math_hunt(hunt.queries[0], data)
        else:
            raise ValueError(f"Unknown hunt type: {hunt.hunt_type}")

    async def _analyze_hunt_results(self, hunt: ThreatHunt, results: Dict) -> Dict:
        """Analyzes hunt results to determine success and findings"""
        analysis = {"success": False, "findings": [], "recommendations": [], "confidence": 0.0}

        if hunt.hunt_type == HuntType.HYPOTHESIS_DRIVEN:
            for query, result in results.items():
                if isinstance(result, dict) and result.get("count", 0) > 0:
                    analysis["success"] = True
                    analysis["findings"].append(
                        {"query": query, "matches": result["count"], "sample_data": result.get("data", [])[:5]}
                    )

        elif hunt.hunt_type == HuntType.BASELINE:
            if "error" not in results and results.get("baseline_avg") is not None:
                analysis["success"] = True
                analysis["findings"].append({"baseline_established": True, "statistics": results})

        elif hunt.hunt_type == HuntType.MODEL_ASSISTED:
            anomaly_score = results.get("anomaly_score", 0)
            if anomaly_score > 0.5:
                analysis["success"] = True
                analysis["confidence"] = anomaly_score
                analysis["findings"] = results.get("anomalies", [])[:10]

        # Generate recommendations
        if analysis["success"]:
            analysis["recommendations"] = self._generate_recommendations(hunt, analysis["findings"])

        # Update hunt record
        hunt.results = analysis
        hunt.phase = "act"
        hunt.updated_at = datetime.utcnow()

        # Create Jira ticket for significant findings
        if analysis["success"] and len(analysis["findings"]) > 0:
            await self.atlassian.create_hunt_ticket(hunt, settings.jira_project)

        return analysis

    async def _create_detections(self, hunt: ThreatHunt, analysis: Dict) -> List[str]:
        """Converts successful hunts into automated detections"""
        detections = []

        try:
            for i, finding in enumerate(analysis["findings"][:3]):  # Limit to top 3
                if "query" in finding:
                    detection = {
                        "name": f"ThreatHunt_{
                            hunt.hunt_id}_{
                            i + 1}",
                        "description": f"Detection based on hunt: {
                            hunt.hypothesis}",
                        "query": finding["query"],
                        "threshold": max(1, finding.get("matches", 1) // 2),
                        "severity": self._assess_severity(finding),
                        "mitre_techniques": [t["id"] for t in hunt.data_sources if t.startswith("T")],
                    }

                    # Deploy to Splunk
                    detection_id = await self.splunk.create_saved_search(detection)
                    if detection_id:
                        detections.append(detection_id)

                        # Document in Confluence
                        await self.atlassian.create_detection_page(detection, settings.confluence_space)

            hunt.detections_created = detections

        except Exception as e:
            logger.error("Error creating detections", error=str(e))

        return detections

    def _generate_recommendations(self, hunt: ThreatHunt, findings: List[Dict]) -> List[str]:
        """Generates actionable recommendations based on hunt results"""
        recommendations = []

        if hunt.hunt_type == HuntType.HYPOTHESIS_DRIVEN:
            if findings:
                recommendations.append("Create automated detection rules for confirmed behaviors")
                recommendations.append("Investigate sample events for additional context")
                recommendations.append("Update threat intelligence with confirmed TTPs")
            else:
                recommendations.append("Refine hypothesis and adjust query parameters")
                recommendations.append("Consider alternative data sources")

        elif hunt.hunt_type == HuntType.BASELINE:
            recommendations.append("Use baseline for anomaly detection in future hunts")
            recommendations.append("Schedule regular baseline updates")
            recommendations.append("Create alerts for significant deviations")

        elif hunt.hunt_type == HuntType.MODEL_ASSISTED:
            recommendations.append("Investigate high-confidence anomalies manually")
            recommendations.append("Tune algorithm parameters based on results")
            recommendations.append("Consider ensemble methods for improved accuracy")

        return recommendations

    def _assess_severity(self, finding: Dict) -> str:
        """Assesses the severity of a finding"""
        matches = finding.get("matches", 0)

        if matches > 100:
            return "High"
        elif matches > 10:
            return "Medium"
        else:
            return "Low"


async def main():
    """Main entry point for the MCP server"""
    try:
        # logger.info("Starting Threat Hunting MCP Server")
        server = ThreatHuntingMCPServer()

        # Run the server
        await server.mcp.run()

    except Exception as e:
        # logger.error("Failed to start server", error=str(e))
        raise
