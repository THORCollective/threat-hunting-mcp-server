import spacy
from typing import List, Dict, Tuple, Optional
import re
import logging
import asyncio

# For production, you would install and use transformers
# from transformers import pipeline

logger = logging.getLogger(__name__)


class ThreatHuntingNLP:
    """Natural language processing for threat hunting queries"""
    
    def __init__(self):
        # In production, you would load actual models
        # self.nlp = spacy.load("en_core_web_lg")
        # self.intent_classifier = pipeline("zero-shot-classification")
        self.entity_patterns = self._load_security_patterns()
        self.intent_keywords = self._load_intent_keywords()
        
    async def process_hunt_query(self, query: str) -> Dict:
        """Processes natural language hunting queries"""
        # Classify intent
        intent = self._classify_intent(query)
        
        # Extract entities
        entities = self._extract_entities(query)
        
        # Handle ambiguity
        if self._is_ambiguous(query, entities):
            clarifications = self._generate_clarifying_questions(query, entities)
            return {'status': 'needs_clarification', 'questions': clarifications}
        
        # Generate response based on intent
        if intent == 'generate_query':
            return await self._handle_query_generation(query, entities)
        elif intent == 'explain_technique':
            return await self._handle_technique_explanation(entities)
        elif intent == 'analyze_ioc':
            return await self._handle_ioc_analysis(entities)
        elif intent == 'hunt_methodology':
            return await self._handle_methodology_request(query, entities)
        elif intent == 'baseline_analysis':
            return await self._handle_baseline_request(query, entities)
        elif intent == 'anomaly_detection':
            return await self._handle_anomaly_request(query, entities)
        else:
            return {'status': 'error', 'message': f'Unknown intent: {intent}'}
            
    def _classify_intent(self, query: str) -> str:
        """Classifies the intent of a threat hunting query"""
        query_lower = query.lower()
        
        # Simple keyword-based classification (in production, use ML model)
        for intent, keywords in self.intent_keywords.items():
            if any(keyword in query_lower for keyword in keywords):
                return intent
        
        # Default to query generation
        return 'generate_query'
        
    def _extract_entities(self, query: str) -> Dict:
        """Extracts security-specific entities from queries"""
        entities = {
            'techniques': [],
            'iocs': [],
            'tools': [],
            'actors': [],
            'platforms': [],
            'timeframes': [],
            'metrics': [],
            'anomaly_types': []
        }
        
        # Pattern-based extraction
        for pattern_type, patterns in self.entity_patterns.items():
            for pattern in patterns:
                matches = re.findall(pattern['regex'], query, re.IGNORECASE)
                if matches:
                    entities[pattern_type].extend(matches)
        
        # Simple keyword matching for entities not covered by regex
        entity_keywords = {
            'tools': ['mimikatz', 'psexec', 'powershell', 'cmd', 'wmic', 'netsh'],
            'actors': ['apt28', 'apt29', 'lazarus', 'cozy bear', 'fancy bear'],
            'platforms': ['windows', 'linux', 'macos', 'endpoint', 'network'],
            'metrics': ['cpu', 'memory', 'network', 'disk', 'login', 'process'],
            'anomaly_types': ['outlier', 'anomaly', 'unusual', 'suspicious', 'abnormal']
        }
        
        query_lower = query.lower()
        for entity_type, keywords in entity_keywords.items():
            for keyword in keywords:
                if keyword in query_lower:
                    entities[entity_type].append(keyword)
        
        # Remove duplicates
        for key in entities:
            entities[key] = list(set(entities[key]))
        
        return entities
    
    def _is_ambiguous(self, query: str, entities: Dict) -> bool:
        """Determines if a query is ambiguous and needs clarification"""
        # Check for vague terms
        vague_terms = ['something', 'anything', 'stuff', 'thing', 'some']
        if any(term in query.lower() for term in vague_terms):
            return True
        
        # Check if multiple conflicting intents
        intent_indicators = 0
        for intent_keywords in self.intent_keywords.values():
            if any(keyword in query.lower() for keyword in intent_keywords):
                intent_indicators += 1
        
        return intent_indicators > 2
    
    def _generate_clarifying_questions(self, query: str, entities: Dict) -> List[str]:
        """Generates clarifying questions for ambiguous queries"""
        questions = []
        
        if not entities['timeframes']:
            questions.append("What time period should I search? (e.g., last 24 hours, past week)")
        
        if not entities['platforms'] and 'generate_query' in self._classify_intent(query):
            questions.append("Which platform/environment? (Windows, Linux, Network logs)")
        
        if len([e for e in entities.values() if e]) == 0:
            questions.append("Could you be more specific about what you're looking for?")
        
        return questions
    
    async def _handle_query_generation(self, query: str, entities: Dict) -> Dict:
        """Generates SPL queries from natural language"""
        query_type = self._determine_query_type(query, entities)
        
        if 'lateral movement' in query.lower():
            spl_query = self._generate_lateral_movement_query(entities)
        elif 'credential' in query.lower() or 'password' in query.lower():
            spl_query = self._generate_credential_query(entities)
        elif 'persistence' in query.lower():
            spl_query = self._generate_persistence_query(entities)
        elif 'process injection' in query.lower() or 'injection' in query.lower():
            spl_query = self._generate_process_injection_query(entities)
        elif 'command and control' in query.lower() or 'c2' in query.lower():
            spl_query = self._generate_c2_query(entities)
        else:
            spl_query = self._generate_generic_query(entities)
            
        return {
            'status': 'success',
            'intent': 'generate_query',
            'query_type': query_type,
            'spl_query': spl_query,
            'explanation': self._explain_query(spl_query, query_type),
            'related_techniques': self._get_related_techniques(query_type),
            'entities_found': entities
        }
    
    async def _handle_technique_explanation(self, entities: Dict) -> Dict:
        """Handles requests for technique explanations"""
        techniques = entities.get('techniques', [])
        
        if not techniques:
            return {
                'status': 'error',
                'message': 'No MITRE ATT&CK techniques found in query'
            }
        
        explanations = {}
        for technique_id in techniques:
            explanations[technique_id] = self._get_technique_explanation(technique_id)
        
        return {
            'status': 'success',
            'intent': 'explain_technique',
            'explanations': explanations
        }
    
    async def _handle_ioc_analysis(self, entities: Dict) -> Dict:
        """Handles IOC analysis requests"""
        iocs = entities.get('iocs', [])
        
        if not iocs:
            return {
                'status': 'error',
                'message': 'No indicators of compromise found in query'
            }
        
        analysis = {}
        for ioc in iocs:
            ioc_type = self._determine_ioc_type(ioc)
            analysis[ioc] = {
                'type': ioc_type,
                'pyramid_level': self._get_pyramid_level(ioc_type),
                'hunt_queries': self._generate_ioc_hunt_queries(ioc, ioc_type)
            }
        
        return {
            'status': 'success',
            'intent': 'analyze_ioc',
            'ioc_analysis': analysis
        }
    
    async def _handle_methodology_request(self, query: str, entities: Dict) -> Dict:
        """Handles methodology-related requests"""
        methodologies = {
            'peak': self._get_peak_methodology(),
            'sqrrl': self._get_sqrrl_methodology(),
            'intelligence': self._get_intelligence_methodology()
        }
        
        requested_methodology = None
        for methodology in methodologies:
            if methodology in query.lower():
                requested_methodology = methodology
                break
        
        if requested_methodology:
            return {
                'status': 'success',
                'intent': 'hunt_methodology',
                'methodology': requested_methodology,
                'details': methodologies[requested_methodology]
            }
        else:
            return {
                'status': 'success',
                'intent': 'hunt_methodology',
                'available_methodologies': list(methodologies.keys()),
                'details': methodologies
            }
    
    async def _handle_baseline_request(self, query: str, entities: Dict) -> Dict:
        """Handles baseline establishment requests"""
        metrics = entities.get('metrics', [])
        platforms = entities.get('platforms', ['general'])
        
        if not metrics:
            metrics = ['login_count', 'process_count', 'network_connections']
        
        baseline_queries = []
        for metric in metrics:
            for platform in platforms:
                baseline_queries.append(self._generate_baseline_query(metric, platform))
        
        return {
            'status': 'success',
            'intent': 'baseline_analysis',
            'metrics': metrics,
            'platforms': platforms,
            'baseline_queries': baseline_queries,
            'methodology': 'PEAK Baseline Hunt'
        }
    
    async def _handle_anomaly_request(self, query: str, entities: Dict) -> Dict:
        """Handles anomaly detection requests"""
        anomaly_types = entities.get('anomaly_types', ['general'])
        platforms = entities.get('platforms', ['endpoint'])
        
        algorithms = ['isolation_forest', 'clustering', 'time_series']
        
        return {
            'status': 'success',
            'intent': 'anomaly_detection',
            'anomaly_types': anomaly_types,
            'platforms': platforms,
            'recommended_algorithms': algorithms,
            'methodology': 'PEAK Model-Assisted Threat Hunting (M-ATH)'
        }
    
    def _determine_query_type(self, query: str, entities: Dict) -> str:
        """Determines the type of query being requested"""
        query_lower = query.lower()
        
        if 'lateral movement' in query_lower:
            return 'lateral_movement'
        elif 'credential' in query_lower or 'password' in query_lower:
            return 'credential_access'
        elif 'persistence' in query_lower:
            return 'persistence'
        elif 'process injection' in query_lower:
            return 'process_injection'
        elif 'command and control' in query_lower or 'c2' in query_lower:
            return 'command_and_control'
        elif 'discovery' in query_lower:
            return 'discovery'
        else:
            return 'general_hunting'
    
    def _generate_lateral_movement_query(self, entities: Dict) -> str:
        """Generates SPL for detecting lateral movement"""
        base_query = """
        index=windows EventCode=4624 Logon_Type IN (3,10)
        | eval hour=strftime(_time, "%H")
        | stats count by Account_Name, Source_Network_Address, 
                Workstation_Name, hour
        | where count > 5
        | eventstats avg(count) as avg_count by Account_Name
        | where count > avg_count*2
        """
        
        # Add entity-specific filters
        if entities.get('timeframes'):
            timeframe = entities['timeframes'][0]
            base_query = f"earliest={timeframe} " + base_query
        
        if entities.get('actors'):
            actor = entities['actors'][0]
            base_query += f"\n| eval threat_actor=\"{actor}\""
            
        return base_query.strip()
    
    def _generate_credential_query(self, entities: Dict) -> str:
        """Generates SPL for detecting credential access"""
        return """
        index=sysmon EventCode=10 TargetImage="*\\lsass.exe"
        | stats count by SourceImage, SourceUser, Computer_Name
        | where count > 2
        | eval technique="T1003.001"
        """
    
    def _generate_persistence_query(self, entities: Dict) -> str:
        """Generates SPL for detecting persistence mechanisms"""
        return """
        (index=sysmon EventCode=13 TargetObject="*\\Run\\*") OR
        (index=windows EventCode=4698)
        | stats count by Computer_Name, Image, Details
        | eval persistence_type=case(
            match(TargetObject, ".*Run.*"), "Registry Run Key",
            EventCode=4698, "Scheduled Task",
            1=1, "Other"
        )
        """
    
    def _generate_process_injection_query(self, entities: Dict) -> str:
        """Generates SPL for detecting process injection"""
        return """
        index=sysmon EventCode=8
        | stats count by SourceImage, TargetImage, Computer_Name
        | where SourceImage!=TargetImage
        | eval suspicious=if(
            match(TargetImage, ".*(explorer|winlogon|csrss|lsass).*"), "High", "Medium"
        )
        | eval technique="T1055"
        """
    
    def _generate_c2_query(self, entities: Dict) -> str:
        """Generates SPL for detecting command and control"""
        return """
        index=network
        | stats count by src_ip, dest_ip, dest_port
        | where count > 100
        | lookup suspicious_domains dest_ip OUTPUT threat_level
        | where isnotnull(threat_level)
        | eval technique="T1071"
        """
    
    def _generate_generic_query(self, entities: Dict) -> str:
        """Generates a generic hunting query"""
        base_query = "index=* earliest=-24h@h latest=now"
        
        # Add filters based on entities
        if entities.get('tools'):
            tools = "|".join(entities['tools'])
            base_query += f" | search {tools}"
        
        if entities.get('iocs'):
            iocs = "|".join(entities['iocs'])
            base_query += f" | search {iocs}"
        
        base_query += " | head 1000 | stats count by sourcetype, host"
        
        return base_query
    
    def _generate_baseline_query(self, metric: str, platform: str) -> str:
        """Generates baseline establishment query"""
        return f"""
        index={platform} earliest=-30d@d latest=now
        | bucket _time span=1h
        | stats avg({metric}) as avg_{metric}, 
                stdev({metric}) as std_{metric},
                p95({metric}) as p95_{metric} by _time
        | eventstats avg(avg_{metric}) as baseline_{metric}
        """
    
    def _generate_ioc_hunt_queries(self, ioc: str, ioc_type: str) -> List[str]:
        """Generates hunt queries for a specific IOC"""
        if ioc_type == 'ip':
            return [
                f'index=network src_ip="{ioc}" OR dest_ip="{ioc}"',
                f'index=proxy url="*{ioc}*"',
                f'index=dns query="{ioc}"'
            ]
        elif ioc_type == 'domain':
            return [
                f'index=dns query="*{ioc}*"',
                f'index=proxy url="*{ioc}*"',
                f'index=network dest_domain="{ioc}"'
            ]
        elif ioc_type == 'hash':
            return [
                f'index=endpoint hash="{ioc}"',
                f'index=file_hash hash="{ioc}"'
            ]
        else:
            return [f'index=* "{ioc}"']
    
    def _explain_query(self, spl_query: str, query_type: str) -> str:
        """Explains what the SPL query does"""
        explanations = {
            'lateral_movement': 'This query searches for suspicious login patterns that may indicate lateral movement, focusing on remote logons (types 3 and 10) and identifying accounts with unusual login frequency.',
            'credential_access': 'This query detects potential credential dumping by monitoring for processes accessing LSASS memory, which is a common technique for extracting credentials.',
            'persistence': 'This query looks for persistence mechanisms including registry Run keys and scheduled tasks, which are common ways adversaries maintain access.',
            'process_injection': 'This query identifies process injection attempts by monitoring cross-process memory operations, particularly targeting system processes.',
            'command_and_control': 'This query searches for potential C2 communication by analyzing network traffic patterns and suspicious domains.',
            'general_hunting': 'This is a general hunting query that searches for specified indicators across multiple data sources.'
        }
        
        return explanations.get(query_type, 'This query searches for suspicious activity based on the provided criteria.')
    
    def _get_related_techniques(self, query_type: str) -> List[str]:
        """Gets related MITRE ATT&CK techniques"""
        technique_mapping = {
            'lateral_movement': ['T1021.001', 'T1021.002', 'T1075', 'T1097'],
            'credential_access': ['T1003.001', 'T1003.002', 'T1558', 'T1110'],
            'persistence': ['T1547.001', 'T1053', 'T1543', 'T1547'],
            'process_injection': ['T1055.001', 'T1055.002', 'T1055.003', 'T1055.004'],
            'command_and_control': ['T1071.001', 'T1071.004', 'T1573', 'T1008'],
            'discovery': ['T1083', 'T1057', 'T1018', 'T1135']
        }
        
        return technique_mapping.get(query_type, [])
    
    def _get_technique_explanation(self, technique_id: str) -> Dict:
        """Gets explanation for a MITRE technique"""
        # Mock data - in production, this would query the MITRE database
        explanations = {
            'T1055': {
                'name': 'Process Injection',
                'description': 'Adversaries may inject code into processes to evade process-based defenses.',
                'tactic': 'Defense Evasion',
                'detection': 'Monitor for suspicious cross-process memory operations'
            },
            'T1003.001': {
                'name': 'LSASS Memory',
                'description': 'Adversaries may attempt to access credential material stored in LSASS memory.',
                'tactic': 'Credential Access',
                'detection': 'Monitor for processes accessing lsass.exe'
            }
        }
        
        return explanations.get(technique_id, {
            'name': 'Unknown Technique',
            'description': f'No information available for {technique_id}',
            'tactic': 'Unknown',
            'detection': 'No detection guidance available'
        })
    
    def _determine_ioc_type(self, ioc: str) -> str:
        """Determines the type of an IOC"""
        if re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', ioc):
            return 'ip'
        elif re.match(r'^[a-f0-9]{32}$', ioc, re.IGNORECASE):
            return 'hash'
        elif re.match(r'^[a-f0-9]{64}$', ioc, re.IGNORECASE):
            return 'hash'
        elif '.' in ioc and not ioc.replace('.', '').isdigit():
            return 'domain'
        else:
            return 'unknown'
    
    def _get_pyramid_level(self, ioc_type: str) -> str:
        """Gets Pyramid of Pain level for IOC type"""
        mapping = {
            'hash': 'hash_values',
            'ip': 'ip_addresses', 
            'domain': 'domain_names',
            'url': 'network_artifacts'
        }
        return mapping.get(ioc_type, 'unknown')
    
    def _get_peak_methodology(self) -> Dict:
        """Returns PEAK methodology details"""
        return {
            'name': 'PEAK (Prepare, Execute, Act with Knowledge)',
            'phases': [
                'Prepare: Select topics, conduct research, understand data',
                'Execute: Dive deep into analysis, follow leads',
                'Act with Knowledge: Document findings, create detections'
            ],
            'hunt_types': [
                'Hypothesis-Driven: Test specific hypotheses',
                'Baseline: Establish normal patterns', 
                'Model-Assisted (M-ATH): Use ML for anomaly detection'
            ]
        }
    
    def _get_sqrrl_methodology(self) -> Dict:
        """Returns SQRRL methodology details"""
        return {
            'name': 'SQRRL Framework',
            'components': [
                'Hunting Maturity Model (HMM0-HMM4)',
                'Hunt Loop: Hypothesis → Investigate → Patterns → Analytics',
                'Hunt Matrix: Activities mapped to maturity levels'
            ]
        }
    
    def _get_intelligence_methodology(self) -> Dict:
        """Returns Intelligence-Driven methodology details"""
        return {
            'name': 'Intelligence-Driven Methodology',
            'requirements': [
                'Adversary Understanding: Know threat actors and TTPs',
                'Telemetry and Data: Comprehensive visibility',
                'Business Impact Analysis: Understand crown jewels'
            ],
            'process': [
                'Formulate specific, testable hypotheses',
                'Translate to technical queries',
                'Evaluate results rigorously',
                'Iterate and refine',
                'Transition to automated detections'
            ]
        }
    
    def _load_security_patterns(self) -> Dict:
        """Loads security-specific regex patterns"""
        return {
            'techniques': [
                {'regex': r'\bT\d{4}(?:\.\d{3})?\b'},
            ],
            'iocs': [
                {'regex': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'},  # IP addresses
                {'regex': r'\b[a-f0-9]{32}\b'},  # MD5
                {'regex': r'\b[a-f0-9]{64}\b'},  # SHA256
                {'regex': r'\bhttps?://[^\s<>"\']+'},  # URLs
            ],
            'timeframes': [
                {'regex': r'\blast\s+(\d+)\s+(hours?|days?|weeks?|months?)\b'},
                {'regex': r'\bpast\s+(\d+)\s+(hours?|days?|weeks?|months?)\b'},
                {'regex': r'\b(\d+)\s+(hours?|days?|weeks?|months?)\s+ago\b'},
            ]
        }
    
    def _load_intent_keywords(self) -> Dict:
        """Loads intent classification keywords"""
        return {
            'generate_query': ['find', 'search', 'hunt', 'look for', 'detect', 'identify'],
            'explain_technique': ['explain', 'describe', 'what is', 'tell me about'],
            'analyze_ioc': ['analyze', 'investigate', 'check', 'lookup'],
            'hunt_methodology': ['methodology', 'framework', 'approach', 'peak', 'sqrrl'],
            'baseline_analysis': ['baseline', 'normal', 'establish', 'average'],
            'anomaly_detection': ['anomaly', 'outlier', 'unusual', 'abnormal', 'suspicious']
        }