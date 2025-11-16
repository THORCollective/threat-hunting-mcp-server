"""Graph-based threat detection and correlation engine"""

import logging
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class EntityNode:
    """Represents an entity in the attack graph"""

    entity_id: str
    entity_type: str  # process, user, host, file, network_connection
    properties: Dict
    first_seen: datetime
    last_seen: datetime
    suspicious_score: float = 0.0


@dataclass
class RelationshipEdge:
    """Represents a relationship between entities"""

    source_id: str
    target_id: str
    relationship_type: str  # created, accessed, connected_to, executed
    timestamp: datetime
    properties: Dict


@dataclass
class AttackPath:
    """Represents a potential attack path through the graph"""

    path_id: str
    nodes: List[EntityNode]
    edges: List[RelationshipEdge]
    confidence: float
    kill_chain_stages: List[str]
    ttps: List[str]


class AttackGraph:
    """Graph structure for tracking attack progression"""

    def __init__(self):
        self.nodes: Dict[str, EntityNode] = {}
        self.edges: List[RelationshipEdge] = []
        self.adjacency: Dict[str, List[str]] = defaultdict(list)

    def add_entity_node(self, entity: EntityNode):
        """Adds an entity node to the graph"""
        self.nodes[entity.entity_id] = entity

    def add_relationship_edge(self, edge: RelationshipEdge):
        """Adds a relationship edge to the graph"""
        self.edges.append(edge)
        self.adjacency[edge.source_id].append(edge.target_id)

    def get_neighbors(self, entity_id: str) -> List[EntityNode]:
        """Gets neighboring entities"""
        neighbor_ids = self.adjacency.get(entity_id, [])
        return [self.nodes[nid] for nid in neighbor_ids if nid in self.nodes]

    def find_paths(self, start_id: str, end_id: str, max_depth: int = 10) -> List[List[str]]:
        """Finds all paths between two entities"""
        paths = []
        visited = set()

        def dfs(current: str, target: str, path: List[str], depth: int):
            if depth > max_depth:
                return

            if current == target:
                paths.append(path.copy())
                return

            visited.add(current)
            for neighbor in self.adjacency.get(current, []):
                if neighbor not in visited:
                    path.append(neighbor)
                    dfs(neighbor, target, path, depth + 1)
                    path.pop()
            visited.remove(current)

        dfs(start_id, end_id, [start_id], 0)
        return paths


class ProvenanceGraph:
    """Tracks data provenance and lineage"""

    def __init__(self):
        self.lineage: Dict[str, List[str]] = defaultdict(list)

    def add_provenance(self, entity_id: str, source_id: str):
        """Adds provenance tracking"""
        self.lineage[entity_id].append(source_id)

    def get_ancestry(self, entity_id: str) -> List[str]:
        """Gets complete ancestry of an entity"""
        ancestry = []
        to_visit = [entity_id]
        visited = set()

        while to_visit:
            current = to_visit.pop(0)
            if current in visited:
                continue

            visited.add(current)
            ancestry.append(current)
            to_visit.extend(self.lineage.get(current, []))

        return ancestry


class GraphCorrelationEngine:
    """Graph-based threat detection and correlation"""

    def __init__(self):
        self.provenance_tracker = ProvenanceGraph()
        self.lolbin_signatures = self._load_lolbin_signatures()
        self.suspicious_parent_child = self._load_suspicious_relationships()

    async def build_attack_graph(self, events: List[Dict]) -> AttackGraph:
        """Builds directed graph of attack progression"""
        graph = AttackGraph()

        # Create nodes for entities
        for event in events:
            entity = self._event_to_entity(event)
            if entity:
                graph.add_entity_node(entity)

        # Create relationship edges
        for event in events:
            edges = self._event_to_relationships(event)
            for edge in edges:
                graph.add_relationship_edge(edge)

        return graph

    async def detect_living_off_the_land(self, process_tree: Dict) -> List[Dict]:
        """Detects LOLBin abuse through graph analysis"""
        suspicious_patterns = []

        # Check for unusual parent-child relationships
        if self._is_suspicious_parent(process_tree):
            suspicious_patterns.append(
                {
                    "type": "unexpected_child_process",
                    "confidence": self._calculate_lol_confidence(process_tree),
                    "parent": process_tree.get("parent_process"),
                    "child": process_tree.get("process_name"),
                    "explanation": "Unusual parent-child process relationship detected",
                }
            )

        # Detect rapid sequential LOLBin execution
        if self._detect_lolbin_chain(process_tree):
            suspicious_patterns.append(
                {
                    "type": "lolbin_chain",
                    "confidence": 0.8,
                    "tools": self._extract_lolbin_sequence(process_tree),
                    "explanation": "Multiple living-off-the-land binaries executed in sequence",
                }
            )

        # Detect LOLBin with suspicious command line
        if self._has_suspicious_cmdline(process_tree):
            suspicious_patterns.append(
                {
                    "type": "suspicious_lolbin_cmdline",
                    "confidence": 0.7,
                    "process": process_tree.get("process_name"),
                    "cmdline": process_tree.get("command_line"),
                    "explanation": "LOLBin executed with suspicious command line arguments",
                }
            )

        return suspicious_patterns

    async def find_critical_paths(self, graph: AttackGraph, pivot_points: List[str]) -> List[AttackPath]:
        """Identifies critical attack paths through the graph"""
        critical_paths = []

        # Find paths from initial compromise to critical assets
        for pivot in pivot_points:
            if pivot not in graph.nodes:
                continue

            # Look for high-value targets
            for node_id, node in graph.nodes.items():
                if node.entity_type in ["domain_controller", "database", "admin_account"]:
                    paths = graph.find_paths(pivot, node_id)

                    for path_ids in paths:
                        attack_path = self._analyze_attack_path(graph, path_ids)
                        if attack_path.confidence > 0.6:
                            critical_paths.append(attack_path)

        return critical_paths

    async def identify_pivot_nodes(self, graph: AttackGraph) -> List[Dict]:
        """
        Identifies key pivot points using betweenness centrality
        Nodes with high betweenness are critical to attack progression
        """
        pivot_nodes = []

        # Calculate betweenness centrality
        centrality_scores = self._calculate_betweenness_centrality(graph)

        # Sort by centrality
        sorted_nodes = sorted(centrality_scores.items(), key=lambda x: x[1], reverse=True)

        # Top 10% are potential pivots
        top_count = max(1, len(sorted_nodes) // 10)
        for node_id, score in sorted_nodes[:top_count]:
            node = graph.nodes.get(node_id)
            if node:
                pivot_nodes.append(
                    {
                        "entity_id": node_id,
                        "entity_type": node.entity_type,
                        "centrality_score": score,
                        "properties": node.properties,
                        "explanation": "High betweenness centrality indicates critical pivot point",
                    }
                )

        return pivot_nodes

    def _event_to_entity(self, event: Dict) -> Optional[EntityNode]:
        """Converts an event to an entity node"""
        if "process_name" in event:
            return EntityNode(
                entity_id=event.get("process_guid", event.get("process_name")),
                entity_type="process",
                properties=event,
                first_seen=event.get("timestamp", datetime.utcnow()),
                last_seen=event.get("timestamp", datetime.utcnow()),
            )
        elif "user_name" in event:
            return EntityNode(
                entity_id=event.get("user_name"),
                entity_type="user",
                properties=event,
                first_seen=event.get("timestamp", datetime.utcnow()),
                last_seen=event.get("timestamp", datetime.utcnow()),
            )
        elif "host_name" in event:
            return EntityNode(
                entity_id=event.get("host_name"),
                entity_type="host",
                properties=event,
                first_seen=event.get("timestamp", datetime.utcnow()),
                last_seen=event.get("timestamp", datetime.utcnow()),
            )
        return None

    def _event_to_relationships(self, event: Dict) -> List[RelationshipEdge]:
        """Extracts relationships from an event"""
        edges = []

        # Process creation relationship
        if "parent_process" in event and "process_name" in event:
            edges.append(
                RelationshipEdge(
                    source_id=event.get("parent_process"),
                    target_id=event.get("process_guid", event.get("process_name")),
                    relationship_type="created",
                    timestamp=event.get("timestamp", datetime.utcnow()),
                    properties=event,
                )
            )

        # Network connection relationship
        if "source_ip" in event and "dest_ip" in event:
            edges.append(
                RelationshipEdge(
                    source_id=event.get("source_ip"),
                    target_id=event.get("dest_ip"),
                    relationship_type="connected_to",
                    timestamp=event.get("timestamp", datetime.utcnow()),
                    properties=event,
                )
            )

        return edges

    def _is_suspicious_parent(self, process_tree: Dict) -> bool:
        """Checks if parent-child relationship is suspicious"""
        parent = process_tree.get("parent_process", "").lower()
        child = process_tree.get("process_name", "").lower()

        # Check against known suspicious relationships
        for suspicious_pair in self.suspicious_parent_child:
            if suspicious_pair["parent"] in parent and suspicious_pair["child"] in child:
                return True

        return False

    def _detect_lolbin_chain(self, process_tree: Dict) -> bool:
        """Detects chained LOLBin execution"""
        children = process_tree.get("children", [])

        lolbin_count = 0
        for child in children:
            child_name = child.get("process_name", "").lower()
            if any(lolbin in child_name for lolbin in self.lolbin_signatures):
                lolbin_count += 1

        # 3+ LOLBins in sequence is suspicious
        return lolbin_count >= 3

    def _extract_lolbin_sequence(self, process_tree: Dict) -> List[str]:
        """Extracts sequence of LOLBins"""
        sequence = []
        children = process_tree.get("children", [])

        for child in children:
            child_name = child.get("process_name", "")
            if any(lolbin in child_name.lower() for lolbin in self.lolbin_signatures):
                sequence.append(child_name)

        return sequence

    def _has_suspicious_cmdline(self, process_tree: Dict) -> bool:
        """Checks for suspicious command line arguments"""
        cmdline = process_tree.get("command_line", "").lower()
        process_name = process_tree.get("process_name", "").lower()

        # PowerShell obfuscation indicators
        if "powershell" in process_name:
            suspicious_patterns = ["-enc", "-w hidden", "-nop", "downloadstring", "invoke-expression", "iex", "bypass"]
            return any(pattern in cmdline for pattern in suspicious_patterns)

        # WMIC suspicious usage
        if "wmic" in process_name:
            suspicious_patterns = ["process call create", "/node:", "shadowcopy"]
            return any(pattern in cmdline for pattern in suspicious_patterns)

        # Certutil abuse
        if "certutil" in process_name:
            suspicious_patterns = ["-decode", "-urlcache", "-split"]
            return any(pattern in cmdline for pattern in suspicious_patterns)

        return False

    def _calculate_lol_confidence(self, process_tree: Dict) -> float:
        """Calculates confidence score for LOLBin detection"""
        confidence = 0.5

        # Increase if multiple indicators
        if self._has_suspicious_cmdline(process_tree):
            confidence += 0.2

        if self._is_suspicious_parent(process_tree):
            confidence += 0.2

        # Decrease if common legitimate scenarios
        if process_tree.get("signed", False):
            confidence -= 0.1

        return min(1.0, max(0.0, confidence))

    def _analyze_attack_path(self, graph: AttackGraph, path_ids: List[str]) -> AttackPath:
        """Analyzes an attack path and maps to kill chain"""
        nodes = [graph.nodes[nid] for nid in path_ids if nid in graph.nodes]
        edges = []

        # Find edges connecting the path
        for i in range(len(path_ids) - 1):
            source = path_ids[i]
            target = path_ids[i + 1]
            matching_edges = [e for e in graph.edges if e.source_id == source and e.target_id == target]
            edges.extend(matching_edges)

        # Map to kill chain stages
        kill_chain_stages = self._map_to_kill_chain(nodes, edges)

        # Extract TTPs
        ttps = self._extract_ttps_from_path(nodes, edges)

        # Calculate confidence
        confidence = self._calculate_path_confidence(nodes, edges)

        return AttackPath(
            path_id=f"path_{hash(tuple(path_ids))}",
            nodes=nodes,
            edges=edges,
            confidence=confidence,
            kill_chain_stages=kill_chain_stages,
            ttps=ttps,
        )

    def _calculate_betweenness_centrality(self, graph: AttackGraph) -> Dict[str, float]:
        """
        Calculates betweenness centrality for all nodes
        Simple implementation - in production use NetworkX
        """
        centrality = defaultdict(float)

        # For each pair of nodes, find shortest paths
        node_ids = list(graph.nodes.keys())
        for i, start in enumerate(node_ids):
            for end in node_ids[i + 1 :]:
                paths = graph.find_paths(start, end, max_depth=5)

                # Count how many times each node appears in paths
                for path in paths:
                    for node_id in path[1:-1]:  # Exclude start and end
                        centrality[node_id] += 1.0 / len(paths)

        return dict(centrality)

    def _map_to_kill_chain(self, nodes: List[EntityNode], edges: List[RelationshipEdge]) -> List[str]:
        """Maps attack path to cyber kill chain stages"""
        stages = []

        # Analyze node types and relationships to infer stages
        for node in nodes:
            if node.entity_type == "external_connection":
                stages.append("delivery")
            elif node.entity_type == "process" and "exploit" in str(node.properties):
                stages.append("exploitation")
            elif node.entity_type == "persistence_mechanism":
                stages.append("installation")
            elif node.entity_type == "c2_connection":
                stages.append("command_and_control")

        return list(set(stages))

    def _extract_ttps_from_path(self, nodes: List[EntityNode], edges: List[RelationshipEdge]) -> List[str]:
        """Extracts MITRE ATT&CK TTPs from attack path"""
        ttps = []

        # Analyze patterns to infer TTPs
        for edge in edges:
            if edge.relationship_type == "lateral_movement":
                ttps.append("T1021")  # Remote Services
            elif edge.relationship_type == "credential_access":
                ttps.append("T1003")  # Credential Dumping

        return list(set(ttps))

    def _calculate_path_confidence(self, nodes: List[EntityNode], edges: List[RelationshipEdge]) -> float:
        """Calculates confidence in attack path"""
        if not nodes:
            return 0.0

        # Average suspicious scores of nodes
        avg_score = sum(n.suspicious_score for n in nodes) / len(nodes)

        # Bonus for longer paths (more evidence)
        length_bonus = min(0.2, len(nodes) * 0.02)

        return min(1.0, avg_score + length_bonus)

    def _load_lolbin_signatures(self) -> List[str]:
        """Loads Living-off-the-Land binary signatures"""
        return [
            "powershell",
            "cmd",
            "wmic",
            "certutil",
            "bitsadmin",
            "mshta",
            "regsvr32",
            "rundll32",
            "msiexec",
            "wscript",
            "cscript",
            "installutil",
            "regasm",
            "regsvcs",
            "msxsl",
        ]

    def _load_suspicious_relationships(self) -> List[Dict]:
        """Loads suspicious parent-child process relationships"""
        return [
            {"parent": "winword", "child": "powershell"},
            {"parent": "excel", "child": "powershell"},
            {"parent": "outlook", "child": "powershell"},
            {"parent": "winword", "child": "cmd"},
            {"parent": "excel", "child": "wmic"},
            {"parent": "adobe", "child": "powershell"},
            {"parent": "explorer", "child": "wscript"},
        ]
