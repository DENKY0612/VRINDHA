"""Database-backed lightweight threat graph relationship engine."""
from __future__ import annotations

from collections import deque
from typing import Any, Dict, List, Set

from ..database import ThreatDatabase


class RelationshipEngine:
    def __init__(self, database: ThreatDatabase):
        self.database = database

    def neighbors(self, ref: str) -> List[Dict[str, Any]]:
        return self.database.relationships(ref=ref)

    def traverse(self, start: str, max_depth: int = 3, max_nodes: int = 500) -> Dict[str, Any]:
        max_depth = max(0, min(max_depth, 6))
        queue = deque([(start, 0)])
        visited: Set[str] = {start}
        edges: List[Dict[str, Any]] = []
        while queue and len(visited) < max_nodes:
            node, depth = queue.popleft()
            if depth >= max_depth:
                continue
            for edge in self.database.relationships(ref=node, limit=max_nodes):
                edges.append(edge)
                other = edge["target_ref"] if edge["source_ref"] == node else edge["source_ref"]
                if other not in visited:
                    visited.add(other)
                    queue.append((other, depth + 1))
        return {"start": start, "nodes": sorted(visited), "edges": edges, "depth": max_depth,
                "truncated": len(visited) >= max_nodes}

    def convergence(self, target_ref: str) -> Dict[str, Any]:
        edges = self.database.relationships(ref=target_ref)
        evidence_sources = {edge["source_ref"] for edge in edges if float(edge["confidence"]) >= 0.5}
        # This is evidence metadata, not a blind confidence mutation.
        return {"target_ref": target_ref, "independent_relationships": len(edges),
                "independent_sources": len(evidence_sources), "confidence_increase_allowed": len(evidence_sources) >= 2,
                "evidence": edges}
