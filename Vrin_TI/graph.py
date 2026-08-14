"""Threat graph abstraction; database implementation can later be replaced by Neo4j."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List

from .correlation.relationship_engine import RelationshipEngine


class ThreatGraph(ABC):
    @abstractmethod
    def neighbors(self, ref: str) -> List[Dict[str, Any]]: ...

    @abstractmethod
    def traverse(self, ref: str, max_depth: int = 3) -> Dict[str, Any]: ...


class SQLiteThreatGraph(ThreatGraph):
    def __init__(self, relationship_engine: RelationshipEngine):
        self.engine = relationship_engine

    def neighbors(self, ref: str) -> List[Dict[str, Any]]:
        return self.engine.neighbors(ref)

    def traverse(self, ref: str, max_depth: int = 3) -> Dict[str, Any]:
        return self.engine.traverse(ref, max_depth=max_depth)
