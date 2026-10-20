"""Common interface every engine ingestor implements.

An ingestor follows a fetch/parse/normalize shape and produces facts
(FactNode/FactEdge) for the rule engine's per-run property graph.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, ClassVar

from kresheen.models.facts import FactEdge, FactNode


class SourceIngestor(ABC):
    source_type: ClassVar[str]

    @abstractmethod
    def fetch(self, **kwargs) -> Any:
        """Pull raw data: read an uploaded file, load the source's saved
        connection_details."""

    @abstractmethod
    def parse(self, raw: Any) -> list[dict]:
        """Turn raw source data into a list of source-native records."""

    @abstractmethod
    def normalize(
        self, records: list[dict], *, run_id: str, application_id: str
    ) -> tuple[list[FactNode], list[FactEdge]]:
        """Map source-native records to the one canonical FactNode/FactEdge
        shape, regardless of how different the raw source formats are (see
        engine/facts/graph.py)."""

    def run(
        self, *, run_id: str, application_id: str, **kwargs
    ) -> tuple[list[FactNode], list[FactEdge]]:
        raw = self.fetch(**kwargs)
        records = self.parse(raw)
        return self.normalize(records, run_id=run_id, application_id=application_id)
