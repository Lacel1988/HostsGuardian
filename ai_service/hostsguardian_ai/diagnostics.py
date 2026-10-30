from datetime import datetime, timezone
from typing import Protocol

from .schemas import Evidence, Outcome, ToolName, ToolResult


class DiagnosticTools(Protocol):
    """v1: four named, read-only operations; no URLs, SQL, shell or write arguments."""
    async def read(self, tool: ToolName) -> ToolResult: ...


class MockDiagnostics:
    async def read(self, tool: ToolName) -> ToolResult:
        observations = {
            ToolName.ENGINE: "Fixture Engine reports available; production availability is unknown.",
            ToolName.POLICY: "Fixture policy revision is 7; production policy is unknown.",
            ToolName.DEVICE: "Fixture IPv4 identity observed; IPv6 enforcement is unknown.",
            ToolName.ACTIVITY: "Fixture activity contains 3 blocked and 5 allowed queries.",
        }
        return ToolResult(tool=tool, outcome=Outcome.SUCCESS, evidence=(Evidence(
            evidence_id=f"fixture:{tool.value}", source_component="mock-diagnostics",
            timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
            observation=observations[tool], verification="fixture",
            policy_revision=7 if tool == ToolName.POLICY else None,
            source_reference=f"fixture://gate1/{tool.value}",
            limitation="Deterministic fixture; never production evidence.",
        ),))
