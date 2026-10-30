import asyncio
import os
from typing import TypedDict

# LangGraph transitively installs the LangSmith SDK. Ambient tracing settings must
# never turn this local-only service into a cloud client.
os.environ["LANGSMITH_TRACING"] = "false"
os.environ["LANGCHAIN_TRACING_V2"] = "false"
os.environ["LANGCHAIN_TRACING"] = "false"

from langgraph.graph import END, START, StateGraph

from .config import Settings
from .diagnostics import DiagnosticTools
from .schemas import (Evidence, Finding, InvestigationResponse, Outcome, ToolName, ToolResult)


class State(TypedDict, total=False):
    query: str
    selected: tuple[ToolName, ...]
    results: list[ToolResult]
    calls: int
    retries: int
    response: InvestigationResponse


def build_workflow(settings: Settings, tools: DiagnosticTools):
    def accept(state: State):
        query = state["query"].strip().lower()
        commands = {tool.value: (tool,) for tool in ToolName}
        commands["overview"] = tuple(ToolName)
        return {"selected": commands.get(query, ()), "calls": 0, "retries": 0}

    async def collect(state: State):
        results, calls, retries = [], 0, 0
        for tool in state["selected"]:
            if calls >= settings.max_tool_calls:
                break
            while calls < settings.max_tool_calls:
                calls += 1
                try:
                    raw = await asyncio.wait_for(tools.read(tool), timeout=settings.request_timeout)
                    result = ToolResult.model_validate(raw)
                    if result.tool != tool:
                        raise ValueError("Mismatched tool result")
                except TimeoutError:
                    result = ToolResult(tool=tool, outcome=Outcome.TIMEOUT, limitation="Diagnostic deadline exceeded")
                except Exception:
                    # Never echo an exception, tool body or credentials into errors/logs.
                    result = ToolResult(tool=tool, outcome=Outcome.INVALID, limitation="Invalid diagnostic response")
                if result.outcome not in (Outcome.TIMEOUT, Outcome.UNAVAILABLE) or retries >= settings.max_retry_rounds or calls >= settings.max_tool_calls:
                    break
                retries += 1
            results.append(result)
        return {"results": results, "calls": calls, "retries": retries}

    def respond(state: State):
        selected = state["selected"]
        results = state.get("results", [])
        evidence: list[Evidence] = []
        verified = []
        unknowns = []
        seen = set()
        for result in results:
            if result.outcome != Outcome.SUCCESS:
                unknowns.append(f"{result.tool.value}: {result.outcome.value}")
            for item in result.evidence:
                if item.evidence_id in seen:
                    unknowns.append("Duplicate evidence rejected")
                    continue
                seen.add(item.evidence_id)
                evidence.append(item)
                if result.outcome == Outcome.SUCCESS and item.verification == "verified":
                    verified.append(Finding(observation=item.observation, evidence_ids=(item.evidence_id,)))
                else:
                    unknowns.append(f"{item.evidence_id}: {item.verification}; production conclusion unavailable")
        if len(results) < len(selected):
            unknowns.append("Tool-call budget exhausted; remaining diagnostics were not executed")
        if not selected:
            unknowns.append("Unsupported or ambiguous command")
        return {"response": InvestigationResponse(
            route="diagnostic" if selected else "unsupported", evidence=tuple(evidence),
            verified_findings=tuple(verified), unknowns=tuple(unknowns),
            recommended_next_steps=("Use an explicit command: overview, " + ", ".join(t.value for t in ToolName),)
            if not selected else ("Validate against authenticated Engine readback in a future authorized integration.",),
            tool_calls=state["calls"], retry_rounds=state["retries"],
        )}

    graph = StateGraph(State)
    graph.add_node("accept", accept)
    graph.add_node("collect", collect)
    graph.add_node("respond", respond)
    graph.add_edge(START, "accept")
    graph.add_conditional_edges("accept", lambda state: "collect" if state["selected"] else "respond")
    graph.add_edge("collect", "respond")
    graph.add_edge("respond", END)
    return graph.compile()


def build_adaptive_workflow(settings, tools, retrieval, provider):
    """Gate 3 extension; preserve the original v1 fixture command workflow."""
    from .orchestration import Analyst
    return Analyst(settings, tools, retrieval, provider)
