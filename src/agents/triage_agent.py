"""LangGraph SOC alert triage agent.

Takes a SOC alert and produces a triage decision:
label (malicious/benign), severity, MITRE ATT&CK mapping, and recommended action.
"""

import json
import logging
import os
from typing import Annotated, TypedDict

from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, SystemMessage
from langgraph.graph import END, StateGraph
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode

from src.agents.schemas import AlertInput, TriageDecision
from src.agents.tools import TRIAGE_TOOLS

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = (
    """You are an expert SOC analyst AI assistant. Your job is to triage security alerts.

For each alert you receive, you must:
1. Analyse the alert's Sigma rule name, description, level, and matched event fields.
2. Use the analyse_event_fields tool to inspect the raw event for suspicious indicators.
3. If MITRE ATT&CK techniques are listed, use lookup_technique to understand the threat.
4. Make a triage decision.

Your decision MUST be valid JSON with these exact fields:
{
  "alert_id": "<the alert ID>",
  "label": "malicious" or "benign",
  "confidence": <float 0-1>,
  "severity": "critical", "high", "medium", "low", or null (null if benign),
  "techniques": ["T1234.001", ...],
  "reasoning": "<brief explanation>",
  "recommended_action": "<what the analyst should do>"
}

Guidelines:
- A Sigma rule hit does NOT automatically mean the alert is malicious. Many hits are on
  normal system activity (false positives). Examine the actual event fields carefully.
- Look at: the process name, command line, parent process, user context, EventID.
- System processes (svchost.exe, services.exe, explorer.exe, etc.) doing normal operations
  are usually benign even if a Sigma rule fires.
- Suspicious indicators: encoded commands, unusual process trees, LOLBins with unusual args,
  SYSTEM-level execution of user tools, network connections to unusual ports.
- For malicious alerts, assign severity based on the tactic:
  - critical: Credential Access, Impact, Exploitation
  - high: Persistence, Privilege Escalation, Lateral Movement, Exfiltration
  - medium: Execution, Defense Evasion, Collection, C2, Initial Access
  - low: Discovery, Reconnaissance
- Be concise in reasoning (1-2 sentences).
- Recommended action should be specific and actionable.

Respond ONLY with the JSON decision after using the tools. No other text."""
)


class AgentState(TypedDict):
    """State passed through the triage graph."""

    messages: Annotated[list[BaseMessage], add_messages]
    alert: dict
    decision: TriageDecision | None


def _build_alert_prompt(alert: dict) -> str:
    """Format an alert into a prompt for the agent."""
    event_str = json.dumps(alert.get("matched_event", {}), indent=2, default=str)
    # Truncate very long events
    if len(event_str) > 3000:
        event_str = event_str[:3000] + "\n... (truncated)"

    return f"""Triage this SOC alert:

Alert ID: {alert['alert_id']}
Rule Name: {alert['rule_name']}
Sigma Level: {alert.get('sigma_level', 'unknown')}
Description: {alert.get('description', 'N/A')}
MITRE Techniques: {', '.join(alert.get('techniques', [])) or 'none listed'}

Matched Event (raw):
{event_str}

Use the tools to analyse this alert, then provide your triage decision as JSON."""


def _get_llm(model_name: str | None = None):
    """Get the LLM instance with retry logic for transient failures."""
    from langchain_google_genai import ChatGoogleGenerativeAI

    return ChatGoogleGenerativeAI(
        model=model_name or os.getenv("GEMINI_MODEL", "gemini-3.8-flash"),
        google_api_key=os.getenv("GEMINI_API_KEY"),
        temperature=0.0,
        max_retries=3,
    )


def _parse_decision(text: str, alert_id: str) -> TriageDecision:
    """Parse the agent's text response into a TriageDecision."""
    # Try to extract JSON from the response
    text = text.strip()
    # Handle markdown code blocks
    if "```json" in text:
        text = text.split("```json")[1].split("```")[0].strip()
    elif "```" in text:
        text = text.split("```")[1].split("```")[0].strip()

    try:
        data = json.loads(text)
        # Ensure alert_id matches
        data["alert_id"] = alert_id
        # Normalize label
        data["label"] = data.get("label", "benign").lower().strip()
        if data["label"] not in ("malicious", "benign"):
            data["label"] = "benign"
        # Null severity for benign
        if data["label"] == "benign":
            data["severity"] = None
        return TriageDecision(**data)
    except (json.JSONDecodeError, KeyError, ValueError):
        # Fallback: try to infer from text
        label = "malicious" if "malicious" in text.lower() else "benign"
        return TriageDecision(
            alert_id=alert_id,
            label=label,
            confidence=0.3,
            severity="medium" if label == "malicious" else None,
            techniques=[],
            reasoning="Failed to parse structured response; inferred from text.",
            recommended_action="Manual review required — agent response was unparseable.",
        )


def build_triage_graph(llm=None):
    """Build the LangGraph triage workflow.

    Args:
        llm: Optional LLM instance. If None, uses Gemini from env.
    """
    if llm is None:
        llm = _get_llm()

    llm_with_tools = llm.bind_tools(TRIAGE_TOOLS)

    tool_node = ToolNode(TRIAGE_TOOLS)

    def call_model(state: AgentState) -> dict:
        """Invoke the LLM with current messages."""
        response = llm_with_tools.invoke(state["messages"])
        return {"messages": [response]}

    def should_use_tools(state: AgentState) -> str:
        """Route to tools if the LLM requested a tool call, else to parse."""
        last_msg = state["messages"][-1]
        if isinstance(last_msg, AIMessage) and last_msg.tool_calls:
            return "tools"
        return "parse"

    def parse_decision(state: AgentState) -> dict:
        """Parse the final LLM response into a TriageDecision."""
        last_msg = state["messages"][-1]
        content = last_msg.content
        if isinstance(content, list):
            # Gemini returns list of content blocks; extract text
            text = " ".join(
                block.get("text", "") for block in content
                if isinstance(block, dict)
            )
        else:
            text = str(content)
        decision = _parse_decision(text, state["alert"]["alert_id"])
        return {"decision": decision}

    graph = StateGraph(AgentState)

    graph.add_node("agent", call_model)
    graph.add_node("tools", tool_node)
    graph.add_node("parse", parse_decision)

    graph.set_entry_point("agent")
    graph.add_conditional_edges("agent", should_use_tools, {"tools": "tools", "parse": "parse"})
    graph.add_edge("tools", "agent")
    graph.add_edge("parse", END)

    return graph.compile()


def triage_alert(alert: dict | AlertInput, llm=None) -> TriageDecision:
    """Triage a single alert. Main entry point.

    Args:
        alert: Alert dict or AlertInput instance.
        llm: Optional LLM to use (for testing).

    Returns:
        TriageDecision with label, severity, reasoning, etc.
    """
    if isinstance(alert, AlertInput):
        alert_dict = alert.model_dump()
    else:
        alert_dict = alert

    alert_id = alert_dict.get("alert_id", "unknown")
    logger.info("Triaging alert %s: %s", alert_id, alert_dict.get("rule_name", ""))

    graph = build_triage_graph(llm=llm)

    initial_state: AgentState = {
        "messages": [
            SystemMessage(content=SYSTEM_PROMPT),
            HumanMessage(content=_build_alert_prompt(alert_dict)),
        ],
        "alert": alert_dict,
        "decision": None,
    }

    result = graph.invoke(initial_state)
    decision = result["decision"]
    logger.info(
        "Triage result for %s: label=%s severity=%s confidence=%.2f",
        alert_id, decision.label, decision.severity, decision.confidence,
    )
    return decision
