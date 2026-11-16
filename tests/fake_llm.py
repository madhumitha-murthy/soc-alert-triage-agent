"""Fake LLM for deterministic testing without API calls."""

import json

from langchain_core.messages import AIMessage, BaseMessage


class FakeLLM:
    """A fake LLM that returns deterministic triage decisions.

    Classifies based on simple heuristics on the alert content,
    mimicking what the real LLM would do.
    """

    def __init__(self, default_label: str = "benign"):
        self.default_label = default_label
        self._bound_tools = []
        self._call_count = 0

    def bind_tools(self, tools: list) -> "FakeLLM":
        """Return self with tools stored (mimics LLM.bind_tools)."""
        clone = FakeLLM(self.default_label)
        clone._bound_tools = tools
        return clone

    def invoke(self, messages: list[BaseMessage], **kwargs) -> AIMessage:
        """Return a deterministic response based on alert content."""
        self._call_count += 1

        # On first call, return tool calls to analyse the event
        # On subsequent calls, return the decision
        last_msg = messages[-1]
        content = last_msg.content if hasattr(last_msg, "content") else str(last_msg)

        # If this is a tool result coming back, produce the final decision
        if self._call_count > 1 or "Process:" in content or "Technique" in content:
            return self._make_decision(messages)

        # First call: use analyse_event_fields tool
        if self._bound_tools:
            # Extract event from the prompt
            event_json = self._extract_event(content)
            if event_json:
                return AIMessage(
                    content="",
                    tool_calls=[{
                        "id": "call_001",
                        "name": "analyse_event_fields",
                        "args": {"event_json": event_json},
                    }],
                )

        return self._make_decision(messages)

    def _extract_event(self, content: str) -> str | None:
        """Try to extract event JSON from the prompt."""
        if "Matched Event (raw):" in content:
            parts = content.split("Matched Event (raw):")
            if len(parts) > 1:
                event_text = parts[1].strip()
                # Find the JSON block
                if event_text.startswith("{"):
                    # Find matching brace
                    depth = 0
                    for i, c in enumerate(event_text):
                        if c == "{":
                            depth += 1
                        elif c == "}":
                            depth -= 1
                            if depth == 0:
                                return event_text[: i + 1]
        return None

    def _make_decision(self, messages: list[BaseMessage]) -> AIMessage:
        """Produce a triage decision based on heuristics."""
        from langchain_core.messages import SystemMessage

        # Gather message content, skipping the system prompt (it contains
        # keywords like "credential", "persistence" that skew heuristics)
        full_text = " ".join(
            m.content if hasattr(m, "content") and isinstance(m.content, str) else ""
            for m in messages
            if not isinstance(m, SystemMessage)
        ).lower()

        # Heuristic classification
        suspicious_indicators = [
            "powershell", "mimikatz", "empire", "invoke-",
            "encodedcommand", "-enc", "base64",
            "credential", "lsass", "sam_access", "dcsync",
            "schtasks", "scheduled task",
            "persistence", "privilege escalation",
            "lateral movement", "smbexec",
            "uac", "fodhelper",
            "commonly abused", "obfuscation",
            "hidden execution",
        ]

        benign_indicators = [
            "known windows system process",
            "likely benign",
            "wfp bind allowed",
            "wfp connection allowed",
            "normal system",
            "guestagent",
            "windowsazure",
        ]

        alert_id = "ALERT-0000"
        for m in messages:
            c = m.content if hasattr(m, "content") and isinstance(m.content, str) else ""
            if "Alert ID:" in c:
                try:
                    alert_id = c.split("Alert ID:")[1].split("\n")[0].strip()
                except IndexError:
                    pass

        suspicious_score = sum(1 for ind in suspicious_indicators if ind in full_text)
        benign_score = sum(1 for ind in benign_indicators if ind in full_text)

        if suspicious_score > benign_score and suspicious_score >= 2:
            label = "malicious"
            severity = "high" if suspicious_score >= 4 else "medium"
            if any(k in full_text for k in ["credential", "lsass", "dcsync", "critical"]):
                severity = "critical"
            elif any(k in full_text for k in ["discovery", "reconnaissance"]):
                severity = "low"
            confidence = min(0.5 + suspicious_score * 0.1, 0.95)
            reasoning = "Suspicious indicators detected in event analysis."
            action = "Investigate the process tree and isolate the host if confirmed."
        else:
            label = "benign"
            severity = None
            confidence = min(0.5 + benign_score * 0.15, 0.95)
            reasoning = "Event appears to be normal system activity triggering a broad Sigma rule."
            action = "No action required — mark as false positive."

        decision = {
            "alert_id": alert_id,
            "label": label,
            "confidence": round(confidence, 2),
            "severity": severity,
            "techniques": [],
            "reasoning": reasoning,
            "recommended_action": action,
        }

        return AIMessage(content=json.dumps(decision))
