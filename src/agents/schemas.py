"""Pydantic schemas for agent input/output."""

from pydantic import BaseModel, Field


class AlertInput(BaseModel):
    """A SOC alert to be triaged."""

    alert_id: str
    rule_name: str
    rule_id: str = ""
    sigma_level: str = "medium"
    description: str = ""
    matched_event: dict = Field(default_factory=dict)
    techniques: list[str] = Field(default_factory=list)


class TriageDecision(BaseModel):
    """Agent's triage decision for a single alert."""

    alert_id: str
    label: str = Field(description="'malicious' or 'benign'")
    confidence: float = Field(ge=0.0, le=1.0, description="0-1 confidence score")
    severity: str | None = Field(
        default=None,
        description="'critical', 'high', 'medium', 'low' — only if malicious",
    )
    techniques: list[str] = Field(
        default_factory=list,
        description="MITRE ATT&CK technique IDs (e.g. T1053.005)",
    )
    reasoning: str = Field(description="Brief explanation of the decision")
    recommended_action: str = Field(
        description="What the SOC analyst should do next",
    )
