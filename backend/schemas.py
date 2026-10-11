"""Pydantic request / response models (the public API contract)."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from backend.config import MAX_MESSAGE_CHARS, MIN_MESSAGE_CHARS

RiskLevel = Literal["NONE", "LOW", "MEDIUM", "HIGH"]
Severity = Literal["high", "medium", "low"]


class AnalyzeRequest(BaseModel):
    # Whitespace is stripped before length validation, so "   " is rejected.
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    message: str = Field(
        ...,
        min_length=MIN_MESSAGE_CHARS,
        max_length=MAX_MESSAGE_CHARS,
        description="The SMS / WhatsApp / email text to analyze (treated as untrusted data).",
        examples=["Dear customer, your KYC will expire today. Share your OTP now."],
    )
    use_ai: bool = Field(
        True,
        description="Ask for the optional AI explanation. Ignored unless Bedrock is enabled on the server.",
    )

    @field_validator("message")
    @classmethod
    def _no_nul(cls, v: str) -> str:
        return v.replace("\x00", "")


class IndicatorDetail(BaseModel):
    name: str
    evidence: str
    severity: Severity  # high = strong evidence, medium = supporting, low = weak signal


class IndicatorNote(BaseModel):
    name: str
    why_it_matters: str


class AIExplanation(BaseModel):
    """Plain-language explanation written by the model. It never changes the score."""

    summary: str
    indicator_notes: list[IndicatorNote] = []
    provider: str = "Amazon Bedrock"


class AnalyzeResponse(BaseModel):
    risk_level: RiskLevel
    risk_score: int = Field(..., ge=0, le=100)
    summary: str
    threat_type: str
    indicators: list[str]
    indicator_details: list[IndicatorDetail]
    recommendations: list[str]
    urls_found: list[str]
    spoken_summary: str
    analysis_source: Literal["local", "local+bedrock"]
    ai_status: Literal["disabled", "skipped", "used", "unavailable"]
    ai_notice: str | None = None
    ai_explanation: AIExplanation | None = None
    disclaimer: str


class BedrockHealth(BaseModel):
    enabled: bool
    status: Literal["disabled", "configured", "cooldown"]
    last_error: str | None = None


class HealthResponse(BaseModel):
    status: Literal["ok"]
    version: str
    mode: Literal["local", "local+bedrock"]
    bedrock: BedrockHealth
