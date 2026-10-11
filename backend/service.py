"""
Analysis service.

1. The deterministic local analyzer always runs and decides score and level.
2. If Bedrock is enabled (and the caller wants it), the model adds a
   plain-language explanation. Any failure leaves the local result untouched.
"""

from __future__ import annotations

import logging

from backend.analyzer import analyze_message
from backend.bedrock_explainer import BedrockExplainer
from backend.config import Settings

logger = logging.getLogger("echoshield.service")


class AnalysisService:
    def __init__(self, settings: Settings, explainer: BedrockExplainer | None = None):
        self.settings = settings
        # No explainer object (and so no boto3 import or client) when Bedrock is off.
        self.explainer = explainer if explainer is not None else (
            BedrockExplainer(settings) if settings.use_bedrock else None
        )

    def startup(self) -> None:
        if self.settings.use_bedrock and self.explainer is not None:
            self.explainer.init()

    def analyze(self, message: str, use_ai: bool = True) -> dict:
        result = analyze_message(message)
        result.update(analysis_source="local", ai_status="disabled", ai_notice=None, ai_explanation=None)

        if not self.settings.use_bedrock or self.explainer is None:
            return result
        if not use_ai:
            result["ai_status"] = "skipped"
            return result

        try:
            outcome = self.explainer.explain(message, result)
        except Exception:  # noqa: BLE001 - defensive: the local result must always be returned
            logger.exception("Unexpected error in AI explanation layer")
            result.update(ai_status="unavailable",
                          ai_notice="AI explanation is temporarily unavailable. Showing the local analysis.")
            return result

        result["ai_status"] = outcome.status
        result["ai_notice"] = outcome.notice
        if outcome.explanation is not None:
            result["ai_explanation"] = outcome.explanation.model_dump()
            result["analysis_source"] = "local+bedrock"
        return result
