"""
One-off Bedrock check. Makes exactly ONE small model call, prints a sanitized
result, and exits. Run it only after your AWS account is verified.

    python -m backend.check_bedrock
"""

from __future__ import annotations

import sys

from backend.analyzer import analyze_message
from backend.bedrock_explainer import NOTICES, BedrockExplainer
from backend.config import ConfigError, load_settings

SAMPLE = "Dear customer, your KYC expires today. Share your OTP now: http://bit.ly/kyc-update"


def main() -> int:
    try:
        settings = load_settings()
    except ConfigError as exc:
        print(f"Configuration problem: {exc}")
        return 2

    if not settings.use_bedrock:
        print("USE_BEDROCK is false, so nothing was called. Set USE_BEDROCK=true in .env to test Bedrock.")
        return 0

    print(f"Testing Bedrock once: profile={settings.aws_profile} region={settings.aws_region} "
          f"model={settings.bedrock_model_id}")
    analysis = analyze_message(SAMPLE)
    result = BedrockExplainer(settings).explain(SAMPLE, analysis)

    if result.explanation is not None:
        print("OK. The model answered and the output passed validation:")
        print(result.explanation.summary)
        return 0

    print("Bedrock could not be used:", result.notice or NOTICES["service_error"])
    print("The app still works with local analysis. Check the server log line 'Bedrock unavailable: kind=...'")
    return 1


if __name__ == "__main__":
    sys.exit(main())
