import json

import pytest
from botocore.exceptions import ClientError
from fastapi.testclient import TestClient

from backend.bedrock_explainer import BedrockExplainer
from backend.config import load_settings
from backend.main import create_app
from backend.service import AnalysisService

SECRET_BITS = ("arn:aws:iam::123456789012:user/secret-user", "FAKE-ACCESS-KEY-ID-NOT-REAL", "123456789012")


def make_settings(**env):
    base = {"USE_BEDROCK": "false"}
    base.update({k: str(v) for k, v in env.items()})
    return load_settings(base, load_env_file=False)


def client_error(code, message=None):
    msg = message or f"User {SECRET_BITS[0]} is not authorized (key {SECRET_BITS[1]}, account {SECRET_BITS[2]})"
    return ClientError({"Error": {"Code": code, "Message": msg}}, "Converse")


def model_reply(payload):
    text = payload if isinstance(payload, str) else json.dumps(payload)
    return {"output": {"message": {"role": "assistant", "content": [{"text": text}]}},
            "usage": {"inputTokens": 10, "outputTokens": 10}}


class FakeBedrock:
    """Stands in for the boto3 bedrock-runtime client. Never touches the network."""

    def __init__(self, reply=None, error=None):
        self.reply, self.error, self.calls = reply, error, []

    def converse(self, **kwargs):
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error
        return self.reply


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


@pytest.fixture
def local_client():
    return TestClient(create_app(make_settings()))


@pytest.fixture
def bedrock_env():
    """Build a TestClient with Bedrock enabled and a fake AWS client."""

    def build(fake, clock=None, **env):
        settings = make_settings(USE_BEDROCK="true", **env)
        explainer = BedrockExplainer(settings, client_factory=lambda _s: fake, clock=clock or Clock())
        service = AnalysisService(settings, explainer)
        return TestClient(create_app(settings, service)), service, explainer

    return build
