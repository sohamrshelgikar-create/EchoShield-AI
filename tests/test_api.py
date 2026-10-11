import json

import boto3
import pytest
from fastapi.testclient import TestClient

from backend.main import create_app
from backend.schemas import AnalyzeResponse
from backend.service import AnalysisService
from tests.conftest import make_settings

GOOD = "Dear customer, your SBI KYC expires today. Share your OTP now: http://bit.ly/sbi-kyc"


def test_health_is_minimal_and_has_no_secrets(local_client):
    r = local_client.get("/api/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok" and body["mode"] == "local"
    assert body["bedrock"] == {"enabled": False, "status": "disabled", "last_error": None}
    text = json.dumps(body).lower()
    for word in ("echoshield\"", "profile", "region", "key", "secret", "arn:", "nova"):
        assert word not in text.replace('"echoshield ai"', "")


def test_root(local_client):
    assert local_client.get("/").json()["status"] == "running"


def test_analyze_valid_request_matches_response_schema(local_client):
    r = local_client.post("/api/analyze", json={"message": GOOD})
    assert r.status_code == 200
    data = AnalyzeResponse.model_validate(r.json())
    assert data.risk_level == "HIGH" and 0 <= data.risk_score <= 100
    assert data.analysis_source == "local" and data.ai_status == "disabled"
    assert data.ai_explanation is None and data.disclaimer
    assert data.urls_found == ["http://bit.ly/sbi-kyc"]


def test_schema_is_identical_for_scam_and_benign(local_client):
    a = local_client.post("/api/analyze", json={"message": GOOD}).json()
    b = local_client.post("/api/analyze", json={"message": "See you at lunch tomorrow"}).json()
    assert set(a) == set(b)


@pytest.mark.parametrize("payload,expect", [
    ({"message": ""}, "at least 3"),
    ({"message": "   "}, "at least 3"),
    ({"message": "ab"}, "at least 3"),
    ({"message": "x" * 5001}, "at most 5000"),
    ({}, "required"),
    ({"message": 123}, "text"),
    ({"message": None}, "text"),
    ({"message": "hello there", "use_ai": "banana"}, "use_ai"),
    ({"message": "hello there", "surprise": 1}, "Unexpected field"),
])
def test_invalid_inputs_return_422_with_friendly_detail(local_client, payload, expect):
    r = local_client.post("/api/analyze", json=payload)
    assert r.status_code == 422
    assert expect in r.json()["detail"]


def test_boundary_lengths_accepted(local_client):
    assert local_client.post("/api/analyze", json={"message": "abc"}).status_code == 200
    assert local_client.post("/api/analyze", json={"message": "a" * 5000}).status_code == 200


def test_malformed_json_returns_422(local_client):
    r = local_client.post("/api/analyze", content="{not json", headers={"Content-Type": "application/json"})
    assert r.status_code == 422 and "valid JSON" in r.json()["detail"]


def test_validation_errors_do_not_echo_the_submitted_text(local_client):
    secret = "my-private-text-" + "x" * 5100
    r = local_client.post("/api/analyze", json={"message": secret})
    assert "my-private-text" not in r.text


def test_oversized_body_rejected_with_413(local_client):
    r = local_client.post("/api/analyze", json={"message": "a" * 200_000})
    assert r.status_code == 413 and r.json()["detail"] == "Request is too large."


def test_oversized_chunked_body_rejected_without_content_length(local_client):
    def chunks():
        for _ in range(50):
            yield b"a" * 2000
    r = local_client.post("/api/analyze", content=chunks(), headers={"Content-Type": "application/json"})
    assert r.status_code == 413


def test_unknown_route_and_wrong_method(local_client):
    assert local_client.get("/nope").status_code == 404
    assert local_client.get("/api/analyze").status_code == 405


def test_cors_allows_dev_origins_only(local_client):
    for origin in ("http://localhost:5173", "http://127.0.0.1:5173"):
        r = local_client.options("/api/analyze", headers={
            "Origin": origin, "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "content-type"})
        assert r.headers.get("access-control-allow-origin") == origin
    r = local_client.options("/api/analyze", headers={
        "Origin": "https://evil.example", "Access-Control-Request-Method": "POST"})
    assert "access-control-allow-origin" not in r.headers


def test_internal_errors_return_generic_500_without_details():
    class Boom(AnalysisService):
        def analyze(self, message, use_ai=True):
            raise RuntimeError("secret internal path C:\\Users\\me\\.aws\\credentials")

    settings = make_settings()
    client = TestClient(create_app(settings, Boom(settings)), raise_server_exceptions=False)
    r = client.post("/api/analyze", json={"message": GOOD})
    assert r.status_code == 500
    assert r.json() == {"detail": "Failed to analyze the message."}
    assert "credentials" not in r.text and "Traceback" not in r.text


def test_bedrock_disabled_makes_no_aws_calls_and_builds_no_client(monkeypatch):
    def forbidden(*a, **k):
        raise AssertionError("AWS must not be touched when USE_BEDROCK=false")

    monkeypatch.setattr(boto3, "Session", forbidden)
    monkeypatch.setattr(boto3, "client", forbidden)
    settings = make_settings(USE_BEDROCK="false")
    service = AnalysisService(settings)
    assert service.explainer is None
    with TestClient(create_app(settings, service)) as client:  # runs startup too
        r = client.post("/api/analyze", json={"message": GOOD, "use_ai": True})
    assert r.status_code == 200 and r.json()["ai_status"] == "disabled"
