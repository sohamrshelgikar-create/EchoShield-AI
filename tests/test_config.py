import pytest

from backend.config import ConfigError, load_settings


def load(**env):
    return load_settings({k: str(v) for k, v in env.items()}, load_env_file=False)


def test_safe_defaults_when_nothing_is_set():
    s = load()
    assert s.use_bedrock is False
    assert (s.aws_profile, s.aws_region, s.bedrock_model_id) == ("echoshield", "us-east-1", "amazon.nova-micro-v1:0")
    assert "http://localhost:5173" in s.cors_origins and "http://127.0.0.1:5173" in s.cors_origins


@pytest.mark.parametrize("raw,expected", [("true", True), ("1", True), ("YES", True), ("false", False), ("0", False), ("", False)])
def test_use_bedrock_parsing(raw, expected):
    assert load(USE_BEDROCK=raw).use_bedrock is expected


def test_unrecognised_use_bedrock_fails_fast():
    with pytest.raises(ConfigError):
        load(USE_BEDROCK="maybe")


@pytest.mark.parametrize("bad", [{"AWS_REGION": "mars"}, {"AWS_PROFILE": ""}, {"AWS_PROFILE": "bad profile!"}, {"BEDROCK_MODEL_ID": ""}])
def test_invalid_aws_settings_rejected_when_enabled(bad):
    with pytest.raises(ConfigError):
        load(USE_BEDROCK="true", **bad)


def test_invalid_aws_settings_ignored_when_disabled():
    assert load(USE_BEDROCK="false", AWS_REGION="mars").use_bedrock is False


def test_numeric_limits():
    with pytest.raises(ConfigError):
        load(BEDROCK_MAX_TOKENS="999999")
    with pytest.raises(ConfigError):
        load(BEDROCK_TIMEOUT_SECONDS="abc")
    assert load(BEDROCK_TIMEOUT_SECONDS="5").bedrock_timeout_seconds == 5


@pytest.mark.parametrize("origins", ["*", "http://*.example.com", "localhost:5173", "ftp://x"])
def test_wildcard_or_malformed_cors_rejected(origins):
    with pytest.raises(ConfigError):
        load(CORS_ORIGINS=origins)


def test_custom_cors_origins():
    assert load(CORS_ORIGINS="https://a.example, https://b.example/").cors_origins == ("https://a.example", "https://b.example")


def test_no_aws_key_settings_exist():
    s = load(AWS_ACCESS_KEY_ID="x", AWS_SECRET_ACCESS_KEY="y")
    assert not any("key" in f.lower() or "secret" in f.lower() or "token" in f.lower() for f in s.__dataclass_fields__
                   if f not in ("bedrock_max_tokens",))
