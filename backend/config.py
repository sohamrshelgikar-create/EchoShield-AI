"""
Configuration, loaded once at startup and validated.

Safe defaults: Bedrock is OFF unless USE_BEDROCK is explicitly set to true.
AWS credentials are never read from this file or from .env: when Bedrock is
enabled, boto3 uses the named AWS CLI profile (AWS_PROFILE) in AWS_REGION.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Mapping

from dotenv import load_dotenv

APP_NAME = "EchoShield AI"
APP_VERSION = "0.3.0"

DEFAULT_AWS_PROFILE = "echoshield"
DEFAULT_AWS_REGION = "us-east-1"
DEFAULT_MODEL_ID = "amazon.nova-micro-v1:0"
DEFAULT_CORS_ORIGINS = ("http://localhost:5173", "http://127.0.0.1:5173")

MIN_MESSAGE_CHARS = 3
MAX_MESSAGE_CHARS = 5000
MAX_REQUEST_BYTES = 32 * 1024  # JSON body limit; 5000 chars of UTF-8 fits comfortably

_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"0", "false", "no", "off"}
_REGION_RE = re.compile(r"^[a-z]{2}(?:-[a-z]+)+-\d$")
_PROFILE_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,64}$")
_MODEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/\-]{2,200}$")


class ConfigError(ValueError):
    """Raised at startup when a setting is present but invalid."""


@dataclass(frozen=True)
class Settings:
    app_name: str
    app_version: str
    app_env: str
    use_bedrock: bool
    aws_profile: str
    aws_region: str
    bedrock_model_id: str
    bedrock_max_tokens: int
    bedrock_timeout_seconds: int
    cors_origins: tuple[str, ...]
    min_message_chars: int = MIN_MESSAGE_CHARS
    max_message_chars: int = MAX_MESSAGE_CHARS
    max_request_bytes: int = MAX_REQUEST_BYTES


def _bool(env: Mapping[str, str], name: str, default: bool) -> bool:
    raw = env.get(name)
    if raw is None or raw.strip() == "":
        return default
    value = raw.strip().lower()
    if value in _TRUE:
        return True
    if value in _FALSE:
        return False
    raise ConfigError(f"{name} must be true or false (got an unrecognised value).")


def _int(env: Mapping[str, str], name: str, default: int, low: int, high: int) -> int:
    raw = env.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = int(raw.strip())
    except ValueError as exc:
        raise ConfigError(f"{name} must be a whole number.") from exc
    if not low <= value <= high:
        raise ConfigError(f"{name} must be between {low} and {high}.")
    return value


def _origins(env: Mapping[str, str]) -> tuple[str, ...]:
    raw = env.get("CORS_ORIGINS")
    if raw is None or raw.strip() == "":
        return DEFAULT_CORS_ORIGINS
    origins = tuple(o.strip().rstrip("/") for o in raw.split(",") if o.strip())
    for origin in origins:
        if origin == "*" or not re.match(r"^https?://[^\s/*]+$", origin):
            raise ConfigError(
                "CORS_ORIGINS must be a comma-separated list of exact origins "
                "such as http://localhost:5173 (wildcards are not allowed)."
            )
    return origins or DEFAULT_CORS_ORIGINS


def load_settings(
    environ: Mapping[str, str] | None = None, *, load_env_file: bool = True
) -> Settings:
    """Read and validate settings. Pass `environ` in tests to avoid touching os.environ."""
    if environ is None:
        if load_env_file:
            load_dotenv()  # does not override variables already set in the shell
        environ = os.environ

    use_bedrock = _bool(environ, "USE_BEDROCK", default=False)

    profile = environ.get("AWS_PROFILE", DEFAULT_AWS_PROFILE).strip()
    region = environ.get("AWS_REGION", DEFAULT_AWS_REGION).strip()
    model_id = environ.get("BEDROCK_MODEL_ID", DEFAULT_MODEL_ID).strip()

    if use_bedrock:
        if not _PROFILE_RE.match(profile):
            raise ConfigError("AWS_PROFILE is empty or contains invalid characters.")
        if not _REGION_RE.match(region):
            raise ConfigError("AWS_REGION is not a valid region name (example: us-east-1).")
        if not _MODEL_RE.match(model_id):
            raise ConfigError("BEDROCK_MODEL_ID is empty or contains invalid characters.")

    return Settings(
        app_name=APP_NAME,
        app_version=APP_VERSION,
        app_env=environ.get("APP_ENV", "development").strip() or "development",
        use_bedrock=use_bedrock,
        aws_profile=profile or DEFAULT_AWS_PROFILE,
        aws_region=region or DEFAULT_AWS_REGION,
        bedrock_model_id=model_id or DEFAULT_MODEL_ID,
        bedrock_max_tokens=_int(environ, "BEDROCK_MAX_TOKENS", 512, 64, 2048),
        bedrock_timeout_seconds=_int(environ, "BEDROCK_TIMEOUT_SECONDS", 10, 1, 60),
        cors_origins=_origins(environ),
    )
