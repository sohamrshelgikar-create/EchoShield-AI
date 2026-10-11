"""FastAPI app: routing and validation only. Analysis lives in service.py."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from backend.config import Settings, load_settings
from backend.schemas import AnalyzeRequest, AnalyzeResponse, BedrockHealth, HealthResponse
from backend.service import AnalysisService

logging.basicConfig(level=logging.INFO, format="%(levelname)s [%(name)s] %(message)s")
logger = logging.getLogger("echoshield")


_TOO_LARGE_BODY = b'{"detail":"Request is too large."}'


class BodyLimitMiddleware:
    """Reject request bodies larger than max_bytes with 413, even without Content-Length."""

    def __init__(self, app, max_bytes: int):
        self.app, self.max_bytes = app, max_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        declared = dict(scope.get("headers") or []).get(b"content-length")
        if declared is not None and declared.isdigit() and int(declared) > self.max_bytes:
            return await self._reject(send)

        received = 0
        exceeded = False
        responded = False

        async def counting_receive():
            nonlocal received, exceeded
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    exceeded = True
                    raise _TooLarge  # stops reading the body
            return message

        async def guarded_send(message):
            # The framework may turn the aborted read into its own 400 response;
            # replace whatever it sends with a single clean 413.
            nonlocal responded
            if exceeded:
                if not responded:
                    responded = True
                    await self._reject(send)
                return
            if message["type"] == "http.response.start":
                responded = True
            await send(message)

        try:
            await self.app(scope, counting_receive, guarded_send)
        except _TooLarge:
            pass
        if exceeded and not responded:
            await self._reject(send)

    @staticmethod
    async def _reject(send):
        await send({"type": "http.response.start", "status": 413, "headers": [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(_TOO_LARGE_BODY)).encode())]})
        await send({"type": "http.response.body", "body": _TOO_LARGE_BODY})


class _TooLarge(Exception):
    pass


def create_app(settings: Settings | None = None, service: AnalysisService | None = None) -> FastAPI:
    settings = settings or load_settings()
    service = service or AnalysisService(settings)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        service.startup()  # builds the Bedrock client only when USE_BEDROCK=true
        logger.info("EchoShield started (mode=%s)", "local+bedrock" if settings.use_bedrock else "local")
        yield

    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description="Scam and phishing message analyzer. A deterministic local analyzer decides the "
                    "risk; Amazon Bedrock optionally adds a plain-language explanation.",
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.state.service = service

    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(settings.cors_origins),
        allow_credentials=False,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Content-Type"],
    )
    app.add_middleware(BodyLimitMiddleware, max_bytes=settings.max_request_bytes)

    @app.exception_handler(RequestValidationError)
    async def validation_error(_request: Request, exc: RequestValidationError):
        # Never echo the submitted text back; give a short, friendly reason.
        detail = "Invalid request."
        for err in exc.errors():
            kind, loc = err.get("type", ""), err.get("loc", ())
            if kind == "json_invalid":
                detail = "Request body must be valid JSON."
            elif "message" in loc and kind == "missing":
                detail = "A 'message' field is required."
            elif "message" in loc and kind == "string_too_short":
                detail = f"Message must be at least {settings.min_message_chars} characters."
            elif "message" in loc and kind == "string_too_long":
                detail = f"Message must be at most {settings.max_message_chars} characters."
            elif "message" in loc:
                detail = "Message must be text."
            elif "use_ai" in loc:
                detail = "use_ai must be true or false."
            elif kind == "extra_forbidden":
                detail = "Unexpected field in request."
            break
        return JSONResponse({"detail": detail}, status_code=422)

    @app.get("/")
    def root():
        return {"name": settings.app_name, "status": "running", "version": settings.app_version}

    @app.get("/api/health", response_model=HealthResponse)
    def health():
        explainer = service.explainer
        if settings.use_bedrock and explainer is not None:
            bedrock = BedrockHealth(enabled=True, status=explainer.status(), last_error=explainer.last_error)
        else:
            bedrock = BedrockHealth(enabled=False, status="disabled")
        return HealthResponse(
            status="ok",
            version=settings.app_version,
            mode="local+bedrock" if settings.use_bedrock else "local",
            bedrock=bedrock,
        )

    @app.post("/api/analyze", response_model=AnalyzeResponse)
    def analyze(payload: AnalyzeRequest):
        try:
            return service.analyze(payload.message, use_ai=payload.use_ai)
        except Exception:  # noqa: BLE001
            logger.exception("Analysis failed")  # details stay in the server log
            raise HTTPException(status_code=500, detail="Failed to analyze the message.")

    return app


app = create_app()
