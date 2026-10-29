from __future__ import annotations

from pathlib import Path
import logging

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from backend.chatbot_service import ChatbotService
from backend.config import ConfigurationError, Settings
from backend.groq_client import GroqProviderError, GroqRateLimitError
from backend.security import (
    AuthenticationError,
    IdentityServiceError,
    authenticate_cookie,
)
from backend.secure_access_client import DataSourceError, SecureAccessClient
from backend.tool_registry import ToolRegistry


logger = logging.getLogger("groq_ai_addon")
FRONTEND = Path(__file__).resolve().parents[1] / "frontend"
app = FastAPI(title="Secure Access Groq AI Addon", version="0.1.0")


class ChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=4000)


class ChatResponse(BaseModel):
    answer: str
    model: str
    retrieval_mode: str
    evidence_available: bool
    evidence_summary: str


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(FRONTEND / "index.html")


@app.get("/secret-ai.css", include_in_schema=False)
def stylesheet():
    return FileResponse(FRONTEND / "secret-ai.css", media_type="text/css")


@app.get("/secret-ai.js", include_in_schema=False)
def javascript():
    return FileResponse(FRONTEND / "secret-ai.js", media_type="text/javascript")


@app.get("/health")
def health():
    return {"status": "healthy", "addon": "standalone"}


@app.post("/api/chat", response_model=ChatResponse)
def chat(body: ChatRequest, request: Request):
    settings = Settings.from_env()
    try:
        settings.validate()
        cookie, identity = authenticate_cookie(
            request.headers.get("cookie"),
            settings,
        )
        client = SecureAccessClient(settings, cookie, identity)
        registry = ToolRegistry(settings, client, identity)
        service = ChatbotService(settings, client, registry)
        return service.answer(body.message, identity)
    except AuthenticationError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    except IdentityServiceError as exc:
        logger.warning("Identity validation failed")
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except ConfigurationError as exc:
        logger.warning("Addon configuration is incomplete: %s", exc)
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except DataSourceError as exc:
        logger.warning("Data source unavailable: %s", exc.source)
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except GroqRateLimitError as exc:
        headers = (
            {"Retry-After": str(exc.retry_after_seconds)}
            if exc.retry_after_seconds is not None
            else None
        )
        raise HTTPException(status_code=429, detail=str(exc), headers=headers) from exc
    except GroqProviderError as exc:
        logger.warning("Groq provider request failed")
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
