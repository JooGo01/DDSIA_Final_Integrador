"""Logs en JSON con un request_id que atraviesa toda la peticion."""

import logging
import sys
from contextvars import ContextVar

import structlog

_request_id: ContextVar[str] = ContextVar("request_id", default="-")

# Claves que se reemplazan por [REDACTED] antes de escribir el log.
SENSITIVE_KEYS = frozenset(
    {
        "authorization",
        "password",
        "token",
        "access_token",
        "jwt_secret",
        "api_key",
        "prompt",
        "context",
        "question",
        "answer",
    }
)


def set_request_id(value: str) -> None:
    """Guarda el request_id actual para que lo tomen los logs de esta peticion."""
    _request_id.set(value)


def get_request_id() -> str:
    """Devuelve el request_id de la peticion en curso."""
    return _request_id.get()


def add_request_id(logger, name, event_dict):
    """Procesador de structlog: agrega el request_id a cada evento."""
    event_dict["request_id"] = _request_id.get()
    return event_dict


def redact_sensitive(logger, name, event_dict):
    """Procesador de structlog: enmascara los campos sensibles."""
    for key in list(event_dict):
        if key.lower() in SENSITIVE_KEYS:
            event_dict[key] = "[REDACTED]"
    return event_dict


def configure_logging(level: str = "INFO") -> None:
    """Deja structlog escribiendo JSON a stdout."""
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(format="%(message)s", stream=sys.stdout, level=numeric_level)
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            add_request_id,
            redact_sensitive,
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(numeric_level),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str = "app"):
    """Devuelve un logger ya configurado."""
    return structlog.get_logger(name)
