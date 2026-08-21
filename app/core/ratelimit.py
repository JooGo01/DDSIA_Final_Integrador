"""Limites de uso: token bucket por request y presupuesto diario de tokens de LLM.

El estado vive en memoria del proceso. Alcanza para una sola instancia, que es el
alcance de este proyecto; con varias replicas habria que moverlo a Redis.
"""

import threading
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime


@dataclass
class Bucket:
    tokens: float
    last_refill: float


class TokenBucketLimiter:
    """Permite rafagas cortas y despues repone a ritmo constante."""

    def __init__(self, capacity: int, refill_per_minute: int) -> None:
        self.capacity = capacity
        self.refill_rate = refill_per_minute / 60.0
        self._buckets: dict[str, Bucket] = {}
        self._lock = threading.Lock()

    def check(self, key: str) -> tuple[bool, int]:
        """Consume un permiso para la clave. Devuelve (permitido, segundos para reintentar)."""
        now = time.monotonic()
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = Bucket(tokens=float(self.capacity), last_refill=now)
                self._buckets[key] = bucket

            elapsed = now - bucket.last_refill
            bucket.tokens = min(self.capacity, bucket.tokens + elapsed * self.refill_rate)
            bucket.last_refill = now

            if bucket.tokens >= 1:
                bucket.tokens -= 1
                return True, 0

            missing = 1 - bucket.tokens
            retry_after = max(1, int(missing / self.refill_rate) + 1)
            return False, retry_after

    def reset(self) -> None:
        """Vacia el estado. Se usa entre tests."""
        with self._lock:
            self._buckets.clear()


@dataclass
class DailyUsage:
    day: str
    tokens: int = 0


@dataclass
class TokenBudget:
    """Cuota diaria de tokens de LLM por usuario. Se reinicia sola al cambiar el dia UTC."""

    limit: int
    _usage: dict[str, DailyUsage] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    @staticmethod
    def _today() -> str:
        return datetime.now(UTC).strftime("%Y-%m-%d")

    def remaining(self, user: str) -> int:
        """Tokens que le quedan al usuario hoy."""
        with self._lock:
            usage = self._usage.get(user)
            if usage is None or usage.day != self._today():
                return self.limit
            return max(0, self.limit - usage.tokens)

    def has_budget(self, user: str) -> bool:
        """True si al usuario todavia le queda cuota."""
        return self.remaining(user) > 0

    def consume(self, user: str, tokens: int) -> None:
        """Descuenta tokens ya gastados del presupuesto del usuario."""
        today = self._today()
        with self._lock:
            usage = self._usage.get(user)
            if usage is None or usage.day != today:
                usage = DailyUsage(day=today)
                self._usage[user] = usage
            usage.tokens += tokens

    def reset(self) -> None:
        """Vacia el estado. Se usa entre tests."""
        with self._lock:
            self._usage.clear()
