"""
nexsus/core/rate_limiter.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~
Token-bucket rate limiter with:
  • Per-host independent buckets
  • Adaptive throttle when 429 / 503 responses arrive
  • Burst allowance (short spikes above steady rate)
  • Global cap so the whole scanner never overwhelms a single target
  • Concurrency semaphore per host
  • Jitter to avoid thundering-herd patterns
"""
import asyncio
import time
import random
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class _Bucket:
    """Token-bucket state for one host."""
    rate: float          # tokens per second  (requests/sec)
    burst: float         # maximum burst size
    tokens: float        # current token count
    last_refill: float   # monotonic timestamp of last refill
    backoff: float = 1.0 # multiplicative slow-down factor (raised on 429)
    _lock: asyncio.Lock  = field(default_factory=asyncio.Lock, repr=False)

    def refill(self):
        now = time.monotonic()
        elapsed = now - self.last_refill
        self.tokens = min(self.burst, self.tokens + elapsed * self.effective_rate)
        self.last_refill = now

    @property
    def effective_rate(self) -> float:
        return self.rate / self.backoff

    def consume(self) -> float:
        """Return wait time (seconds) needed before a token is available."""
        self.refill()
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return 0.0
        # How long until one token accumulates?
        wait = (1.0 - self.tokens) / max(self.effective_rate, 0.001)
        return wait


class RateLimiter:
    """
    Adaptive, per-host token-bucket rate limiter.

    Parameters
    ----------
    default_rate : float
        Steady-state requests per second per host.
    burst_multiplier : float
        Bucket capacity = rate × burst_multiplier.
    max_concurrency : int
        Limit simultaneous in-flight requests per host.
    global_cap : float
        Hard cap on requests/sec across **all** hosts combined.
    jitter : float
        Add ±jitter seconds of random delay after each wait.
    """

    def __init__(
        self,
        default_rate: float = 15,
        burst_multiplier: float = 3.0,
        max_concurrency: int = 10,
        global_cap: float = 100,
        jitter: float = 0.05,
    ):
        self.default_rate      = default_rate
        self.burst_multiplier  = burst_multiplier
        self.max_concurrency   = max_concurrency
        self.global_cap        = global_cap
        self.jitter            = jitter

        self._buckets: dict[str, _Bucket]           = {}
        self._semaphores: dict[str, asyncio.Semaphore] = {}
        self._global_tokens: float                  = global_cap
        self._global_last_refill: float             = time.monotonic()
        self._global_lock: asyncio.Lock             = asyncio.Lock()

        # Cooldown tracking for backoff recovery
        self._cooldown_tasks: dict[str, asyncio.Task] = {}

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _get_bucket(self, host: str) -> _Bucket:
        if host not in self._buckets:
            r = self.default_rate
            self._buckets[host] = _Bucket(
                rate=r,
                burst=r * self.burst_multiplier,
                tokens=r * self.burst_multiplier,   # start full
                last_refill=time.monotonic(),
            )
        return self._buckets[host]

    def _get_semaphore(self, host: str) -> asyncio.Semaphore:
        if host not in self._semaphores:
            self._semaphores[host] = asyncio.Semaphore(self.max_concurrency)
        return self._semaphores[host]

    async def _consume_global(self):
        """Ensure we stay within the global cap."""
        async with self._global_lock:
            now = time.monotonic()
            elapsed = now - self._global_last_refill
            self._global_tokens = min(
                self.global_cap,
                self._global_tokens + elapsed * self.global_cap,
            )
            self._global_last_refill = now
            if self._global_tokens < 1.0:
                wait = (1.0 - self._global_tokens) / self.global_cap
                await asyncio.sleep(wait)
            self._global_tokens -= 1.0

    # ── Public API ─────────────────────────────────────────────────────────────

    async def wait_if_needed(self, host: str):
        """
        Acquire permission to send one request to *host*.
        Blocks until both the per-host and global budgets allow it.
        """
        bucket = self._get_bucket(host)
        sem    = self._get_semaphore(host)

        # Per-host token bucket
        async with bucket._lock:
            wait = bucket.consume()
        if wait > 0:
            jitter = random.uniform(-self.jitter, self.jitter)
            await asyncio.sleep(max(0, wait + jitter))

        # Global cap
        await self._consume_global()

        # Concurrency limit (acquire; caller must release via context manager
        # or call release_slot)
        await sem.acquire()

    def release_slot(self, host: str):
        """Release the concurrency slot after a request completes."""
        sem = self._semaphores.get(host)
        if sem:
            sem.release()

    def on_rate_limited(self, host: str, retry_after: Optional[float] = None):
        """
        Call when a 429 / 503 is received.
        Doubles the effective back-off and schedules automatic recovery.
        """
        bucket = self._buckets.get(host)
        if not bucket:
            return
        bucket.backoff = min(bucket.backoff * 2, 64)  # cap at 64×

        # Cancel any existing recovery task
        old = self._cooldown_tasks.pop(host, None)
        if old and not old.done():
            old.cancel()

        # Schedule recovery after back-off window
        recover_in = (retry_after or 30) * 1.5
        self._cooldown_tasks[host] = asyncio.ensure_future(
            self._recover_backoff(host, recover_in)
        )

    async def _recover_backoff(self, host: str, delay: float):
        await asyncio.sleep(delay)
        bucket = self._buckets.get(host)
        if bucket and bucket.backoff > 1.0:
            bucket.backoff = max(1.0, bucket.backoff / 2)

    def set_rate(self, host: str, rate: float):
        """Manually set requests/sec for a specific host."""
        if host in self._buckets:
            b = self._buckets[host]
            b.rate  = rate
            b.burst = rate * self.burst_multiplier
        else:
            self._get_bucket(host)  # create with default, then override
            self._buckets[host].rate  = rate
            self._buckets[host].burst = rate * self.burst_multiplier

    def stats(self, host: str) -> dict:
        b = self._buckets.get(host)
        if not b:
            return {}
        b.refill()
        return {
            "host":           host,
            "rate_rps":       round(b.rate, 2),
            "effective_rps":  round(b.effective_rate, 2),
            "tokens":         round(b.tokens, 2),
            "backoff":        b.backoff,
        }

    def all_stats(self) -> list[dict]:
        return [self.stats(h) for h in self._buckets]
