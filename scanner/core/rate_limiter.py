import time
import threading
from collections import deque


class RateLimiter:
    """Sliding-window rate limiter. Thread-safe."""

    def __init__(self, rps: int = 10):
        self._rps = max(1, rps)
        self._lock = threading.Lock()
        self._timestamps: deque = deque()

    def acquire(self) -> None:
        while True:
            with self._lock:
                now = time.time()
                cutoff = now - 1.0
                while self._timestamps and self._timestamps[0] < cutoff:
                    self._timestamps.popleft()
                if len(self._timestamps) < self._rps:
                    self._timestamps.append(now)
                    return
                sleep_until = self._timestamps[0] + 1.0
            time.sleep(max(0.001, sleep_until - time.time()))


class RateLimitedClient:
    """Wraps httpx.Client and rate-limits every outbound request."""

    def __init__(self, client, limiter: RateLimiter):
        self._client = client
        self._limiter = limiter

    def get(self, *args, **kwargs):
        self._limiter.acquire()
        return self._client.get(*args, **kwargs)

    def post(self, *args, **kwargs):
        self._limiter.acquire()
        return self._client.post(*args, **kwargs)

    def put(self, *args, **kwargs):
        self._limiter.acquire()
        return self._client.put(*args, **kwargs)

    def patch(self, *args, **kwargs):
        self._limiter.acquire()
        return self._client.patch(*args, **kwargs)

    def delete(self, *args, **kwargs):
        self._limiter.acquire()
        return self._client.delete(*args, **kwargs)

    def request(self, *args, **kwargs):
        self._limiter.acquire()
        return self._client.request(*args, **kwargs)

    def close(self):
        self._client.close()

    def __getattr__(self, name):
        return getattr(self._client, name)
