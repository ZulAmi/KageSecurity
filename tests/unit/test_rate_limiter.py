"""Unit tests for scanner/core/rate_limiter.py"""
import time
import threading
import pytest
from scanner.core.rate_limiter import RateLimiter, RateLimitedClient


class TestRateLimiter:
    def test_allows_up_to_rps(self):
        rl = RateLimiter(rps=5)
        start = time.time()
        for _ in range(5):
            rl.acquire()
        elapsed = time.time() - start
        assert elapsed < 0.1, "First burst of 5 should be instant"

    def test_blocks_on_sixth(self):
        rl = RateLimiter(rps=5)
        for _ in range(5):
            rl.acquire()
        start = time.time()
        rl.acquire()
        elapsed = time.time() - start
        assert elapsed >= 0.9, "6th call should wait ~1s for window to slide"

    def test_minimum_rps_is_one(self):
        rl = RateLimiter(rps=0)
        rl.acquire()

    def test_thread_safe(self):
        rl = RateLimiter(rps=10)
        results = []
        errors = []

        def worker():
            try:
                for _ in range(3):
                    rl.acquire()
                    results.append(1)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)

        assert not errors
        assert len(results) == 15


class TestRateLimitedClient:
    def test_proxies_get(self):
        calls = []

        class FakeClient:
            def get(self, *a, **kw):
                calls.append(("get", a, kw))
                return "ok"
            cookies = {}

        rl = RateLimiter(rps=100)
        client = RateLimitedClient(FakeClient(), rl)
        result = client.get("http://x.com")
        assert result == "ok"
        assert calls[0][0] == "get"

    def test_proxies_post(self):
        calls = []

        class FakeClient:
            def post(self, *a, **kw):
                calls.append("post")
                return "posted"
            cookies = {}

        rl = RateLimiter(rps=100)
        client = RateLimitedClient(FakeClient(), rl)
        result = client.post("http://x.com", data={"k": "v"})
        assert result == "posted"
        assert "post" in calls

    def test_delegates_unknown_attr(self):
        class FakeClient:
            custom_attr = "hello"
            cookies = {}

        rl = RateLimiter(rps=100)
        client = RateLimitedClient(FakeClient(), rl)
        assert client.custom_attr == "hello"
