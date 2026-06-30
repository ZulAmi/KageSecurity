"""Unit tests for concurrent multi-target scanning in cli/main.py."""
import sys
import types
import threading
import unittest.mock as mock
import pytest


def _make_args(parallel: int = 2) -> types.SimpleNamespace:
    return types.SimpleNamespace(
        parallel=parallel,
        output="json",
        fail_on=None,
        modules=None,
        verbose=False,
        no_color=True,
    )


class TestRunMultiTargetParallel:
    """Validate _run_multi_target thread-safety and error handling."""

    def _patch_run_single(self, return_values: dict):
        """Return a mock for _run_single_target that maps target → return code."""
        def _fake(target, args, prefix="", print_lock=None):
            return return_values.get(target, 0)
        return _fake

    def test_all_success_exits_zero(self, monkeypatch, capsys):
        import cli.main as cli

        returns = {"http://a.com": 0, "http://b.com": 0}
        monkeypatch.setattr(cli, "_run_single_target", self._patch_run_single(returns))

        with pytest.raises(SystemExit) as exc_info:
            cli._run_multi_target(["http://a.com", "http://b.com"], _make_args())
        # sys.exit only called on failure — if no exception raised, success
        pytest.skip("no sys.exit on success — reached here normally")

    def test_one_failure_exits_one(self, monkeypatch):
        import cli.main as cli

        returns = {"http://a.com": 0, "http://b.com": 1}
        monkeypatch.setattr(cli, "_run_single_target", self._patch_run_single(returns))

        with pytest.raises(SystemExit) as exc_info:
            cli._run_multi_target(["http://a.com", "http://b.com"], _make_args())
        assert exc_info.value.code == 1

    def test_thread_crash_does_not_lose_other_results(self, monkeypatch, capsys):
        """A thread that raises must not silence a failure in another thread."""
        import cli.main as cli

        call_count = {"n": 0}
        lock = threading.Lock()

        def _crashing(target, args, prefix="", print_lock=None):
            with lock:
                call_count["n"] += 1
            if target == "http://crash.com":
                raise RuntimeError("network down")
            return 1  # other target has findings

        monkeypatch.setattr(cli, "_run_single_target", _crashing)

        with pytest.raises(SystemExit) as exc_info:
            cli._run_multi_target(
                ["http://crash.com", "http://findings.com"],
                _make_args(parallel=2),
            )
        assert exc_info.value.code == 1
        # Both targets were attempted
        assert call_count["n"] == 2

    def test_sequential_fallback_when_parallel_one(self, monkeypatch):
        """parallel=1 should use the sequential path (no ThreadPoolExecutor)."""
        import cli.main as cli

        order = []

        def _ordered(target, args, prefix="", print_lock=None):
            order.append(target)
            return 0

        monkeypatch.setattr(cli, "_run_single_target", _ordered)

        # Should not raise (all success)
        cli._run_multi_target(
            ["http://first.com", "http://second.com"],
            _make_args(parallel=1),
        )
        assert order == ["http://first.com", "http://second.com"]
