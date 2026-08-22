"""Tests for backend.core.queue — CommandLane, LanePriority, ProcessResult."""
import pytest
from backend.core.queue import LanePriority, ProcessResult, CommandLane


class TestLanePriority:
    def test_values(self):
        assert LanePriority.CRITICAL.value == 0
        assert LanePriority.HIGH.value == 1
        assert LanePriority.NORMAL.value == 2


class TestProcessResult:
    def test_creation(self):
        pr = ProcessResult(exit_code=0, stdout="ok", stderr="", timed_out=False, killed=False, duration_ms=12)
        assert pr.exit_code == 0
        assert pr.stdout == "ok"
        assert pr.timed_out is False
        assert pr.killed is False
        assert pr.duration_ms == 12


class TestCommandLane:
    def test_creation(self):
        cl = CommandLane(max_concurrent=5)
        assert cl is not None
