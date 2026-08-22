"""Tests for backend.tools.recon modules — registry, runner, commands."""
import pytest
from unittest.mock import patch, MagicMock


class TestReconRegistry:
    def test_import(self):
        from backend.tools.recon.registry import check_tool_availability
        assert callable(check_tool_availability)

    def test_check_tool(self):
        from backend.tools.recon.registry import check_tool_availability
        result = check_tool_availability("nmap")
        assert isinstance(result, dict)
        assert "installed" in result


class TestReconRunner:
    def test_import(self):
        from backend.tools.recon.runner import ReconCommandRunner, ReconCommandResult
        assert ReconCommandRunner is not None
        assert ReconCommandResult is not None


class TestReconCommands:
    def test_import(self):
        from backend.tools.recon.commands import ReconCommand, ReconCommandPlanner
        assert ReconCommand is not None
        assert ReconCommandPlanner is not None
