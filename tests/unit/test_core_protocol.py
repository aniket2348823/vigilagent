"""Tests for backend.core.protocol — Enums, Pydantic models, JobPacket, ResultPacket."""
import pytest
from backend.core.protocol import (
    TaskPriority, AgentStatus, AgentID, ModuleConfig,
    TaskTarget, JobPacket, Vulnerability, ResultPacket,
)


class TestTaskPriority:
    def test_values(self):
        assert TaskPriority.CRITICAL.value == "CRITICAL"
        assert TaskPriority.HIGH.value == "HIGH"
        assert TaskPriority.NORMAL.value == "NORMAL"
        assert TaskPriority.LOW.value == "LOW"

    def test_is_str_enum(self):
        assert isinstance(TaskPriority.CRITICAL, str)


class TestAgentStatus:
    def test_values(self):
        assert AgentStatus.IDLE.value == "IDLE"
        assert AgentStatus.WORKING.value == "WORKING"
        assert AgentStatus.THROTTLED.value == "THROTTLED"
        assert AgentStatus.SLEEPING.value == "SLEEPING"


class TestAgentID:
    def test_all_agents_present(self):
        expected = {"agent_omega", "agent_zeta", "agent_alpha", "agent_beta",
                    "agent_gamma", "agent_sigma", "agent_kappa", "agent_delta",
                    "agent_prism", "agent_chi", "agent_lambda"}
        actual = {a.value for a in AgentID}
        assert expected == actual

    def test_is_str_enum(self):
        assert isinstance(AgentID.ALPHA, str)


class TestModuleConfig:
    def test_minimal(self):
        mc = ModuleConfig(module_id="test", agent_id=AgentID.ALPHA)
        assert mc.module_id == "test"
        assert mc.agent_id == AgentID.ALPHA
        assert mc.aggression == 5
        assert mc.ai_mode is True
        assert mc.session_id is None
        assert mc.params == {}

    def test_custom_params(self):
        mc = ModuleConfig(module_id="x", agent_id=AgentID.BETA, aggression=8, params={"key": "val"})
        assert mc.aggression == 8
        assert mc.params == {"key": "val"}

    def test_aggression_bounds(self):
        ModuleConfig(module_id="x", agent_id=AgentID.ALPHA, aggression=1)
        ModuleConfig(module_id="x", agent_id=AgentID.ALPHA, aggression=10)
        with pytest.raises(Exception):
            ModuleConfig(module_id="x", agent_id=AgentID.ALPHA, aggression=0)
        with pytest.raises(Exception):
            ModuleConfig(module_id="x", agent_id=AgentID.ALPHA, aggression=11)


class TestTaskTarget:
    def test_minimal(self):
        tt = TaskTarget(url="http://example.com")
        assert tt.url == "http://example.com"
        assert tt.method == "GET"
        assert tt.headers == {}
        assert tt.payload is None

    def test_custom(self):
        tt = TaskTarget(url="http://x.com", method="POST", headers={"Auth": "tok"})
        assert tt.method == "POST"
        assert tt.headers["Auth"] == "tok"


class TestJobPacket:
    def test_auto_generates_id(self):
        jp = JobPacket(
            target=TaskTarget(url="http://a.com"),
            config=ModuleConfig(module_id="m", agent_id=AgentID.ALPHA)
        )
        assert jp.id  # UUID auto-generated
        assert jp.priority == TaskPriority.NORMAL
        assert jp.timestamp is not None

    def test_custom_priority(self):
        jp = JobPacket(
            priority=TaskPriority.CRITICAL,
            target=TaskTarget(url="http://a.com"),
            config=ModuleConfig(module_id="m", agent_id=AgentID.BETA)
        )
        assert jp.priority == TaskPriority.CRITICAL


class TestVulnerability:
    def test_required_fields(self):
        v = Vulnerability(name="SQLi", severity="HIGH", description="test", evidence="payload")
        assert v.name == "SQLi"
        assert v.remediation is None

    def test_with_remediation(self):
        v = Vulnerability(name="XSS", severity="MEDIUM", description="d", evidence="e", remediation="fix")
        assert v.remediation == "fix"


class TestResultPacket:
    def test_minimal(self):
        rp = ResultPacket(
            job_id="j1",
            source_agent=AgentID.ALPHA,
            status="SUCCESS",
            execution_time_ms=100.5,
            data={"key": "val"}
        )
        assert rp.job_id == "j1"
        assert rp.vulnerabilities == []
        assert rp.next_step is None

    def test_with_vulns(self):
        rp = ResultPacket(
            job_id="j2",
            source_agent=AgentID.BETA,
            status="VULN_FOUND",
            execution_time_ms=50.0,
            data={},
            vulnerabilities=[Vulnerability(name="XSS", severity="HIGH", description="d", evidence="e")],
            next_step="validate"
        )
        assert len(rp.vulnerabilities) == 1
        assert rp.next_step == "validate"
