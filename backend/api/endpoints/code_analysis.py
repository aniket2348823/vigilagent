"""
PROBLEM 18 FIX: Code Analysis API endpoint.
Exposes the Lambda Agent's pre-code scanning via REST API.
Used by VS Code extension and any CI/CD integration.
"""

from fastapi import APIRouter
from pydantic import BaseModel

from backend.agents.lambda_agent import LambdaAgent

router = APIRouter()
lambda_agent = LambdaAgent("agent_lambda", None)


class CodePayload(BaseModel):
    code: str
    language: str = "python"
    filename: str = ""


class FilePayload(BaseModel):
    content: str
    filename: str = ""


@router.post("/analyze-code")
async def analyze_code(payload: CodePayload):
    """
    Analyze source code for security vulnerabilities.
    Returns findings with line numbers, severity, and fix recommendations.
    """
    findings = await lambda_agent.analyze(payload.code, payload.language, filename=payload.filename)
    return {
        "findings": findings,
        "total": len(findings),
        "critical": sum(1 for f in findings if f["severity"] == "CRITICAL"),
        "high": sum(1 for f in findings if f["severity"] == "HIGH"),
        "medium": sum(1 for f in findings if f["severity"] == "MEDIUM"),
        "low": sum(1 for f in findings if f["severity"] == "LOW"),
    }


@router.post("/analyze-iac")
async def analyze_iac(payload: FilePayload):
    """Scan Infrastructure-as-Code for misconfigurations (Architecture §29.5).
    Supports Terraform, CloudFormation, Kubernetes, Dockerfile."""
    findings = lambda_agent.scan_iac(payload.content, payload.filename)
    return {
        "findings": findings,
        "total": len(findings),
        "by_severity": {
            s: sum(1 for f in findings if f["severity"] == s) for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
        },
    }


@router.post("/analyze-dependencies")
async def analyze_dependencies(payload: FilePayload):
    """Scan a dependency manifest (SBOM) for vulnerable/unpinned packages
    (Architecture §29.5). Supports requirements.txt, package.json, go.mod."""
    findings = lambda_agent.scan_sbom(payload.content, payload.filename)
    return {
        "findings": findings,
        "total": len(findings),
        "by_severity": {
            s: sum(1 for f in findings if f["severity"] == s) for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
        },
    }
