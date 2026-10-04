from fastapi import FastAPI
from pydantic import BaseModel
import requests

app = FastAPI(
    title="AI Security Analyst",
    description="Security analysis API for the Cloud-Native Security Platform",
    version="0.3.3"
)

PROMETHEUS_URL = "http://prometheus.monitoring.svc.cluster.local:9090"


class SecurityFinding(BaseModel):
    finding: str
    source: str
    destination: str
    evidence: str
    control: str


class SecurityEvidence(BaseModel):
    event_type: str
    source_workload: str
    destination_workload: str
    source_principal: str
    destination_principal: str
    response: str
    security_protocol: str
    denied_connections: int


@app.get("/health")
def health():
    return {
        "service": "ai-security-analyst",
        "status": "healthy"
    }


@app.post("/analyze")
def analyze_finding(finding: SecurityFinding):
    return {
        "finding": finding.finding,
        "severity": "HIGH",
        "source": finding.source,
        "destination": finding.destination,
        "evidence": finding.evidence,
        "security_control": finding.control,
        "impact": (
            "Unauthorized communication was prevented "
            "by the security control."
        ),
        "recommended_action": (
            "Review the workload identity and "
            "authorization policy."
        )
    }


@app.get("/evidence/denied-connections")
def denied_connections():
    query = 'istio_tcp_connections_failed_total{response_flags="DENY"}'

    response = requests.get(
        f"{PROMETHEUS_URL}/api/v1/query",
        params={"query": query},
        timeout=5
    )

    response.raise_for_status()

    data = response.json()

    findings = []

    for item in data["data"]["result"]:
        metric = item["metric"]
        value = item["value"][1]

        evidence = SecurityEvidence(
            event_type="authorization_denial",
            source_workload=metric.get(
                "source_workload",
                "unknown"
            ),
            destination_workload=metric.get(
                "destination_workload",
                "unknown"
            ),
            source_principal=metric.get(
                "source_principal",
                "unknown"
            ),
            destination_principal=metric.get(
                "destination_principal",
                "unknown"
            ),
            response=metric.get(
                "response_flags",
                "unknown"
            ),
            security_protocol=metric.get(
                "connection_security_policy",
                "unknown"
            ),
            denied_connections=int(float(value))
        )

        findings.append(evidence.model_dump())

    return {
        "evidence_type": "istio_authorization_denial",
        "prometheus_status": data["status"],
        "findings": findings
    }


@app.get("/analyze/denied-connections")
def analyze_denied_connections():
    query = 'istio_tcp_connections_failed_total{response_flags="DENY"}'

    response = requests.get(
        f"{PROMETHEUS_URL}/api/v1/query",
        params={"query": query},
        timeout=5
    )

    response.raise_for_status()

    data = response.json()

    findings = []

    for item in data["data"]["result"]:
        metric = item["metric"]

        denied_connections = int(
            float(item["value"][1])
        )

        source = metric.get(
            "source_workload",
            "unknown"
        )

        destination = metric.get(
            "destination_workload",
            "unknown"
        )

        source_principal = metric.get(
            "source_principal",
            "unknown"
        )

        destination_principal = metric.get(
            "destination_principal",
            "unknown"
        )

        evidence = SecurityEvidence(
            event_type="authorization_denial",
            source_workload=source,
            destination_workload=destination,
            source_principal=source_principal,
            destination_principal=destination_principal,
            response=metric.get(
                "response_flags",
                "unknown"
            ),
            security_protocol=metric.get(
                "connection_security_policy",
                "unknown"
            ),
            denied_connections=denied_connections
        )

        findings.append({
            "finding": (
                f"Unauthorized connection attempt from "
                f"{source} to {destination}"
            ),
            "severity": "HIGH",
            "source": source,
            "destination": destination,
            "evidence": evidence.model_dump(),
            "security_control": (
                "Istio AuthorizationPolicy denied "
                "the connection."
            ),
            "impact": (
                "The source workload was prevented from "
                "communicating with the protected destination."
            ),
            "recommended_action": (
                "Review the source workload identity and verify "
                "that the authorization policy allows only "
                "intended service-to-service communication."
            )
        })

    return {
        "analysis_type": "istio_denied_connection_analysis",
        "prometheus_status": data["status"],
        "findings": findings
    }
