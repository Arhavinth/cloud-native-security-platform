from fastapi import FastAPI
from pydantic import BaseModel
import requests

app = FastAPI(
    title="AI Security Analyst",
    description="Security analysis API for the Cloud-Native Security Platform",
    version="0.2.0"
)

PROMETHEUS_URL = "http://prometheus.monitoring.svc.cluster.local:9090"


class SecurityFinding(BaseModel):
    finding: str
    source: str
    destination: str
    evidence: str
    control: str


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
        "impact": "Unauthorized communication was prevented by the security control.",
        "recommended_action": "Review the workload identity and authorization policy."
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

        findings.append({
            "source_workload": metric.get("source_workload"),
            "source_namespace": metric.get("source_workload_namespace"),
            "source_principal": metric.get("source_principal"),
            "destination_workload": metric.get("destination_workload"),
            "destination_namespace": metric.get("destination_workload_namespace"),
            "destination_principal": metric.get("destination_principal"),
            "response_flag": metric.get("response_flags"),
            "connection_security_policy": metric.get(
                "connection_security_policy"
            ),
            "denied_connections": int(float(value))
        })

    return {
        "evidence_type": "istio_authorization_denial",
        "prometheus_status": data["status"],
        "findings": findings
    }
