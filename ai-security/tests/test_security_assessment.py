from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.main import SecurityAssessment, normalize_security_assessment


@pytest.fixture
def denied_evidence():
    return {
        "event_type": "authorization_denial",
        "source_workload": "unauthorized-test-client",
        "destination_workload": "security-demo-api",
        "source_principal": "spiffe://cluster.local/ns/default/sa/default",
        "destination_principal": (
            "spiffe://cluster.local/ns/default/sa/security-demo-api"
        ),
        "response": "DENY",
        "security_protocol": "mutual_tls",
        "denied_connections": 1,
    }


@pytest.fixture
def misleading_assessment():
    return SecurityAssessment(
        finding="The API was compromised by an attacker.",
        severity="HIGH",
        security_control="Mutual TLS caused the denial.",
        impact="The attacker successfully compromised the API.",
        recommended_action="Disable the authorization policy immediately.",
        confidence="HIGH",
    )


def test_deny_finding_uses_evidence_workload_names(
    denied_evidence, misleading_assessment
):
    result = normalize_security_assessment(
        misleading_assessment, denied_evidence
    )

    assert result.finding == (
        "Connection from unauthorized-test-client to "
        "security-demo-api was denied."
    )


def test_deny_assessment_does_not_claim_proven_compromise(
    denied_evidence, misleading_assessment
):
    result = normalize_security_assessment(
        misleading_assessment, denied_evidence
    )

    assert "does not establish" in result.impact
    assert "successful compromise" in result.impact
    assert "malicious intent" in result.impact


def test_mtls_is_observed_without_claiming_it_caused_denial(
    denied_evidence, misleading_assessment
):
    result = normalize_security_assessment(
        misleading_assessment, denied_evidence
    )

    assert "Authorization outcome: DENY" in result.security_control
    assert "Mutual TLS was observed." in result.security_control
    assert "does not establish the precise denial cause" in (
        result.security_control
    )
    assert "Mutual TLS caused the denial." not in result.security_control


def test_unknown_protocol_does_not_assume_mtls(
    denied_evidence, misleading_assessment
):
    denied_evidence["security_protocol"] = "unknown"

    result = normalize_security_assessment(
        misleading_assessment, denied_evidence
    )

    assert "Observed security protocol: unknown." in result.security_control
    assert "Mutual TLS was observed." not in result.security_control


def test_non_deny_assessment_preserves_existing_behavior(
    denied_evidence, misleading_assessment
):
    denied_evidence["response"] = "ALLOW"
    original = misleading_assessment.model_dump()

    result = normalize_security_assessment(
        misleading_assessment, denied_evidence
    )

    assert result.model_dump() == original


def test_normalization_does_not_mutate_original_assessment(
    denied_evidence, misleading_assessment
):
    original = misleading_assessment.model_dump()

    normalize_security_assessment(misleading_assessment, denied_evidence)

    assert misleading_assessment.model_dump() == original
