from datetime import date

from core.findings import generate_findings
from core.service import analyze_architecture


INPUT_FILE = (
    "data/banking_architecture.yaml"
)


def _findings():
    report = analyze_architecture(
        INPUT_FILE
    )

    return generate_findings(
        report["attack_paths"],
        assessment_date=date(
            2026,
            9,
            12,
        ),
    )


def test_findings_are_generated():
    findings = _findings()

    assert findings


def test_findings_have_unique_ids():
    findings = _findings()

    ids = [
        finding["id"]
        for finding in findings
    ]

    assert len(ids) == len(set(ids))


def test_findings_have_owner():
    findings = _findings()

    assert all(
        finding["owner"]
        for finding in findings
    )


def test_findings_have_sla():
    findings = _findings()

    assert all(
        finding["sla_days"] > 0
        for finding in findings
    )


def test_findings_have_due_date():
    findings = _findings()

    assert all(
        finding["due_date"]
        for finding in findings
    )


def test_missing_least_privilege_becomes_finding():
    findings = _findings()

    least_privilege = [
        finding
        for finding in findings
        if finding["control_id"]
        == "TM-C010"
    ]

    assert least_privilege
    assert (
        least_privilege[0]["status"]
        == "Open"
    )


def test_finding_ids_are_stable():
    first = _findings()
    second = _findings()

    first_ids = {
        finding["id"]
        for finding in first
    }

    second_ids = {
        finding["id"]
        for finding in second
    }

    assert first_ids == second_ids


def test_finding_ids_use_fingerprint_format():
    findings = _findings()

    for finding in findings:
        assert finding["id"].startswith(
            "GAP-"
        )

        fingerprint = finding[
            "id"
        ].removeprefix("GAP-")

        assert len(fingerprint) == 8
        assert all(
            character
            in "0123456789ABCDEF"
            for character in fingerprint
        )
