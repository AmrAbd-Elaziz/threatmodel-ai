from pathlib import Path
import tempfile

import yaml
from pydantic import ValidationError

from fastapi import FastAPI, HTTPException, File, UploadFile
from fastapi.responses import HTMLResponse, Response, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from core.service import analyze_architecture
from core.reporting import generate_html_report
from core.assessment_history import (
    create_assessment_snapshot,
    compare_assessments,
)
from core.finding_reconciliation import (
    reconcile_findings,
    reconciliation_summary,
)


app = FastAPI(
    title="ThreatModel AI API",
    version="2.0.0",
    description=(
        "Security architecture threat modeling, "
        "attack-path analysis, control assessment, "
        "and continuous security reassessment API."
    ),
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "service": "ThreatModel AI",
        "version": "2.0.0",
    }


@app.get("/api/demo/banking")
def banking_demo():
    architecture_file = Path(
        "data/banking_architecture.yaml"
    )

    if not architecture_file.exists():
        raise HTTPException(
            status_code=404,
            detail="Banking architecture not found.",
        )

    return analyze_architecture(
        str(architecture_file)
    )


@app.get("/api/demo/banking/remediated")
def banking_demo_remediated():
    architecture_file = Path(
        "data/banking_architecture_remediated.yaml"
    )

    if not architecture_file.exists():
        raise HTTPException(
            status_code=404,
            detail="Remediated architecture not found.",
        )

    return analyze_architecture(
        str(architecture_file)
    )


@app.get("/api/demo/banking/reassessment")
def banking_reassessment():
    baseline_file = Path(
        "data/banking_architecture.yaml"
    )

    remediated_file = Path(
        "data/banking_architecture_remediated.yaml"
    )

    if not baseline_file.exists():
        raise HTTPException(
            status_code=404,
            detail="Baseline architecture not found.",
        )

    if not remediated_file.exists():
        raise HTTPException(
            status_code=404,
            detail="Remediated architecture not found.",
        )

    baseline_report = analyze_architecture(
        str(baseline_file)
    )

    remediated_report = analyze_architecture(
        str(remediated_file)
    )

    baseline_snapshot = (
        create_assessment_snapshot(
            baseline_report,
            "A-001",
        )
    )

    remediated_snapshot = (
        create_assessment_snapshot(
            remediated_report,
            "A-002",
        )
    )

    comparison = compare_assessments(
        baseline_snapshot,
        remediated_snapshot,
    )

    reconciliation = reconcile_findings(
        baseline_report["findings"],
        remediated_report["findings"],
    )

    lifecycle_summary = (
        reconciliation_summary(
            reconciliation
        )
    )

    return {
        "baseline": baseline_snapshot,
        "remediated": remediated_snapshot,
        "comparison": comparison,
        "finding_lifecycle": lifecycle_summary,
        "reconciliation": reconciliation,
        "baseline_findings": baseline_report[
            "findings"
        ],
        "remediated_findings": remediated_report[
            "findings"
        ],
    }


@app.get(
    "/api/demo/banking/report",
    response_class=HTMLResponse,
)
def banking_html_report():
    architecture_file = Path(
        "data/banking_architecture.yaml"
    )

    report = analyze_architecture(
        str(architecture_file)
    )

    return generate_html_report(
        report
    )


@app.get(
    "/api/demo/banking/report/download"
)
def banking_html_report_download():
    architecture_file = Path(
        "data/banking_architecture.yaml"
    )

    report = analyze_architecture(
        str(architecture_file)
    )

    html = generate_html_report(
        report
    )

    return Response(
        content=html,
        media_type="text/html",
        headers={
            "Content-Disposition": (
                'attachment; filename='
                '"threatmodel-ai-v2-assessment.html"'
            )
        },
    )


@app.post(
    "/api/assessments/reassessment"
)
def compare_uploaded_assessments(
    payload: dict,
):
    baseline_report = payload.get(
        "baseline"
    )

    remediated_report = payload.get(
        "remediated"
    )

    if not isinstance(
        baseline_report,
        dict,
    ) or not isinstance(
        remediated_report,
        dict,
    ):
        raise HTTPException(
            status_code=422,
            detail=(
                "Baseline and remediated "
                "assessment reports are required."
            ),
        )

    baseline_architecture = (
        baseline_report.get(
            "summary",
            {},
        ).get(
            "architecture"
        )
    )

    remediated_architecture = (
        remediated_report.get(
            "summary",
            {},
        ).get(
            "architecture"
        )
    )

    if (
        baseline_architecture
        and remediated_architecture
        and baseline_architecture
        != remediated_architecture
    ):
        raise HTTPException(
            status_code=422,
            detail=(
                "The remediated file belongs to "
                "a different architecture. "
                f"Expected '{baseline_architecture}', "
                f"received '{remediated_architecture}'."
            ),
        )

    baseline_snapshot = (
        create_assessment_snapshot(
            baseline_report,
            "A-001",
        )
    )

    remediated_snapshot = (
        create_assessment_snapshot(
            remediated_report,
            "A-002",
        )
    )

    comparison = compare_assessments(
        baseline_snapshot,
        remediated_snapshot,
    )

    reconciliation = reconcile_findings(
        baseline_report.get(
            "findings",
            [],
        ),
        remediated_report.get(
            "findings",
            [],
        ),
    )

    lifecycle_summary = (
        reconciliation_summary(
            reconciliation
        )
    )

    return {
        "baseline": baseline_snapshot,
        "remediated": remediated_snapshot,
        "comparison": comparison,
        "finding_lifecycle": (
            lifecycle_summary
        ),
        "reconciliation": reconciliation,
        "baseline_findings": (
            baseline_report.get(
                "findings",
                [],
            )
        ),
        "remediated_findings": (
            remediated_report.get(
                "findings",
                [],
            )
        ),
    }


@app.post(
    "/api/assessments/report",
    response_class=HTMLResponse,
)
def current_assessment_html_report(
    report: dict,
):
    try:
        return generate_html_report(report)
    except (KeyError, TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=422,
            detail=(
                "Unable to generate assessment report: "
                f"{exc}"
            ),
        )


MAX_ARCHITECTURE_FILE_SIZE = 1024 * 1024
ALLOWED_ARCHITECTURE_EXTENSIONS = {
    ".yaml",
    ".yml",
    ".json",
}


@app.post("/api/assessments/upload")
async def upload_architecture_assessment(
    file: UploadFile = File(...),
):
    original_name = Path(
        file.filename or ""
    ).name

    extension = Path(
        original_name
    ).suffix.lower()

    if extension not in (
        ALLOWED_ARCHITECTURE_EXTENSIONS
    ):
        raise HTTPException(
            status_code=415,
            detail=(
                "Unsupported architecture file. "
                "Upload a YAML, YML, or JSON file."
            ),
        )

    content = await file.read(
        MAX_ARCHITECTURE_FILE_SIZE + 1
    )

    await file.close()

    if not content:
        raise HTTPException(
            status_code=400,
            detail="The uploaded file is empty.",
        )

    if len(content) > MAX_ARCHITECTURE_FILE_SIZE:
        raise HTTPException(
            status_code=413,
            detail=(
                "Architecture file exceeds "
                "the 1 MB size limit."
            ),
        )

    try:
        decoded_content = content.decode(
            "utf-8"
        )
    except UnicodeDecodeError:
        raise HTTPException(
            status_code=400,
            detail=(
                "Architecture file must use "
                "UTF-8 encoding."
            ),
        )

    try:
        parsed_document = yaml.safe_load(
            decoded_content
        )
    except yaml.YAMLError as exc:
        raise HTTPException(
            status_code=422,
            detail=(
                "Invalid YAML or JSON syntax: "
                f"{exc}"
            ),
        )

    if not isinstance(parsed_document, dict):
        raise HTTPException(
            status_code=422,
            detail=(
                "Architecture document must "
                "contain a top-level object."
            ),
        )

    temporary_path = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            suffix=extension,
            delete=False,
        ) as temporary_file:
            temporary_file.write(content)

            temporary_path = Path(
                temporary_file.name
            )

        report = analyze_architecture(
            str(temporary_path)
        )

    except ValidationError as exc:
        errors = []

        for error in exc.errors():
            location = ".".join(
                str(part)
                for part in error.get(
                    "loc",
                    [],
                )
            )

            errors.append({
                "field": location,
                "message": error.get(
                    "msg",
                    "Invalid value.",
                ),
                "type": error.get(
                    "type",
                    "validation_error",
                ),
            })

        raise HTTPException(
            status_code=422,
            detail={
                "message": (
                    "Architecture validation failed."
                ),
                "errors": errors,
            },
        )

    except (ValueError, KeyError) as exc:
        raise HTTPException(
            status_code=422,
            detail=(
                "Architecture analysis failed: "
                f"{exc}"
            ),
        )

    finally:
        if (
            temporary_path is not None
            and temporary_path.exists()
        ):
            temporary_path.unlink()

    report["source"] = {
        "filename": original_name,
        "size_bytes": len(content),
        "format": extension.lstrip("."),
    }

    return report


# Serve the compiled React application from the same domain as the API.
FRONTEND_DIST = (
    Path(__file__).resolve().parent.parent
    / "frontend"
    / "dist"
)

app.mount(
    "/assets",
    StaticFiles(directory=FRONTEND_DIST / "assets"),
    name="frontend-assets",
)


@app.get(
    "/{full_path:path}",
    include_in_schema=False,
)
def serve_frontend(full_path: str):
    return FileResponse(
        FRONTEND_DIST / "index.html"
    )
