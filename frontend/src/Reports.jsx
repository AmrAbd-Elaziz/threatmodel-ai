import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";

import {
  Activity,
  AlertTriangle,
  Download,
  ExternalLink,
  FileJson,
  FileText,
  FileWarning,
  LayoutDashboard,
  Network,
  RefreshCcw,
  Route,
  ShieldCheck,
} from "lucide-react";

import Footer from "./Footer";
import Sidebar from "./Sidebar";
import SharedHeader from "./SharedHeader";

import "./index.css";

const API_BASE = "http://127.0.0.1:8000";

const CURRENT_ASSESSMENT_KEY =
  "threatmodel-current-assessment";

function calculateAverageCoverage(
  attackPaths
) {
  if (!attackPaths?.length) {
    return 0;
  }

  const total = attackPaths.reduce(
    (sum, path) =>
      sum +
      (
        path.control_summary
          ?.coverage_percentage ?? 0
      ),
    0
  );

  return Math.round(
    (total / attackPaths.length) * 10
  ) / 10;
}

function calculateHighestResidualRisk(
  attackPaths
) {
  return Math.max(
    0,
    ...(attackPaths || []).map(
      (path) =>
        path.residual_path_risk ?? 0
    )
  );
}

function SidebarItem({
  icon: Icon,
  label,
  to,
  active = false,
}) {
  return (
    <Link
      to={to}
      className={`nav-item ${active ? "active" : ""}`}
    >
      <Icon size={18} />
      <span>{label}</span>
    </Link>
  );
}

function Reports() {
  const [report, setReport] = useState(null);
  const [reassessment, setReassessment] =
    useState(null);

  const [loading, setLoading] =
    useState(true);

  const [error, setError] =
    useState("");

  async function loadReports() {
    try {
      setLoading(true);
      setError("");

      const savedAssessment =
        localStorage.getItem(
          CURRENT_ASSESSMENT_KEY
        );

      if (savedAssessment) {
        const parsedAssessment =
          JSON.parse(savedAssessment);

        setReport(parsedAssessment);

        const savedReassessment =
          localStorage.getItem(
            "threatmodel-current-reassessment"
          );

        if (savedReassessment) {
          try {
            setReassessment(
              JSON.parse(
                savedReassessment
              )
            );
          } catch {
            localStorage.removeItem(
              "threatmodel-current-reassessment"
            );

            setReassessment(null);
          }
        } else {
          setReassessment(null);
        }

        return;
      }

      const [
        reportResponse,
        reassessmentResponse,
      ] = await Promise.all([
        fetch(
          `${API_BASE}/api/demo/banking`
        ),
        fetch(
          `${API_BASE}/api/demo/banking/reassessment`
        ),
      ]);

      if (
        !reportResponse.ok ||
        !reassessmentResponse.ok
      ) {
        throw new Error(
          "ThreatModel API returned an error."
        );
      }

      setReport(
        await reportResponse.json()
      );

      setReassessment(
        await reassessmentResponse.json()
      );
    } catch (err) {
      setError(
        err.message ||
          "Unable to load reports."
      );
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadReports();
  }, []);

  const highestPath = useMemo(() => {
    if (!report?.attack_paths?.length) {
      return null;
    }

    return [...report.attack_paths].sort(
      (a, b) =>
        (b.path_risk || 0) -
        (a.path_risk || 0)
    )[0];
  }, [report]);

  function downloadJson() {
    const blob = new Blob(
      [
        JSON.stringify(
          report,
          null,
          2
        ),
      ],
      {
        type: "application/json",
      }
    );

    const url =
      URL.createObjectURL(blob);

    const anchor =
      document.createElement("a");

    anchor.href = url;

    anchor.download =
      "threatmodel-ai-v2-assessment.json";

    anchor.click();

    URL.revokeObjectURL(url);
  }

  async function exportHtml(
    shouldDownload
  ) {
    if (!report) {
      return;
    }

    const previewWindow =
      shouldDownload
        ? null
        : window.open("", "_blank");

    try {
      setError("");

      const response = await fetch(
        `${API_BASE}/api/assessments/report`,
        {
          method: "POST",
          headers: {
            "Content-Type":
              "application/json",
          },
          body: JSON.stringify(report),
        }
      );

      if (!response.ok) {
        const result =
          await response.json();

        throw new Error(
          result.detail ||
          "Unable to generate HTML report."
        );
      }

      const blob = await response.blob();
      const url =
        URL.createObjectURL(blob);

      if (shouldDownload) {
        const anchor =
          document.createElement("a");

        const architectureName = (
          report.summary?.architecture ||
          "assessment"
        )
          .toLowerCase()
          .replace(/[^a-z0-9]+/g, "-")
          .replace(/^-|-$/g, "");

        anchor.href = url;
        anchor.download =
          `${architectureName}-threat-report.html`;

        anchor.click();

        setTimeout(
          () => URL.revokeObjectURL(url),
          1000
        );
      } else if (previewWindow) {
        previewWindow.location.href = url;
      }
    } catch (err) {
      if (previewWindow) {
        previewWindow.close();
      }

      setError(
        err.message ||
        "Unable to export HTML report."
      );
    }
  }


  const summary =
    report?.summary || {};

  const hasReassessment = Boolean(
    reassessment?.baseline &&
    reassessment?.remediated
  );

  const currentSnapshot = {
    average_control_coverage:
      calculateAverageCoverage(
        report?.attack_paths || []
      ),
    highest_residual_risk:
      calculateHighestResidualRisk(
        report?.attack_paths || []
      ),
    finding_count:
      report?.findings?.length || 0,
  };

  const baseline = hasReassessment
    ? reassessment.baseline
    : currentSnapshot;

  const current = hasReassessment
    ? reassessment.remediated
    : currentSnapshot;

  const comparison =
    reassessment?.comparison || {};

  return (
    <div className="app-shell">
      <Sidebar />

      <main className="main-content page-with-footer">

        <SharedHeader />
        <header className="topbar">
          <div>
            <p className="eyebrow">
              Security Assessment Center
            </p>

            <h1>
              Assessment
              <span> Reports</span>
            </h1>
          </div>

          <button
            className="run-button"
            onClick={loadReports}
          >
            <RefreshCcw size={17} />
            Refresh Reports
          </button>
        </header>

        <section className="architecture-page-hero">
          <div>
            <p className="eyebrow">
              Reporting & Evidence
            </p>

            <h2>
              Security Assessment Outputs
            </h2>

            <p>
              Review executive metrics,
              assessment evidence, remediation
              progress and exportable security
              reports.
            </p>
          </div>

          <div className="architecture-status">
            REPORT CENTER
          </div>
        </section>

        {loading && (
          <div className="state-panel">
            Loading assessment reports…
          </div>
        )}

        {error && (
          <div className="state-panel error">
            <strong>
              Unable to load reports
            </strong>

            <span>{error}</span>
          </div>
        )}

        {!loading &&
          !error &&
          report && (
            <>
              <section className="report-evidence-hero panel">
                <div className="report-evidence-heading">
                  <div>
                    <p className="eyebrow">
                      Assessment Evidence
                    </p>

                    <h2>
                      {summary.architecture || "Cloud Banking Application"}
                    </h2>

                    <p>
                      Consolidated security assessment evidence,
                      remediation outcomes and exportable analysis.
                    </p>
                  </div>

                  <span className="report-ready-badge">
                    REPORT READY
                  </span>
                </div>

                <div className="report-decision-metrics">

                  <div className="report-decision-card danger">
                    <span>Highest Threat Risk</span>
                    <strong>
                      {summary.highest_risk}/25
                    </strong>
                    <small>
                      Highest inherent STRIDE threat risk
                    </small>
                  </div>

                  <div className="report-metric-arrow">
                    →
                  </div>

                  <div className="report-decision-card warning">
                    <span>Attack Path Risk</span>
                    <strong>
                      {highestPath?.path_risk ?? 0}/25
                    </strong>
                    <small>
                      Highest architecture path risk
                    </small>
                  </div>

                  <div className="report-metric-arrow">
                    →
                  </div>

                  <div className="report-decision-card good">
                    <span>Residual Path Risk</span>
                    <strong>
                      {current.highest_residual_risk ?? 0}/25
                    </strong>
                    <small>
                      Estimated after remediation
                    </small>
                  </div>

                </div>
              </section>


              <section className="report-v2-main-grid">

                <article className="panel report-posture-panel">
                  <div className="panel-heading">
                    <div>
                      <p className="eyebrow">
                        Security Posture
                      </p>

                      <h3>
                        {hasReassessment
                          ? "Baseline → Current"
                          : "Current Assessment Snapshot"}
                      </h3>
                    </div>

                    <Activity size={20} />
                  </div>

                  <div className="report-posture-comparison">

                    <div className="report-posture-row">
                      <span>Control Coverage</span>

                      <strong>
                        {baseline.average_control_coverage ?? 0}%
                      </strong>

                      <b>→</b>

                      <strong className="good-text">
                        {current.average_control_coverage ?? 0}%
                      </strong>
                    </div>

                    <div className="report-posture-track">
                      <div
                        className="report-posture-track-fill"
                        style={{
                          width: `${current.average_control_coverage ?? 0}%`,
                        }}
                      />
                    </div>


                    <div className="report-posture-row">
                      <span>Residual Path Risk</span>

                      <strong className="danger-text">
                        {baseline.highest_residual_risk ?? 0}/25
                      </strong>

                      <b>→</b>

                      <strong className="good-text">
                        {current.highest_residual_risk ?? 0}/25
                      </strong>
                    </div>


                    <div className="report-posture-row">
                      <span>Findings</span>

                      <strong>
                        {baseline.finding_count ?? 0}
                      </strong>

                      <b>→</b>

                      <strong className="good-text">
                        {current.finding_count ?? 0}
                      </strong>
                    </div>


                    <div className="report-posture-footer">
                      <div>
                        <span>Risk Change</span>
                        <strong className="good-text">
                          {comparison.risk_change ?? 0}
                        </strong>
                      </div>

                      <div>
                        <span>Coverage Change</span>
                        <strong className="good-text">
                          {(comparison.coverage_change ?? 0) > 0 ? "+" : ""}
                          {comparison.coverage_change ?? 0}%
                        </strong>
                      </div>

                      <div>
                        <span>Trend</span>
                        <strong className="good-text">
                          {hasReassessment
                          ? comparison.trend || "—"
                          : "Not run"}
                        </strong>
                      </div>
                    </div>

                  </div>
                </article>


                <article className="panel report-export-center">
                  <div className="panel-heading">
                    <div>
                      <p className="eyebrow">
                        Export Center
                      </p>

                      <h3>
                        Assessment Package
                      </h3>
                    </div>

                    <Download size={20} />
                  </div>

                  <div className="report-export-actions">

                    <button
                      type="button"
                      className="report-export-action primary"
                      onClick={() => exportHtml(false)}
                    >
                      <div className="report-export-icon">
                        <FileText size={21} />
                      </div>

                      <div>
                        <strong>
                          View HTML Report
                        </strong>

                        <span>
                          Open the complete V2 security assessment
                        </span>
                      </div>

                      <ExternalLink size={17} />
                    </button>


                    <button
                      type="button"
                      className="report-export-action"
                      onClick={() => exportHtml(true)}
                    >
                      <div className="report-export-icon">
                        <Download size={21} />
                      </div>

                      <div>
                        <strong>
                          Download HTML
                        </strong>

                        <span>
                          Portable human-readable assessment evidence
                        </span>
                      </div>

                      <Download size={17} />
                    </button>


                    <button
                      type="button"
                      className="report-export-action"
                      onClick={downloadJson}
                    >
                      <div className="report-export-icon">
                        <FileJson size={21} />
                      </div>

                      <div>
                        <strong>
                          Download JSON
                        </strong>

                        <span>
                          Machine-readable deterministic engine output
                        </span>
                      </div>

                      <Download size={17} />
                    </button>

                  </div>
                </article>

              </section>


              <section className="panel report-evidence-coverage">
                <div className="panel-heading">
                  <div>
                    <p className="eyebrow">
                      Assessment Evidence
                    </p>

                    <h3>
                      Coverage & Navigation
                    </h3>
                  </div>

                  <ShieldCheck size={20} />
                </div>

                <div className="report-evidence-grid">

                  <Link
                    to="/architecture"
                    className="report-evidence-item"
                  >
                    <Network size={18} />

                    <div>
                      <span>Architecture</span>
                      <strong>
                        {summary.components} Components
                      </strong>
                    </div>

                    <b>→</b>
                  </Link>


                  <Link
                    to="/architecture"
                    className="report-evidence-item"
                  >
                    <Route size={18} />

                    <div>
                      <span>Data Flows</span>
                      <strong>
                        {summary.data_flows} Analyzed
                      </strong>
                    </div>

                    <b>→</b>
                  </Link>


                  <Link
                    to="/threats"
                    className="report-evidence-item"
                  >
                    <AlertTriangle size={18} />

                    <div>
                      <span>STRIDE Threats</span>
                      <strong>
                        {summary.threats} Findings
                      </strong>
                    </div>

                    <b>→</b>
                  </Link>


                  <Link
                    to="/attack-paths"
                    className="report-evidence-item"
                  >
                    <Route size={18} />

                    <div>
                      <span>Attack Paths</span>
                      <strong>
                        {summary.attack_paths} Discovered
                      </strong>
                    </div>

                    <b>→</b>
                  </Link>


                  <Link
                    to="/controls"
                    className="report-evidence-item"
                  >
                    <ShieldCheck size={18} />

                    <div>
                      <span>Control Gaps</span>
                      <strong>
                        {highestPath?.control_gaps?.length || 0} Identified
                      </strong>
                    </div>

                    <b>→</b>
                  </Link>


                  <Link
                    to="/findings"
                    className="report-evidence-item"
                  >
                    <FileWarning size={18} />

                    <div>
                      <span>Security Findings</span>
                      <strong>
                        {report.findings?.length || 0} Tracked
                      </strong>
                    </div>

                    <b>→</b>
                  </Link>


                  <Link
                    to="/reassessment"
                    className="report-evidence-item"
                  >
                    <RefreshCcw size={18} />

                    <div>
                      <span>Reassessment</span>
                      <strong>
                        {hasReassessment
                          ? comparison.trend || "—"
                          : "Not run"}
                      </strong>
                    </div>

                    <b>→</b>
                  </Link>


                  <Link
                    to="/architecture"
                    className="report-evidence-item"
                  >
                    <ShieldCheck size={18} />

                    <div>
                      <span>Trust Boundaries</span>
                      <strong>
                        {summary.trust_boundaries} Crossings
                      </strong>
                    </div>

                    <b>→</b>
                  </Link>

                </div>
              </section>


              <section className="panel report-methodology-v2">
                <div>
                  <p className="eyebrow">
                    Methodology & Evidence Statement
                  </p>

                  <h3>
                    Deterministic Architecture Security Analysis
                  </h3>
                </div>

                <div className="report-methodology-layout">

                  <p>
                    ThreatModel AI performs deterministic,
                    architecture-driven security analysis.
                    Threat scenarios are prioritized using
                    likelihood and impact. Attack-path analysis
                    considers exposure, trust boundaries,
                    asset criticality and sensitive-data flows.
                    Declared controls are evaluated to identify
                    control gaps and estimate residual risk.
                  </p>

                  <p>
                    Attack paths represent plausible
                    architecture-level scenarios and do not
                    represent confirmed exploit chains.
                    Residual-risk values are estimates derived
                    from declared control implementation state
                    and effectiveness.
                  </p>

                </div>
              </section>

            </>
          )}

        <Footer />

      </main>
    </div>
  );
}

export default Reports;
