import { useEffect, useState } from "react";
import { Link } from "react-router-dom";

import {
  Activity,
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  FileWarning,
  FileText,
  LayoutDashboard,
  Network,
  RefreshCcw,
  Route,
  ShieldCheck,
} from "lucide-react";

import Footer from "./Footer";
import Sidebar from "./Sidebar";
import SharedHeader from "./SharedHeader";

import { getCurrentAssessment } from "./assessmentStore";

import "./index.css";

const API_BASE = import.meta.env.VITE_API_BASE_URL || "";

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

function Reassessment() {
  const [data, setData] = useState(null);
  const [currentReport, setCurrentReport] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const [
    remediatedFile,
    setRemediatedFile,
  ] = useState(null);

  const [
    reassessmentMessage,
    setReassessmentMessage,
  ] = useState("");

  const [
    selectedLifecycle,
    setSelectedLifecycle,
  ] = useState("ALL");

  async function runReassessment() {
    const baselineReport =
      getCurrentAssessment();

    if (!baselineReport) {
      setError(
        "Run a baseline assessment from the Dashboard first."
      );
      return;
    }

    if (!remediatedFile) {
      setError(
        "Select a remediated YAML or JSON file first."
      );
      return;
    }

    const formData = new FormData();

    formData.append(
      "file",
      remediatedFile
    );

    try {
      setLoading(true);
      setError("");
      setReassessmentMessage(
        "Analyzing remediated architecture…"
      );

      const uploadResponse = await fetch(
        `${API_BASE}/api/assessments/upload`,
        {
          method: "POST",
          body: formData,
        }
      );

      const remediatedReport =
        await uploadResponse.json();

      if (!uploadResponse.ok) {
        throw new Error(
          typeof remediatedReport.detail ===
          "string"
            ? remediatedReport.detail
            : remediatedReport.detail
                ?.message ||
              "Unable to analyze remediated architecture."
        );
      }

      const comparisonResponse =
        await fetch(
          `${API_BASE}/api/assessments/reassessment`,
          {
            method: "POST",
            headers: {
              "Content-Type":
                "application/json",
            },
            body: JSON.stringify({
              baseline: baselineReport,
              remediated:
                remediatedReport,
            }),
          }
        );

      const comparisonResult =
        await comparisonResponse.json();

      if (!comparisonResponse.ok) {
        throw new Error(
          comparisonResult.detail ||
          "Unable to compare assessments."
        );
      }

      localStorage.setItem(
        "threatmodel-current-reassessment",
        JSON.stringify(
          comparisonResult
        )
      );

      localStorage.setItem(
        "threatmodel-current-assessment",
        JSON.stringify(
          remediatedReport
        )
      );

      setData(comparisonResult);
      setCurrentReport(
        remediatedReport
      );

      setSelectedLifecycle("ALL");

      setReassessmentMessage(
        `Reassessment complete: ${
          comparisonResult
            .finding_lifecycle
            ?.Resolved ?? 0
        } resolved, ${
          comparisonResult
            .finding_lifecycle
            ?.[
              "Still Open"
            ] ?? 0
        } still open.`
      );
    } catch (err) {
      setError(
        err.message ||
        "Unable to run reassessment."
      );

      setReassessmentMessage("");
    } finally {
      setLoading(false);
    }
  }


  async function loadReassessment() {
    try {
      setLoading(true);
      setError("");

      const currentAssessment =
        getCurrentAssessment();

      if (currentAssessment) {
        setCurrentReport(
          currentAssessment
        );

        const savedReassessment =
          localStorage.getItem(
            "threatmodel-current-reassessment"
          );

        if (savedReassessment) {
          try {
            setData(
              JSON.parse(
                savedReassessment
              )
            );
          } catch {
            localStorage.removeItem(
              "threatmodel-current-reassessment"
            );

            setData(null);
          }
        } else {
          setData(null);
        }

        return;
      }

      const [
        reassessmentResponse,
        currentResponse,
      ] = await Promise.all([
        fetch(
          `${API_BASE}/api/demo/banking/reassessment`
        ),
        fetch(
          `${API_BASE}/api/demo/banking`
        ),
      ]);

      if (
        !reassessmentResponse.ok ||
        !currentResponse.ok
      ) {
        throw new Error(
          "ThreatModel API returned an error."
        );
      }

      const [
        reassessmentData,
        currentData,
      ] = await Promise.all([
        reassessmentResponse.json(),
        currentResponse.json(),
      ]);

      setData(reassessmentData);
      setCurrentReport(currentData);
    } catch (err) {
      setError(
        err.message ||
          "Unable to load reassessment."
      );
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadReassessment();
  }, []);

  const currentSummary =
    currentReport?.summary || {};

  const baseline = data?.baseline || {};
  const current = data?.remediated || {};
  const comparison = data?.comparison || {};
  const lifecycle =
    data?.finding_lifecycle || {};
  const reconciliation =
    data?.reconciliation || [];

  const displayedReconciliation =
    selectedLifecycle === "ALL"
      ? reconciliation
      : reconciliation.filter(
          (item) =>
            item.state === selectedLifecycle
        );

  return (
    <div className="app-shell">
      <Sidebar />

      <main className="main-content page-with-footer">

        <SharedHeader />
        <header className="topbar reassessment-platform-topbar">
          <div>
            <p className="eyebrow">
              Security Validation
            </p>

            <h1>
              Reassessment <span>Center</span>
            </h1>
          </div>

          <div className="reassessment-upload-actions">
            <label
              className="reassessment-file-picker"
              htmlFor="remediated-file"
            >
              <FileText size={17} />

              <span>
                {remediatedFile?.name ||
                  "Select remediated file"}
              </span>

              <small>
                YAML / YML / JSON
              </small>
            </label>

            <input
              id="remediated-file"
              className="reassessment-file-input"
              type="file"
              accept=".yaml,.yml,.json,application/json,application/x-yaml,text/yaml"
              onChange={(event) => {
                setRemediatedFile(
                  event.target.files?.[0] ||
                  null
                );

                setError("");
                setReassessmentMessage("");
              }}
            />

            <button
              type="button"
              className="run-button"
              onClick={runReassessment}
              disabled={
                !remediatedFile ||
                loading
              }
            >
              <RefreshCcw
                size={17}
                className={
                  loading
                    ? "assessment-spinner"
                    : ""
                }
              />

              {loading
                ? "Comparing…"
                : "Run Reassessment"}
            </button>
          </div>
        </header>

        <section className="architecture-page-hero">
          <div>
            <p className="eyebrow">
              Assessment Comparison
            </p>

            <h2>
              Baseline vs Remediated State
            </h2>

            <p>
              Validate remediation outcomes by comparing residual risk, control coverage and finding lifecycle between assessment snapshots.
            </p>
          </div>

          <div className="architecture-status">
            CONTINUOUS REVIEW
          </div>
        </section>

        {reassessmentMessage && (
          <div className="assessment-success-message reassessment-success">
            {reassessmentMessage}
          </div>
        )}

        {!loading && !error && currentReport && (
          <section className="reassessment-current-context">
            <div className="reassessment-current-heading">
              <p className="eyebrow">
                Assessment Context
              </p>

              <h2>
                {
                  currentSummary.architecture ||
                  "Cloud Banking Application"
                }
              </h2>
            </div>

            <div className="reassessment-current-grid">

              <div className="reassessment-current-card">
                <Network size={19} />
                <span>Components</span>
                <strong>
                  {currentSummary.components ?? 0}
                </strong>
                <small>Architecture assets</small>
              </div>

              <div className="reassessment-current-card">
                <Route size={19} />
                <span>Data Flows</span>
                <strong>
                  {currentSummary.data_flows ?? 0}
                </strong>
                <small>Application flows</small>
              </div>

              <div className="reassessment-current-card">
                <ShieldCheck size={19} />
                <span>Trust Boundaries</span>
                <strong>
                  {
                    currentSummary
                      .trust_boundaries ?? 0
                  }
                </strong>
                <small>Security zones</small>
              </div>

              <div className="reassessment-current-card">
                <AlertTriangle size={19} />
                <span>Threats</span>
                <strong>
                  {currentSummary.threats ?? 0}
                </strong>
                <small>STRIDE findings</small>
              </div>

              <div className="reassessment-current-card danger">
                <AlertTriangle size={19} />
                <span>Highest Threat Risk</span>
                <strong>
                  {
                    currentSummary.highest_risk ??
                    0
                  }/25
                </strong>
                <small>Threat risk</small>
              </div>

              <div className="reassessment-current-card danger">
                <FileWarning size={19} />
                <span>P1 Threats</span>
                <strong>
                  {
                    currentSummary.priorities
                      ?.P1 ?? 0
                  }
                </strong>
                <small>Critical priority</small>
              </div>

            </div>
          </section>
        )}



        {loading && (
          <div className="state-panel">
            Loading reassessment…
          </div>
        )}

        {error && (
          <div className="state-panel error">
            <strong>
              Unable to load reassessment
            </strong>

            <span>{error}</span>
          </div>
        )}

        {!loading && !error && data && (
          <>
            <section className="reassessment-stage-grid">
              <article className="assessment-stage baseline">
                <p className="eyebrow">
                  Baseline
                </p>

                <h3>A-001</h3>

                <div className="stage-metrics">
                  <div>
                    <span>
                      Control Coverage
                    </span>

                    <strong>
                      {
                        baseline.average_control_coverage
                      }
                      %
                    </strong>
                  </div>

                  <div>
                    <span>
                      Residual Risk
                    </span>

                    <strong>
                      {
                        baseline.highest_residual_risk
                      }
                      /25
                    </strong>
                  </div>

                  <div>
                    <span>
                      Findings
                    </span>

                    <strong>
                      {baseline.finding_count}
                    </strong>
                  </div>
                </div>
              </article>

              <div className="assessment-arrow">
                <ArrowRight size={30} />

                <span>
                  Remediation
                </span>
              </div>

              <article className="assessment-stage remediated">
                <p className="eyebrow">
                  Current
                </p>

                <h3>A-002</h3>

                <div className="stage-metrics">
                  <div>
                    <span>
                      Control Coverage
                    </span>

                    <strong>
                      {
                        current.average_control_coverage
                      }
                      %
                    </strong>
                  </div>

                  <div>
                    <span>
                      Residual Risk
                    </span>

                    <strong>
                      {
                        current.highest_residual_risk
                      }
                      /25
                    </strong>
                  </div>

                  <div>
                    <span>
                      Findings
                    </span>

                    <strong>
                      {current.finding_count}
                    </strong>
                  </div>
                </div>
              </article>
            </section>

            <section className="reassessment-summary-grid">
              <div className="reassessment-summary-card good">
                <span>
                  Coverage Change
                </span>

                <strong>
                  {comparison.coverage_change > 0
                    ? "+"
                    : ""}
                  {
                    comparison.coverage_change
                  }
                  %
                </strong>

                <small>
                  Improved control posture
                </small>
              </div>

              <div className="reassessment-summary-card good">
                <span>
                  Risk Change
                </span>

                <strong>
                  {
                    comparison.risk_change
                  }
                </strong>

                <small>
                  Residual-risk reduction
                </small>
              </div>

              <div className="reassessment-summary-card">
                <span>Trend</span>

                <strong>
                  {comparison.trend}
                </strong>

                <small>
                  Assessment comparison
                </small>
              </div>

              <div className="reassessment-summary-card">
                <span>
                  Resolved
                </span>

                <strong>
                  {lifecycle.Resolved || 0}
                </strong>

                <small>
                  Closed gaps
                </small>
              </div>

              <div className="reassessment-summary-card">
                <span>
                  Still Open
                </span>

                <strong>
                  {
                    lifecycle[
                      "Still Open"
                    ] || 0
                  }
                </strong>

                <small>
                  Remaining findings
                </small>
              </div>
            </section>

            <section className="reassessment-main-grid">
              <article className="panel">
                <div className="panel-heading">
                  <div>
                    <p className="eyebrow">
                      Risk Trend
                    </p>

                    <h3>
                      Residual Risk Reduction
                    </h3>
                  </div>

                  <RefreshCcw size={20} />
                </div>

                <div className="risk-change-visual">
                  <div className="risk-stage">
                    <span>A-001</span>

                    <strong className="danger-text">
                      {
                        baseline.highest_residual_risk
                      }
                      /25
                    </strong>

                    <small>
                      Baseline
                    </small>
                  </div>

                  <div className="risk-change-line">
                    <div
                      className="risk-change-fill"
                      style={{
                        width: "100%",
                      }}
                    />

                    <ArrowRight size={24} />
                  </div>

                  <div className="risk-stage">
                    <span>A-002</span>

                    <strong className="good-text">
                      {
                        current.highest_residual_risk
                      }
                      /25
                    </strong>

                    <small>
                      After remediation
                    </small>
                  </div>
                </div>
              </article>

              <article className="panel">
                <div className="panel-heading">
                  <div>
                    <p className="eyebrow">
                      Control Improvement
                    </p>

                    <h3>
                      Coverage Increase
                    </h3>
                  </div>

                  <ShieldCheck size={20} />
                </div>

                <div className="coverage-comparison">
                  <div>
                    <span>
                      A-001 Baseline
                    </span>

                    <strong>
                      {
                        baseline.average_control_coverage
                      }
                      %
                    </strong>

                    <div className="coverage-track">
                      <div
                        className="coverage-fill baseline-fill"
                        style={{
                          width: `${baseline.average_control_coverage}%`,
                        }}
                      />
                    </div>
                  </div>

                  <div>
                    <span>
                      A-002 Remediated
                    </span>

                    <strong className="good-text">
                      {
                        current.average_control_coverage
                      }
                      %
                    </strong>

                    <div className="coverage-track">
                      <div
                        className="coverage-fill"
                        style={{
                          width: `${current.average_control_coverage}%`,
                        }}
                      />
                    </div>
                  </div>
                </div>
              </article>
            </section>

            <section className="panel">
              <div className="panel-heading">
                <div>
                  <p className="eyebrow">
                    Finding Lifecycle
                  </p>

                  <h3>
                    Reconciliation
                  </h3>
                </div>

                <CheckCircle2 size={20} />
              </div>

              <div className="lifecycle-summary">
                {[
                  "Resolved",
                  "Still Open",
                  "New",
                  "Reopened",
                ].map((state) => (
                  <button
                    type="button"
                    key={state}
                    className={
                      `lifecycle-card ` +
                      state
                        .toLowerCase()
                        .replace(" ", "-") +
                      (
                        selectedLifecycle === state
                          ? " selected"
                          : ""
                      )
                    }
                    onClick={() =>
                      setSelectedLifecycle(
                        selectedLifecycle === state
                          ? "ALL"
                          : state
                      )
                    }
                  >
                    <span>{state}</span>

                    <strong>
                      {lifecycle[state] || 0}
                    </strong>

                    <small>
                      {selectedLifecycle === state
                        ? "Showing filtered results"
                        : "Click to filter"}
                    </small>
                  </button>
                ))}
              </div>

              <div className="reconciliation-table">
                <div className="reconciliation-row table-head">
                  <span>Finding</span>
                  <span>Control</span>
                  <span>Asset</span>
                  <span>Lifecycle</span>
                </div>

                {displayedReconciliation.map(
                  (item) => (
                    <div
                      className="reconciliation-row"
                      key={item.finding_id}
                    >
                      <Link
                        to={`/findings?finding=${encodeURIComponent(
                          item.finding_id
                        )}`}
                        className="reassessment-object-link"
                      >
                        {item.finding_id}
                      </Link>

                      <Link
                        to={`/controls?control=${encodeURIComponent(
                          item.control_id
                        )}`}
                        className="reassessment-object-link control"
                      >
                        {item.control_id}
                        <span>
                          {item.control_name}
                        </span>
                      </Link>

                      <span>
                        {item.asset}
                      </span>

                      <span
                        className={
                          `lifecycle-status ` +
                          item.state
                            .toLowerCase()
                            .replace(
                              " ",
                              "-"
                            )
                        }
                      >
                        {item.state}
                      </span>
                    </div>
                  )
                )}
              </div>
            </section>

            <p className="attack-disclaimer">
              Reassessment compares declared
              architecture and control state
              between snapshots. Residual risk
              remains an estimate and does not
              represent validated production
              effectiveness.
            </p>
          </>
        )}

        <Footer />

      </main>
    </div>
  );
}

export default Reassessment;
