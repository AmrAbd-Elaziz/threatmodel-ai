import {
  useEffect,
  useMemo,
  useState,
} from "react";

import {
  Activity,
  AlertTriangle,
  Boxes,
  Database,
  FileWarning,
  GitBranch,
  LayoutDashboard,
  Network,
  RefreshCcw,
  Route,
  Shield,
  ShieldCheck,
  Waypoints,
  Cloud,
  FileText,
  Globe2,
  KeyRound,
  Server,
  Share2,
  Smartphone,
  UsersRound,
  Workflow,
} from "lucide-react";

import { Link } from "react-router-dom";

import Footer from "./Footer";
import Sidebar from "./Sidebar";
import SharedHeader from "./SharedHeader";

import "./index.css";

const API_BASE = import.meta.env.VITE_API_BASE_URL || "";

const CURRENT_ASSESSMENT_KEY =
  "threatmodel-current-assessment";


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
    ...(
      attackPaths || []
    ).map(
      (path) =>
        path.residual_path_risk ?? 0
    )
  );
}


function getArchitectureIcon(
  componentType
) {
  const icons = {
    client: Smartphone,
    gateway: Server,
    service: UsersRound,
    security_service: KeyRound,
    database: Database,
    storage: Database,
    external_service: Cloud,
  };

  return icons[componentType] || Boxes;
}


function Dashboard() {
const [report, setReport] = useState(null);
  const [remediated, setRemediated] =
    useState(null);

  const [loading, setLoading] =
    useState(true);

  const [error, setError] =
    useState("");

  const [selectedFile, setSelectedFile] =
    useState(null);

  const [assessmentMessage, setAssessmentMessage] =
    useState("");


  async function runUploadedAssessment() {
    if (!selectedFile) {
      setError(
        "Select an architecture YAML or JSON file first."
      );
      return;
    }

    const formData = new FormData();
    formData.append(
      "file",
      selectedFile
    );

    try {
      setLoading(true);
      setError("");
      setAssessmentMessage(
        "Uploading and analyzing architecture…"
      );

      const response = await fetch(
        `${API_BASE}/api/assessments/upload`,
        {
          method: "POST",
          body: formData,
        }
      );

      const result = await response.json();

      if (!response.ok) {
        let message =
          "Unable to analyze architecture.";

        if (typeof result.detail === "string") {
          message = result.detail;
        } else if (
          result.detail?.message
        ) {
          message = result.detail.message;

          if (
            Array.isArray(
              result.detail.errors
            ) &&
            result.detail.errors.length
          ) {
            const firstError =
              result.detail.errors[0];

            message += ` ${
              firstError.field
                ? `${firstError.field}: `
                : ""
            }${firstError.message}`;
          }
        }

        throw new Error(message);
      }

      setReport(result);
      setRemediated(null);

      localStorage.setItem(
        CURRENT_ASSESSMENT_KEY,
        JSON.stringify(result)
      );

      localStorage.removeItem(
        "threatmodel-current-reassessment"
      );

      setAssessmentMessage(
        `Assessment complete: ${
          result.summary?.threats ?? 0
        } threats and ${
          result.findings?.length ?? 0
        } findings identified.`
      );

    } catch (err) {
      setError(
        err.message ||
          "Unable to run assessment."
      );

      setAssessmentMessage("");

    } finally {
      setLoading(false);
    }
  }


  async function loadAssessment() {
    try {
      setLoading(true);
      setError("");

      const [
        baselineResponse,
        remediatedResponse,
      ] = await Promise.all([
        fetch(
          `${API_BASE}/api/demo/banking`
        ),
        fetch(
          `${API_BASE}/api/demo/banking/remediated`
        ),
      ]);

      if (
        !baselineResponse.ok ||
        !remediatedResponse.ok
      ) {
        throw new Error(
          "ThreatModel API returned an error."
        );
      }

      setReport(
        await baselineResponse.json()
      );

      setRemediated(
        await remediatedResponse.json()
      );
    } catch (err) {
      setError(
        err.message ||
          "Unable to connect to ThreatModel API."
      );
    } finally {
      setLoading(false);
    }
  }


  useEffect(() => {
    const savedAssessment =
      localStorage.getItem(
        CURRENT_ASSESSMENT_KEY
      );

    if (savedAssessment) {
      try {
        const parsedAssessment =
          JSON.parse(savedAssessment);

        setReport(parsedAssessment);
        setRemediated(null);

        setAssessmentMessage(
          `Current assessment restored: ${
            parsedAssessment.summary?.threats ??
            0
          } threats and ${
            parsedAssessment.findings?.length ??
            0
          } findings identified.`
        );

        setLoading(false);
        return;
      } catch {
        localStorage.removeItem(
          CURRENT_ASSESSMENT_KEY
        );
      }
    }

    loadAssessment();
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


  const remediatedHighestPath =
    useMemo(() => {
      if (
        !remediated?.attack_paths?.length
      ) {
        return null;
      }

      return [
        ...remediated.attack_paths,
      ].sort(
        (a, b) =>
          (b.path_risk || 0) -
          (a.path_risk || 0)
      )[0];
    }, [remediated]);


  const summary =
    report?.summary || {};

  const threats =
    report?.threats || [];

  const findings =
    report?.findings || [];

  const attackPaths =
    report?.attack_paths || [];


  const baselineCoverage =
    calculateAverageCoverage(
      attackPaths
    );

  const baselineResidual =
    calculateHighestResidualRisk(
      attackPaths
    );

  const remediatedAttackPaths =
    remediated?.attack_paths || [];

  const hasRemediatedAssessment =
    remediatedAttackPaths.length > 0;

  const currentCoverage =
    hasRemediatedAssessment
      ? calculateAverageCoverage(
          remediatedAttackPaths
        )
      : null;

  const currentResidual =
    hasRemediatedAssessment
      ? calculateHighestResidualRisk(
          remediatedAttackPaths
        )
      : null;


  const openFindings =
    findings.filter(
      (finding) =>
        !finding.status ||
        finding.status.toLowerCase() !==
          "resolved"
    ).length;


  const strideCategories = [
    "Spoofing",
    "Tampering",
    "Repudiation",
    "Information Disclosure",
    "Denial of Service",
    "Elevation of Privilege",
  ];


  const strideColors = {
    Spoofing: "#2f86df",
    Tampering: "#6658e8",
    Repudiation: "#d24b72",
    "Information Disclosure":
      "#f17b42",
    "Denial of Service":
      "#f2a51d",
    "Elevation of Privilege":
      "#31b875",
  };


  const strideDistribution =
    useMemo(() => {
      const result = {};

      strideCategories.forEach(
        (category) => {
          result[category] = 0;
        }
      );

      threats.forEach((threat) => {
        result[threat.category] =
          (result[threat.category] || 0) +
          1;
      });

      return result;
    }, [threats]);


  const riskMatrix =
    useMemo(() => {
      const matrix = {};

      threats.forEach((threat) => {
        const key =
          `${threat.likelihood}-${threat.impact}`;

        matrix[key] =
          (matrix[key] || 0) + 1;
      });

      return matrix;
    }, [threats]);


  const donutGradient =
    useMemo(() => {
      if (!threats.length) {
        return "#1b2530";
      }

      let start = 0;

      const segments =
        strideCategories
          .filter(
            (category) =>
              strideDistribution[
                category
              ] > 0
          )
          .map((category) => {
            const count =
              strideDistribution[
                category
              ];

            const end =
              start +
              (count /
                threats.length) *
                100;

            const segment =
              `${strideColors[category]} ` +
              `${start}% ${end}%`;

            start = end;

            return segment;
          });

      return (
        `conic-gradient(` +
        segments.join(", ") +
        `)`
      );
    }, [
      strideDistribution,
      threats.length,
    ]);


  function getMatrixClass(
    likelihood,
    impact
  ) {
    const score =
      likelihood * impact;

    if (score >= 20) {
      return "dashboard-matrix-critical";
    }

    if (score >= 15) {
      return "dashboard-matrix-high";
    }

    if (score >= 10) {
      return "dashboard-matrix-medium";
    }

    return "dashboard-matrix-low";
  }


  return (
    <div className="app-shell">

      <Sidebar />


      <main className="main-content dashboard-v3 page-with-footer">

        <div className="dashboard-unified-hero">

        <SharedHeader />

        <section className="dashboard-assessment-runner">

          <label
            className="dashboard-file-picker"
            htmlFor="architecture-file"
          >
            <FileText size={17} />

            <span>
              {selectedFile?.name ||
                report?.source?.filename ||
                "Select architecture file"}
            </span>

            <small>YAML / YML / JSON</small>
          </label>

          <input
            id="architecture-file"
            className="dashboard-file-input"
            type="file"
            accept=".yaml,.yml,.json,application/json,application/x-yaml,text/yaml"
            onChange={(event) => {
              const file =
                event.target.files?.[0] ||
                null;

              setSelectedFile(file);
              setError("");
              setAssessmentMessage("");
            }}
          />

          <button
            type="button"
            className="run-button dashboard-assessment-button"
            onClick={runUploadedAssessment}
            disabled={
              !selectedFile || loading
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
              ? "Analyzing…"
              : "Run Assessment"}
          </button>

          {assessmentMessage && (
            <div className="assessment-success-message">
              {assessmentMessage}
            </div>
          )}

        </section>

        <section className="dashboard-welcome-hero">

          <div className="dashboard-welcome-copy">

            <h1>
              Welcome to ThreatModel <span>AI</span>
            </h1>

            <p>
              ARCHITECTURE-DRIVEN THREAT MODELING
              <b>•</b>
              ATTACK PATH ANALYSIS
              <b>•</b>
              CONTROL ASSESSMENT
              <b>•</b>
              CONTINUOUS SECURITY REVIEW
            </p>

          </div>


          <div className="dashboard-welcome-statement">
            <span>TURN</span>
            <span>ARCHITECTURE</span>
            <span>INTO SECURITY</span>
            <i />
          </div>

        </section>

        </div>


        {loading && (
          <div className="state-panel">
            Loading security assessment…
          </div>
        )}


        {error && (
          <div className="state-panel error">
            <strong>
              Unable to load assessment
            </strong>

            <span>{error}</span>
          </div>
        )}


        {!loading &&
          !error &&
          report && (
            <>

              {/* KPI ROW */}

              <section className="dashboard-v3-kpis">

                <article className="dashboard-v3-kpi">
                  <div className="dashboard-v3-kpi-icon cyan">
                    <Network size={25} strokeWidth={2} />
                  </div>

                  <div>
                    <strong>
                      {summary.components}
                    </strong>

                    <span>
                      Components
                    </span>

                    <small>
                      From architecture
                    </small>
                  </div>
                </article>


                <article className="dashboard-v3-kpi">
                  <div className="dashboard-v3-kpi-icon blue">
                    <Workflow size={25} strokeWidth={2} />
                  </div>

                  <div>
                    <strong>
                      {summary.data_flows}
                    </strong>

                    <span>
                      Data Flows
                    </span>

                    <small>
                      Across trust zones
                    </small>
                  </div>
                </article>


                <article className="dashboard-v3-kpi">
                  <div className="dashboard-v3-kpi-icon green">
                    <ShieldCheck size={25} strokeWidth={2} />
                  </div>

                  <div>
                    <strong>
                      {summary.threats}
                    </strong>

                    <span>
                      Threats Identified
                    </span>

                    <small>
                      STRIDE analysis
                    </small>
                  </div>
                </article>


                <article className="dashboard-v3-kpi">
                  <div className="dashboard-v3-kpi-icon purple">
                    <Share2 size={25} strokeWidth={2} />
                  </div>

                  <div>
                    <strong>
                      {attackPaths.length}
                    </strong>

                    <span>
                      Attack Paths
                    </span>

                    <small>
                      Security scenarios
                    </small>
                  </div>
                </article>


                <article className="dashboard-v3-kpi">
                  <div className="dashboard-v3-kpi-icon red">
                    <FileText size={25} strokeWidth={2} />
                  </div>

                  <div>
                    <strong>
                      {openFindings}
                    </strong>

                    <span>
                      Open Findings
                    </span>

                    <small>
                      Remediation required
                    </small>
                  </div>
                </article>


                <article className="dashboard-v3-kpi coverage">

                  <div
                    className="dashboard-v3-coverage-ring"
                    style={{
                      background:
                        `conic-gradient(` +
                        `#61d7ff 0 ${baselineCoverage * 0.58}%, ` +
                        `#20b96b ${baselineCoverage * 0.58}% ${baselineCoverage}%, ` +
                        `#202a33 ${baselineCoverage}% 100%)`,
                    }}
                  >
                    <div />
                  </div>

                  <div>
                    <strong>
                      {baselineCoverage}%
                    </strong>

                    <span>
                      Control Coverage
                    </span>

                    <small>
                      Baseline assessment
                    </small>
                  </div>

                </article>

              </section>


              {/* MAIN ROW */}

              <section className="dashboard-v3-main">


                {/* SYSTEM ARCHITECTURE */}

                <article className="panel dashboard-v3-architecture">

                  <div className="dashboard-v3-panel-heading">

                    <div>
                      <h2>
                        System Architecture
                      </h2>

                      <p>
                        {summary.architecture}
                        {" "}· Simplified View
                      </p>
                    </div>


                    <Link
                      to="/architecture"
                      className="dashboard-v3-link"
                    >
                      View Details →
                    </Link>

                  </div>


                  <div className="dashboard-v3-architecture-canvas dashboard-dynamic-canvas">

                    <div className="dashboard-dynamic-components">

                      {report.architecture?.components?.map(
                        (component) => {
                          const Icon =
                            getArchitectureIcon(
                              component.type
                            );

                          const isCritical =
                            component.criticality ===
                              "critical" ||
                            component.criticality ===
                              "high";

                          return (
                            <article
                              key={component.id}
                              className={`dashboard-dynamic-node ${
                                isCritical
                                  ? "critical"
                                  : ""
                              }`}
                            >
                              <div className="dashboard-dynamic-node-icon">
                                <Icon
                                  size={21}
                                  strokeWidth={1.9}
                                />
                              </div>

                              <div>
                                <strong>
                                  {component.name}
                                </strong>

                                <span>
                                  {component.type
                                    .replaceAll(
                                      "_",
                                      " "
                                    )}
                                </span>
                              </div>

                              <small>
                                {component.trust_zone}
                              </small>
                            </article>
                          );
                        }
                      )}

                    </div>


                    <div className="dashboard-dynamic-flows">

                      {report.architecture?.data_flows?.map(
                        (flow) => (
                          <div
                            key={flow.id}
                            className={`dashboard-flow-item ${
                              !flow.encrypted ||
                              !flow.authentication ||
                              !flow.authorization_required
                                ? "insecure"
                                : ""
                            }`}
                          >
                            <span>
                              {flow.source}
                            </span>

                            <b>→</b>

                            <span>
                              {flow.destination}
                            </span>

                            <small>
                              {flow.protocol}
                            </small>
                          </div>
                        )
                      )}

                    </div>

                  </div>


                  <div className="dashboard-zone-legend">

                    <span>
                      <i className="zone-blue" />
                      Internet Zone
                    </span>

                    <span>
                      <i className="zone-orange" />
                      DMZ
                    </span>

                    <span>
                      <i className="zone-app" />
                      Application Zone
                    </span>

                    <span>
                      <i className="zone-red" />
                      Data Zone
                    </span>

                    <span>
                      <i className="zone-gray" />
                      External
                    </span>

                  </div>

                </article>


                {/* RIGHT COLUMN */}

                <div className="dashboard-v3-right">


                  {/* ATTACK PATH */}

                  <article className="panel dashboard-v3-risk">

                    <div className="dashboard-v3-panel-heading">

                      <h2>
                        Highest Risk Attack Path
                      </h2>

                      <div className="critical-badge">
                        CRITICAL
                      </div>

                    </div>


                    {highestPath && (
                      <>

                        <div className="dashboard-v3-path-chain">

                          {highestPath.nodes.map(
                            (node, index) => (
                              <div
                                key={node}
                                className="dashboard-v3-path-node"
                              >

                                <span>
                                  {node}
                                </span>

                                {index <
                                  highestPath.nodes
                                    .length -
                                    1 && (
                                  <b>→</b>
                                )}

                              </div>
                            )
                          )}

                        </div>


                        <div className="dashboard-v3-risk-body">

                          <div className="dashboard-v3-risk-score">

                            <strong>
                              {highestPath.path_risk}
                            </strong>

                            <span>/25</span>

                            <small>
                              Inherent Risk
                            </small>


                            <div>
                              <i
                                style={{
                                  width:
                                    `${
                                      (
                                        highestPath.path_risk /
                                        25
                                      ) *
                                      100
                                    }%`,
                                }}
                              />
                            </div>

                          </div>


                          <div className="dashboard-v3-risk-factors">

                            <h4>
                              Key Risk Factors
                            </h4>

                            <p>
                              <AlertTriangle size={13} />
                              Internet-accessible entry point
                            </p>

                            <p>
                              <AlertTriangle size={13} />
                              Sensitive data access
                            </p>

                            <p>
                              <AlertTriangle size={13} />
                              Multiple trust-boundary crossings
                            </p>

                            <p>
                              <AlertTriangle size={13} />
                              Missing or partial controls
                            </p>

                          </div>

                        </div>

                      </>
                    )}

                  </article>


                  {/* MATRIX + DISTRIBUTION */}

                  <article className="panel dashboard-v3-analysis">

                    <div className="dashboard-v3-panel-heading">

                      <h2>
                        Risk Matrix
                      </h2>

                      <Link
                        to="/threats"
                        className="dashboard-v3-link"
                      >
                        View Full Analysis →
                      </Link>

                    </div>


                    <div className="dashboard-v3-analysis-grid">


                      <div className="dashboard-v3-matrix-wrap">

                        <div className="dashboard-v3-matrix">

                          {[5, 4, 3, 2, 1].map(
                            (impact) =>
                              [
                                1,
                                2,
                                3,
                                4,
                                5,
                              ].map(
                                (likelihood) => {

                                  const key =
                                    `${likelihood}-${impact}`;

                                  const count =
                                    riskMatrix[
                                      key
                                    ] || 0;

                                  return (
                                    <div
                                      key={key}
                                      className={
                                        "dashboard-matrix-cell " +
                                        getMatrixClass(
                                          likelihood,
                                          impact
                                        )
                                      }
                                    >
                                      {count >
                                        0 && (
                                        <b>
                                          {
                                            count
                                          }
                                        </b>
                                      )}
                                    </div>
                                  );
                                }
                              )
                          )}

                        </div>

                        <div className="dashboard-matrix-axis">
                          Likelihood
                        </div>

                      </div>


                      <div className="dashboard-v3-distribution">

                        <h3>
                          Threat Distribution
                        </h3>


                        <div className="dashboard-v3-distribution-body">


                          <div
                            className="dashboard-v3-donut"
                            style={{
                              background:
                                donutGradient,
                            }}
                          >

                            <div>
                              {threats.length}
                            </div>

                          </div>


                          <div className="dashboard-v3-stride-list">

                            {strideCategories.map(
                              (category) => (
                                <div key={category}>

                                  <span
                                    style={{
                                      background:
                                        strideColors[
                                          category
                                        ],
                                    }}
                                  />

                                  <p>
                                    {category}
                                  </p>

                                  <b>
                                    {
                                      strideDistribution[
                                        category
                                      ]
                                    }
                                  </b>

                                </div>
                              )
                            )}

                          </div>

                        </div>

                      </div>

                    </div>

                  </article>

                </div>

              </section>


              {/* BOTTOM ROW */}

              <section className="dashboard-v3-bottom">


                {/* ASSESSMENT COMPARISON */}

                <article className="panel dashboard-v3-comparison">

                  <div className="dashboard-v3-panel-heading">

                    <div>
                      <h2>
                        {hasRemediatedAssessment
                          ? "Assessment Comparison"
                          : "Current Assessment Snapshot"}
                      </h2>

                      <p>
                        {hasRemediatedAssessment
                          ? "Track your security posture over time"
                          : "Current uploaded architecture security posture"}
                      </p>
                    </div>

                    <Link
                      to={
                        hasRemediatedAssessment
                          ? "/reassessment"
                          : "/findings"
                      }
                      className="dashboard-v3-link"
                    >
                      {hasRemediatedAssessment
                        ? "View History →"
                        : "Review Findings →"}
                    </Link>

                  </div>


                  <div className="dashboard-v3-comparison-grid">

                    <div>
                      <span>
                        Control Coverage
                      </span>

                      <section>
                        <strong>
                          {baselineCoverage}%
                        </strong>

                        {hasRemediatedAssessment && (
                          <>
                            <b>→</b>

                            <strong className="good">
                              {currentCoverage}%
                            </strong>
                          </>
                        )}
                      </section>

                      <small>
                        {hasRemediatedAssessment
                          ? "Baseline → Remediated"
                          : "Average across attack paths"}
                      </small>
                    </div>


                    <div>
                      <span>
                        Highest Residual Risk
                      </span>

                      <section>
                        <strong>
                          {baselineResidual}/25
                        </strong>

                        {hasRemediatedAssessment && (
                          <>
                            <b>→</b>

                            <strong className="good">
                              {currentResidual}/25
                            </strong>
                          </>
                        )}
                      </section>

                      <small>
                        {hasRemediatedAssessment
                          ? "Baseline → Remediated"
                          : "Current residual exposure"}
                      </small>
                    </div>


                    <div>
                      <span>
                        Open Findings
                      </span>

                      <section>
                        <strong>
                          {openFindings}
                        </strong>

                        {hasRemediatedAssessment && (
                          <>
                            <b>→</b>

                            <strong className="good">
                              {
                                remediated.findings
                                  ?.filter(
                                    (finding) =>
                                      !finding.status ||
                                      finding.status
                                        .toLowerCase() !==
                                        "resolved"
                                  )
                                  .length ?? 0
                              }
                            </strong>
                          </>
                        )}
                      </section>

                      <small>
                        {hasRemediatedAssessment
                          ? "Baseline → Remediated"
                          : "Requires remediation"}
                      </small>
                    </div>

                  </div>

                </article>


                {/* RECENT FINDINGS */}

                <article className="panel dashboard-v3-findings">

                  <div className="dashboard-v3-panel-heading">

                    <h2>
                      Recent Findings
                    </h2>


                    <Link
                      to="/findings"
                      className="dashboard-v3-link"
                    >
                      View All →
                    </Link>

                  </div>


                  <div className="dashboard-v3-findings-table">


                    <div className="dashboard-v3-findings-row head">

                      <span>ID</span>
                      <span>Control</span>
                      <span>Status</span>
                      <span>Owner</span>
                      <span>SLA</span>

                    </div>


                    {findings
                      .slice(0, 4)
                      .map((finding) => (
                        <div
                          className="dashboard-v3-findings-row"
                          key={finding.id}
                        >

                          <span>
                            {finding.id}
                          </span>

                          <strong>
                            {
                              finding.control_name
                            }
                          </strong>

                          <b className="dashboard-status open">
                            {
                              finding.status ||
                              "Open"
                            }
                          </b>

                          <span>
                            {finding.owner}
                          </span>

                          <span>
                            {
                              finding.sla_days
                                ? `${finding.sla_days} days`
                                : "—"
                            }
                          </span>

                        </div>
                      ))}

                  </div>

                </article>

              </section>

            </>
          )}

        <Footer />

      </main>
</div>
  );
}

export default Dashboard;
