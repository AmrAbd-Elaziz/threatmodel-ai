import { useEffect, useMemo, useRef, useState } from "react";

import {
  Link,
  useSearchParams,
} from "react-router-dom";

import {
  Activity,
  AlertTriangle,
  Bug as ThreatPathIcon,
  ChartPie as CoverageIcon,
  Database as AttackDatabaseIcon,
  FileWarning,
  Globe2 as AttackEntryIcon,
  LayoutDashboard,
  Network,
  Network as BoundaryIcon,
  RefreshCcw,
  Route,
  Server as AttackServiceIcon,
  ShieldCheck,
  ShieldCheck as ResidualRiskIcon,
  TriangleAlert as AttackRiskIcon,
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

function AttackPaths() {
  const metricDetailRef = useRef(null);
  const nodeDetailRef = useRef(null);

  const [searchParams] = useSearchParams();

  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  async function loadAttackPaths() {
    try {
      setLoading(true);
      setError("");

      const currentAssessment =
        getCurrentAssessment();

      if (currentAssessment) {
        setReport(currentAssessment);
        return;
      }

      const response = await fetch(
        `${API_BASE}/api/demo/banking`
      );

      if (!response.ok) {
        throw new Error(
          "ThreatModel API returned an error."
        );
      }

      setReport(await response.json());
    } catch (err) {
      setError(
        err.message ||
          "Unable to load attack paths."
      );
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadAttackPaths();
  }, []);

  const attackPaths = useMemo(() => {
    if (!report?.attack_paths) {
      return [];
    }

    return [...report.attack_paths].sort(
      (a, b) =>
        (b.path_risk || 0) -
        (a.path_risk || 0)
    );
  }, [report]);

  const requestedPathId =
    searchParams.get("path");

  const highestPath =
    attackPaths.find(
      (path) =>
        path.id === requestedPathId
    ) ||
    attackPaths[0];

  const [selectedMetric, setSelectedMetric] =
    useState("inherent");

  const [selectedNode, setSelectedNode] =
    useState(null);

  useEffect(() => {
    if (!selectedMetric || !metricDetailRef.current) {
      return;
    }

    requestAnimationFrame(() => {
      metricDetailRef.current?.scrollIntoView({
        behavior: "smooth",
        block: "center",
      });
    });
  }, [selectedMetric]);

  useEffect(() => {
    if (!selectedNode || !nodeDetailRef.current) {
      return;
    }

    requestAnimationFrame(() => {
      nodeDetailRef.current?.scrollIntoView({
        behavior: "smooth",
        block: "center",
      });
    });
  }, [selectedNode]);


  const componentMap = useMemo(() => {
    if (!report?.architecture?.components) {
      return {};
    }

    return Object.fromEntries(
      report.architecture.components.map(
        (component) => [
          component.id,
          component,
        ]
      )
    );
  }, [report]);

  const activeNode =
    selectedNode ||
    highestPath?.entry_point ||
    null;

  const selectedComponent =
    selectedNode
      ? componentMap[selectedNode]
      : null;

  const selectedNodeThreats = useMemo(() => {
    if (!selectedNode || !report?.threats) {
      return [];
    }

    return report.threats.filter(
      (threat) =>
        threat.target === selectedNode
    );
  }, [selectedNode, report]);

  const selectedNodeFlows = useMemo(() => {
    if (
      !selectedNode ||
      !report?.architecture?.data_flows
    ) {
      return [];
    }

    return report.architecture.data_flows.filter(
      (flow) =>
        flow.source === selectedNode ||
        flow.destination === selectedNode
    );
  }, [selectedNode, report]);

  const selectedNodeRole =
    highestPath && selectedNode
      ? selectedNode === highestPath.entry_point
        ? "Entry Point"
        : selectedNode === highestPath.critical_asset
          ? "Critical Asset"
          : "Intermediate Service"
      : "";

  const selectedNodePosition =
    highestPath && selectedNode
      ? highestPath.nodes.indexOf(selectedNode) + 1
      : 0;

  const inboundFlows = useMemo(() => {
    if (!selectedNode || !report?.architecture?.data_flows) {
      return [];
    }

    return report.architecture.data_flows.filter(
      (flow) => flow.destination === selectedNode
    );
  }, [selectedNode, report]);

  const outboundFlows = useMemo(() => {
    if (!selectedNode || !report?.architecture?.data_flows) {
      return [];
    }

    return report.architecture.data_flows.filter(
      (flow) => flow.source === selectedNode
    );
  }, [selectedNode, report]);

  const metricDetails = highestPath
    ? {
        inherent: {
          title: "Inherent Path Risk",
          value: `${highestPath.path_risk}/25`,
          description:
            "Risk before accounting for declared security controls.",
        },
        residual: {
          title: "Estimated Residual Risk",
          value: `${highestPath.residual_path_risk}/25`,
          description:
            "Estimated risk remaining after declared control coverage and effectiveness.",
        },
        coverage: {
          title: "Control Coverage",
          value:
            `${highestPath.control_summary?.coverage_percentage || 0}%`,
          description:
            "Coverage of required controls along the selected attack path.",
        },
        boundaries: {
          title: "Trust Boundary Crossings",
          value: `${highestPath.boundary_crossings}`,
          description:
            "Number of security trust boundaries crossed by this architecture path.",
        },
        threats: {
          title: "Threats Along Path",
          value: `${highestPath.threat_count}`,
          description:
            "Architecture-associated threats affecting nodes on this path.",
        },
      }
    : {};

  return (
    <div className="app-shell">
      <Sidebar />

      <main className="main-content page-with-footer">

        <SharedHeader />
        <header className="topbar">
          <div>
            <p className="eyebrow">
              Attack Surface Intelligence
            </p>

            <h1>
              Attack Path
              <span> Analysis</span>
            </h1>
          </div>

          <button
            className="run-button"
            onClick={loadAttackPaths}
          >
            <RefreshCcw size={17} />
            Refresh Analysis
          </button>
        </header>

        <section className="architecture-page-hero">
          <div>
            <p className="eyebrow">
              Architecture-Level Attack Paths
            </p>

            <h2>
              Exposure To Critical Assets
            </h2>

            <p>
              Analyze plausible paths from
              exposed entry points toward
              critical assets, including trust
              boundaries, threats, controls and
              estimated residual risk.
            </p>
          </div>

          <div className="architecture-status">
            LIVE ANALYSIS
          </div>
        </section>

        {loading && (
          <div className="state-panel">
            Loading attack path analysis…
          </div>
        )}

        {error && (
          <div className="state-panel error">
            <strong>
              Unable to load attack paths
            </strong>

            <span>{error}</span>
          </div>
        )}

        {!loading &&
          !error &&
          highestPath && (
            <>
              <section className="attack-overview-grid">
                <button
                  className={`attack-summary-card critical interactive-card ${
                    selectedMetric === "inherent"
                      ? "selected"
                      : ""
                  }`}
                  onClick={() =>
                    setSelectedMetric("inherent")
                  }
                >
                  <span>Inherent Risk</span>
                  <strong>
                    {highestPath.path_risk}/25
                  </strong>
                  <small>
                    {highestPath.path_severity}
                  </small>

                  <AttackRiskIcon
                    className="attack-summary-icon"
                    aria-hidden="true"
                  />
                </button>

                <button
                  className={`attack-summary-card interactive-card ${
                    selectedMetric === "residual"
                      ? "selected"
                      : ""
                  }`}
                  onClick={() =>
                    setSelectedMetric("residual")
                  }
                >
                  <span>Residual Risk</span>
                  <strong>
                    {highestPath.residual_path_risk}/25
                  </strong>
                  <small>
                    {highestPath.residual_path_severity}
                  </small>

                  <ResidualRiskIcon
                    className="attack-summary-icon"
                    aria-hidden="true"
                  />
                </button>

                <button
                  className={`attack-summary-card interactive-card ${
                    selectedMetric === "coverage"
                      ? "selected"
                      : ""
                  }`}
                  onClick={() =>
                    setSelectedMetric("coverage")
                  }
                >
                  <span>Control Coverage</span>
                  <strong>
                    {
                      highestPath.control_summary
                        ?.coverage_percentage
                    }
                    %
                  </strong>
                  <small>
                    Declared controls
                  </small>

                  <CoverageIcon
                    className="attack-summary-icon"
                    aria-hidden="true"
                  />
                </button>

                <button
                  className={`attack-summary-card interactive-card ${
                    selectedMetric === "boundaries"
                      ? "selected"
                      : ""
                  }`}
                  onClick={() =>
                    setSelectedMetric("boundaries")
                  }
                >
                  <span>Trust Boundaries</span>
                  <strong>
                    {highestPath.boundary_crossings}
                  </strong>
                  <small>
                    Crossings along path
                  </small>

                  <BoundaryIcon
                    className="attack-summary-icon"
                    aria-hidden="true"
                  />
                </button>

                <button
                  className={`attack-summary-card interactive-card ${
                    selectedMetric === "threats"
                      ? "selected"
                      : ""
                  }`}
                  onClick={() =>
                    setSelectedMetric("threats")
                  }
                >
                  <span>Threats Along Path</span>
                  <strong>
                    {highestPath.threat_count}
                  </strong>
                  <small>
                    Associated threats
                  </small>

                  <ThreatPathIcon
                    className="attack-summary-icon"
                    aria-hidden="true"
                  />
                </button>
              </section>

              {metricDetails[selectedMetric] && (
                <section
                  ref={metricDetailRef}
                  className={`metric-detail-panel ${
                    selectedMetric === "inherent"
                      ? "critical-metric"
                      : ""
                  }`}
                >
                  <div>
                    <span className="metric-detail-label">
                      SELECTED SECURITY METRIC
                    </span>

                    <h3>
                      {
                        metricDetails[selectedMetric]
                          .title
                      }
                    </h3>

                    <p>
                      {
                        metricDetails[selectedMetric]
                          .description
                      }
                    </p>
                  </div>

                  <strong className="metric-detail-value">
                    {
                      metricDetails[selectedMetric]
                        .value
                    }
                  </strong>
                </section>
              )}

              <section className="attack-main-layout">
                <article className="panel attack-chain-panel">
                  <div className="panel-heading">
                    <div>
                      <p className="eyebrow">
                        Highest-Risk Scenario
                      </p>

                      <h3>
                        Attack Chain
                      </h3>
                    </div>

                    <div className="critical-badge">
                      {
                        highestPath.path_priority
                      }
                    </div>
                  </div>

                  <div className="attack-chain-visual attack-chain-enterprise">
                    {highestPath.nodes.map(
                      (node, index) => {
                        const isEntry = index === 0;
                        const isCritical =
                          index ===
                          highestPath.nodes.length - 1;

                        const nodeLabel = isEntry
                          ? "ENTRY POINT"
                          : isCritical
                            ? "CRITICAL ASSET"
                            : "INTERMEDIATE SERVICE";

                        const nodeDescription = isEntry
                          ? "Internet exposed"
                          : isCritical
                            ? "Customer data"
                            : "Business logic";

                        const NodeIcon = isEntry
                          ? AttackEntryIcon
                          : isCritical
                            ? AttackDatabaseIcon
                            : AttackServiceIcon;

                        return (
                          <div
                            className="attack-chain-step"
                            key={node}
                          >
                            <button
                              type="button"
                              onClick={() =>
                                setSelectedNode(
                                  selectedNode === node
                                    ? null
                                    : node
                                )
                              }
                              className={
                                `${
                                  isEntry
                                    ? "attack-node attack-entry"
                                    : isCritical
                                      ? "attack-node attack-critical"
                                      : "attack-node"
                                } attack-node-button attack-node-enterprise ${
                                  selectedNode === node
                                    ? "selected-node"
                                    : ""
                                }`
                              }
                            >
                              <NodeIcon
                                className="attack-node-icon"
                                aria-hidden="true"
                              />

                              <div className="attack-node-copy">
                                <span className="attack-node-role">
                                  {nodeLabel}
                                </span>

                                <strong className="attack-node-title">
                                  {node}
                                </strong>

                                <small className="attack-node-description">
                                  {nodeDescription}
                                </small>
                              </div>
                            </button>

                            {!isCritical && (
                              <div className="attack-arrow">
                                →
                              </div>
                            )}
                          </div>
                        );
                      }
                    )}
                  </div>

                  {selectedComponent && (
                    <section
                      ref={nodeDetailRef}
                      className="node-intelligence-panel"
                    >
                      <div className="node-intelligence-header">
                        <div>
                          <p className="eyebrow">
                            Selected Architecture Node
                          </p>

                          <h3>
                            {selectedComponent.name}
                          </h3>

                          <p>
                            {selectedComponent.id}
                          </p>
                        </div>
                      </div>

                      <div className="node-intelligence-grid">
                        <div>
                          <span>Type</span>
                          <strong>
                            {selectedComponent.type}
                          </strong>
                        </div>

                        <div>
                          <span>Trust Zone</span>
                          <strong>
                            {selectedComponent.trust_zone}
                          </strong>
                        </div>

                        <div>
                          <span>Criticality</span>
                          <strong
                            className={
                              selectedComponent.criticality ===
                              "critical"
                                ? "danger-text"
                                : ""
                            }
                          >
                            {selectedComponent.criticality}
                          </strong>
                        </div>

                        <div>
                          <span>Data Classification</span>
                          <strong>
                            {
                              selectedComponent
                                .data_classification
                            }
                          </strong>
                        </div>

                        <div>
                          <span>Internet Exposure</span>
                          <strong>
                            {
                              selectedComponent
                                .internet_exposed
                                ? "Yes"
                                : "No"
                            }
                          </strong>
                        </div>

                        <div>
                          <span>Sensitive Data</span>
                          <strong>
                            {
                              selectedComponent
                                .stores_sensitive_data
                                ? "Yes"
                                : "No"
                            }
                          </strong>
                        </div>
                      </div>

                      <div className="node-intelligence-footer">
                        <div>
                          <span>
                            Threats Affecting Node
                          </span>
                          <strong>
                            {selectedNodeThreats.length}
                          </strong>
                        </div>

                        <div>
                          <span>
                            Connected Data Flows
                          </span>
                          <strong>
                            {selectedNodeFlows.length}
                          </strong>
                        </div>

                        {selectedNodeThreats.length > 0 && (
                          <div className="node-threat-preview">
                            {selectedNodeThreats.map(
                              (threat, index) => (
                                <span
                                  key={`${threat.category}-${index}`}
                                >
                                  {threat.category}
                                </span>
                              )
                            )}
                          </div>
                        )}
                      </div>
                    </section>
                  )}

                  {selectedComponent && (
                    <div className="attack-path-meta-grid">
                    <div>
                      <span>Role In Path</span>
                      <strong>
                        {selectedNodeRole}
                      </strong>
                    </div>

                    <div>
                      <span>Path Position</span>
                      <strong>
                        {selectedNodePosition} of{" "}
                        {highestPath.nodes.length}
                      </strong>
                    </div>

                    <div>
                      <span>Inbound Flows</span>
                      <strong>
                        {inboundFlows.length}
                      </strong>
                    </div>

                    <div>
                      <span>Outbound Flows</span>
                      <strong>
                        {outboundFlows.length}
                      </strong>
                    </div>
                  </div>
                  )}
                </article>

                <aside className="attack-side-column">
                  <article className="panel">
                    <div className="panel-heading">
                      <div>
                        <p className="eyebrow">
                          Risk Drivers
                        </p>

                        <h3>
                          Why This Path Matters
                        </h3>
                      </div>
                    </div>

                    <div className="risk-driver-list">
                      {(
                        highestPath.risk_drivers ||
                        []
                      ).map((driver) => (
                        <div
                          className="risk-driver-item"
                          key={driver}
                        >
                          <AlertTriangle
                            size={14}
                          />

                          <span>{driver}</span>
                        </div>
                      ))}
                    </div>
                  </article>

                  <article className="panel">
                    <div className="panel-heading">
                      <div>
                        <p className="eyebrow">
                          Control Assessment
                        </p>

                        <h3>
                          Coverage Summary
                        </h3>
                      </div>
                    </div>

                    <div className="coverage-meter">
                      <div className="coverage-value">
                        {
                          highestPath.control_summary
                            ?.coverage_percentage
                        }
                        %
                      </div>

                      <div className="coverage-track">
                        <div
                          className="coverage-fill"
                          style={{
                            width: `${
                              highestPath
                                .control_summary
                                ?.coverage_percentage ||
                              0
                            }%`,
                          }}
                        />
                      </div>
                    </div>

                    <div className="control-stats">
                      <div>
                        <span>Required</span>
                        <strong>
                          {
                            highestPath
                              .control_summary
                              ?.required
                          }
                        </strong>
                      </div>

                      <div>
                        <span>Implemented</span>
                        <strong>
                          {
                            highestPath
                              .control_summary
                              ?.implemented
                          }
                        </strong>
                      </div>

                      <div>
                        <span>Partial</span>
                        <strong>
                          {
                            highestPath
                              .control_summary
                              ?.partial
                          }
                        </strong>
                      </div>

                      <div>
                        <span>Missing</span>
                        <strong>
                          {
                            highestPath
                              .control_summary
                              ?.missing
                          }
                        </strong>
                      </div>
                    </div>
                  </article>
                </aside>
              </section>

              <section className="attack-bottom-grid">

                <article className="panel">
                  <div className="panel-heading">
                    <div>
                      <p className="eyebrow">
                        Remediation
                      </p>

                      <h3>
                        Control Gaps
                      </h3>
                    </div>

                    <ShieldCheck size={20} />
                  </div>

                  <div className="control-gap-table">
                    <div className="control-gap-row table-head">
                      <span>Control ID</span>
                      <span>Name</span>
                      <span>Status</span>
                      <span>Effectiveness</span>
                      <span>Asset</span>
                    </div>

                    {(
                      highestPath.control_gaps ||
                      []
                    ).map((gap) => (
                      <div
                        className="control-gap-row"
                        key={gap.id}
                      >
                        <Link
                          to={`/controls?control=${encodeURIComponent(
                            gap.id
                          )}`}
                          className="control-deep-link"
                          title={`Open ${gap.id} in Controls`}
                        >
                          {gap.id}
                        </Link>

                        <span>
                          {gap.name}
                        </span>

                        <span
                          className={
                            gap.status === "missing"
                              ? "gap-status missing"
                              : "gap-status partial"
                          }
                        >
                          {gap.status}
                        </span>

                        <span>
                          {gap.effectiveness}
                        </span>

                        <span>
                          {gap.component_id || "Global"}
                        </span>
                      </div>
                    ))}
                  </div>
                </article>

                <article className="panel">
                  <div className="panel-heading">
                    <div>
                      <p className="eyebrow">
                        Discovered Paths
                      </p>

                      <h3>
                        Attack Path Inventory
                      </h3>
                    </div>

                    <Route size={20} />
                  </div>

                  <div className="attack-inventory">
                    <div className="attack-inventory-row attack-inventory-head">
                      <span>Path ID</span>
                      <span>Path</span>
                      <span>Inherent</span>
                      <span>Residual</span>
                      <span>Priority</span>
                    </div>

                    {attackPaths.map((path) => (
                      <div
                        className={
                          `attack-inventory-row ${
                            highestPath?.id === path.id
                              ? "selected-path-row"
                              : ""
                          }`
                        }
                        key={path.id}
                      >
                        <span>{path.id}</span>

                        <strong>
                          {path.nodes.join(" → ")}
                        </strong>

                        <span className="danger-text">
                          {path.path_risk}/25
                        </span>

                        <span>
                          {path.residual_path_risk}/25
                        </span>

                        <b>
                          {path.path_priority}
                        </b>
                      </div>
                    ))}
                  </div>
                </article>

              </section>

              <p className="attack-disclaimer">
                Attack paths represent plausible
                architecture-level scenarios and
                do not represent confirmed exploit
                chains. Residual risk is estimated
                from declared control
                implementation and effectiveness.
              </p>
            </>
          )}

        <Footer />

      </main>
    </div>
  );
}

export default AttackPaths;
