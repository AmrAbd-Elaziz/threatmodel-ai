import { DEMO_ENDPOINTS } from "./demoApi";
import { useEffect, useMemo, useRef, useState } from "react";
import {
  Link,
  useNavigate,
  useSearchParams,
} from "react-router-dom";

import {
  Activity,
  AlertTriangle,
  CalendarClock,
  FileWarning,
  LayoutDashboard,
  Network,
  RefreshCcw,
  Route,
  ShieldCheck,
  UserRound,
} from "lucide-react";

import Footer from "./Footer";
import Sidebar from "./Sidebar";
import SharedHeader from "./SharedHeader";

import { getCurrentAssessment } from "./assessmentStore";

import "./index.css";

const API_BASE = import.meta.env.VITE_API_BASE_URL || "";

function SidebarItem({ icon: Icon, label, to, active = false }) {
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

function Findings() {
  const findingDetailRef = useRef(null);

  const navigate = useNavigate();
  const [searchParams] = useSearchParams();

  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [priority, setPriority] = useState("ALL");
  const [owner, setOwner] = useState("ALL");

  const [selectedFindingId, setSelectedFindingId] =
    useState(null);

  async function loadFindings() {
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
        DEMO_ENDPOINTS.banking
      );

      if (!response.ok) {
        throw new Error("ThreatModel API returned an error.");
      }

      setReport(await response.json());
    } catch (err) {
      setError(err.message || "Unable to load findings.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadFindings();
  }, []);

  const findings = report?.findings || [];

  useEffect(() => {
    const findingFromUrl =
      searchParams.get("finding");

    if (
      findingFromUrl &&
      findings.some(
        (finding) =>
          finding.id === findingFromUrl
      )
    ) {
      setSelectedFindingId(
        findingFromUrl
      );
    } else {
      setSelectedFindingId(null);
    }
  }, [findings, searchParams]);

  const selectedFinding = useMemo(
    () =>
      findings.find(
        (finding) =>
          finding.id === selectedFindingId
      ) || null,
    [findings, selectedFindingId]
  );

  function toggleFinding(findingId) {
    if (selectedFindingId === findingId) {
      setSelectedFindingId(null);
      navigate("/findings");
      return;
    }

    setSelectedFindingId(findingId);

    navigate(
      `/findings?finding=${encodeURIComponent(
        findingId
      )}`
    );
  }

  const owners = useMemo(
    () => [
      ...new Set(
        findings.map((finding) => finding.owner)
      ),
    ],
    [findings]
  );

  const filteredFindings = useMemo(
    () =>
      findings.filter((finding) => {
        const priorityMatch =
          priority === "ALL" ||
          finding.priority === priority;

        const ownerMatch =
          owner === "ALL" ||
          finding.owner === owner;

        return priorityMatch && ownerMatch;
      }),
    [findings, priority, owner]
  );

  const openCount = findings.filter(
    (finding) => finding.status === "Open"
  ).length;

  const missingCount = findings.filter(
    (finding) => finding.control_status === "missing"
  ).length;

  const partialCount = findings.filter(
    (finding) => finding.control_status === "partial"
  ).length;

  const overdueCount = findings.filter(
    (finding) => finding.sla_status === "Overdue"
  ).length;

  useEffect(() => {
    if (
      !selectedFindingId ||
      !selectedFinding ||
      !findingDetailRef.current
    ) {
      return;
    }

    requestAnimationFrame(() => {
      findingDetailRef.current?.scrollIntoView({
        behavior: "smooth",
        block: "center",
      });
    });
  }, [selectedFindingId, selectedFinding]);

  return (
    <div className="app-shell">
      <Sidebar />

      <main className="main-content page-with-footer">

        <SharedHeader />
        <header className="topbar">
          <div>
            <p className="eyebrow">Remediation Workflow</p>

            <h1>
              Security <span>Findings</span>
            </h1>
          </div>

          <button
            className="run-button"
            onClick={loadFindings}
          >
            <RefreshCcw size={17} />
            Refresh Findings
          </button>
        </header>

        <section className="architecture-page-hero">
          <div>
            <p className="eyebrow">Finding Management</p>
            <h2>Control Gap Remediation</h2>

            <p>
              Track control gaps using stable finding IDs,
              ownership, SLA targets and remediation guidance.
            </p>
          </div>

          <div className="architecture-status">
            ACTIVE FINDINGS
          </div>
        </section>

        {loading && (
          <div className="state-panel">
            Loading findings…
          </div>
        )}

        {error && (
          <div className="state-panel error">
            <strong>Unable to load findings</strong>
            <span>{error}</span>
          </div>
        )}

        {!loading && !error && report && (
          <>
            <section className="finding-summary-grid">
              <div className="finding-summary-card">
                <FileWarning size={18} />
                <span>Total Findings</span>
                <strong>{findings.length}</strong>
                <small>Current assessment</small>
              </div>

              <div className="finding-summary-card danger">
                <AlertTriangle size={18} />
                <span>Open</span>
                <strong>{openCount}</strong>
                <small>Requires remediation</small>
              </div>

              <div className="finding-summary-card danger">
                <ShieldCheck size={18} />
                <span>Missing Controls</span>
                <strong>{missingCount}</strong>
                <small>Not implemented</small>
              </div>

              <div className="finding-summary-card warning">
                <ShieldCheck size={18} />
                <span>Partial Controls</span>
                <strong>{partialCount}</strong>
                <small>Needs strengthening</small>
              </div>

              <div className="finding-summary-card">
                <CalendarClock size={18} />
                <span>Overdue</span>
                <strong>{overdueCount}</strong>
                <small>SLA status</small>
              </div>
            </section>

            <section className="panel">
              <div className="panel-heading">
                <div>
                  <p className="eyebrow">Finding Register</p>
                  <h3>Prioritized Remediation Queue</h3>
                </div>

                <FileWarning size={20} />
              </div>

              <div className="finding-filter-bar">
                <select
                  value={priority}
                  onChange={(event) =>
                    setPriority(event.target.value)
                  }
                >
                  <option value="ALL">
                    All Priorities
                  </option>

                  {["P1", "P2", "P3", "P4", "P5"].map(
                    (item) => (
                      <option key={item} value={item}>
                        {item}
                      </option>
                    )
                  )}
                </select>

                <select
                  value={owner}
                  onChange={(event) =>
                    setOwner(event.target.value)
                  }
                >
                  <option value="ALL">
                    All Owners
                  </option>

                  {owners.map((item) => (
                    <option key={item} value={item}>
                      {item}
                    </option>
                  ))}
                </select>

                <div className="filter-result-count">
                  {filteredFindings.length} finding(s)
                </div>
              </div>

              <div className="finding-register">
                <div className="finding-register-row table-head">
                  <span>Finding</span>
                  <span>Control</span>
                  <span>Asset</span>
                  <span>Owner</span>
                  <span>Status</span>
                  <span>SLA</span>
                  <span>Due Date</span>
                  <span>Priority</span>
                </div>

                {filteredFindings.map((finding) => (
                  <button
                    type="button"
                    className={
                      `finding-register-row finding-register-button ` +
                      (
                        selectedFindingId === finding.id
                          ? "selected"
                          : ""
                      )
                    }
                    key={finding.id}
                    onClick={() =>
                      toggleFinding(finding.id)
                    }
                  >
                    <strong>{finding.id}</strong>

                    <span>
                      {finding.control_id} ·{" "}
                      {finding.control_name}
                    </span>

                    <span>{finding.asset}</span>
                    <span>{finding.owner}</span>

                    <span className="finding-status">
                      {finding.status}
                    </span>

                    <span
                      className={
                        finding.sla_status === "Overdue"
                          ? "sla-status overdue"
                          : "sla-status"
                      }
                    >
                      {finding.sla_status}
                    </span>

                    <span>{finding.due_date}</span>

                    <b
                      className={
                        `priority-badge ${finding.priority.toLowerCase()}`
                      }
                    >
                      {finding.priority}
                    </b>
                  </button>
                ))}
              </div>
            </section>

            <section className="finding-card-grid">
              {selectedFinding && (() => {
                const finding = selectedFinding;

                return (
                <article
                  ref={findingDetailRef}
                  className="panel finding-detail-card selected-finding-panel"
                  key={finding.id}
                >
                  <div className="finding-detail-header">
                    <div>
                      <p className="eyebrow">
                        {finding.id}
                      </p>

                      <h3>{finding.control_name}</h3>
                    </div>

                    <span
                      className={
                        `control-status ` +
                        finding.control_status
                      }
                    >
                      {finding.control_status}
                    </span>
                  </div>

                  <div className="finding-metadata">
                    <div>
                      <UserRound size={14} />
                      <span>Owner</span>
                      <strong>{finding.owner}</strong>
                    </div>

                    <div>
                      <CalendarClock size={14} />
                      <span>Due Date</span>
                      <strong>{finding.due_date}</strong>
                    </div>

                    <div>
                      <Route size={14} />
                      <span>Attack Path</span>
                      <strong>{finding.attack_path_id}</strong>
                    </div>

                    <div>
                      <ShieldCheck size={14} />
                      <span>Control</span>
                      <strong>{finding.control_id}</strong>
                    </div>
                  </div>

                  <div className="finding-navigation">
                    <Link
                      to={`/controls?control=${encodeURIComponent(
                        finding.control_id
                      )}`}
                      className="finding-nav-link"
                    >
                      <span>View Control</span>
                      <strong>→</strong>
                    </Link>

                    <Link
                      to={`/attack-paths?path=${encodeURIComponent(
                        finding.attack_path_id
                      )}`}
                      className="finding-nav-link"
                    >
                      <span>View Attack Path</span>
                      <strong>→</strong>
                    </Link>
                  </div>

                  <div className="finding-risk-row">
                    <div>
                      <span>Inherent Path Risk</span>
                      <strong className="danger-text">
                        {finding.inherent_path_risk}/25
                      </strong>
                    </div>

                    <b>→</b>

                    <div>
                      <span>Estimated Residual Risk</span>
                      <strong className="good-text">
                        {finding.estimated_residual_risk}/25
                      </strong>
                    </div>
                  </div>

                  <div className="remediation-box">
                    <span>Recommended Remediation</span>
                    <p>{finding.remediation}</p>
                  </div>

                  <div className="finding-sla-footer">
                    <span>
                      SLA: {finding.sla_days} days
                    </span>

                    <strong>
                      {finding.days_remaining} days remaining
                    </strong>
                  </div>
                </article>
                );
              })()}
            </section>
          </>
        )}

        <Footer />

      </main>
    </div>
  );
}

export default Findings;
