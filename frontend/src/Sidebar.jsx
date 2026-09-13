import {
  Activity,
  AlertTriangle,
  FileWarning,
  LayoutDashboard,
  Network,
  RefreshCcw,
  Route,
  ShieldCheck,
} from "lucide-react";

import {
  Link,
  useLocation,
} from "react-router-dom";

import {
  useEffect,
  useState,
} from "react";


const navigation = [
  {
    label: "Dashboard",
    to: "/",
    icon: LayoutDashboard,
  },
  {
    label: "Architecture",
    to: "/architecture",
    icon: Network,
  },
  {
    label: "Threats",
    to: "/threats",
    icon: AlertTriangle,
  },
  {
    label: "Attack Paths",
    to: "/attack-paths",
    icon: Route,
  },
  {
    label: "Controls",
    to: "/controls",
    icon: ShieldCheck,
  },
  {
    label: "Findings",
    to: "/findings",
    icon: FileWarning,
  },
  {
    label: "Reassessment",
    to: "/reassessment",
    icon: RefreshCcw,
  },
  {
    label: "Reports",
    to: "/reports",
    icon: Activity,
  },
];


function Sidebar() {
  const location = useLocation();

  const [collapsed, setCollapsed] = useState(
    () =>
      localStorage.getItem(
        "threatmodel-sidebar-collapsed"
      ) === "true"
  );


  useEffect(() => {
    document.body.classList.toggle(
      "sidebar-is-collapsed",
      collapsed
    );

    localStorage.setItem(
      "threatmodel-sidebar-collapsed",
      String(collapsed)
    );
  }, [collapsed]);


  function toggleSidebar() {
    setCollapsed(
      (current) => !current
    );
  }


  return (
    <aside
      className={`sidebar ${
        collapsed ? "collapsed" : ""
      }`}
    >

      <button
        type="button"
        className="sidebar-logo-toggle"
        onClick={toggleSidebar}
        aria-label={
          collapsed
            ? "Expand sidebar"
            : "Collapse sidebar"
        }
        title={
          collapsed
            ? "Expand sidebar"
            : "Collapse sidebar"
        }
      >
        <img
          src={`${import.meta.env.BASE_URL}threatmodel-symbol.png`}
          alt=""
        />
      </button>


      <nav className="sidebar-nav">

        {navigation.map(
          ({
            label,
            to,
            icon: Icon,
          }) => {

            const active =
              to === "/"
                ? location.pathname === "/"
                : location.pathname.startsWith(to);

            return (
              <Link
                key={to}
                to={to}
                className={`nav-item ${
                  active ? "active" : ""
                }`}
                title={
                  collapsed
                    ? label
                    : undefined
                }
              >
                <Icon size={18} />
                <span>{label}</span>
              </Link>
            );
          }
        )}

      </nav>


      <div className="sidebar-security-card">
        <img
          src={`${import.meta.env.BASE_URL}sidebar-security-card.png`}
          alt="A more secure tomorrow starts with a clearer view today."
        />
      </div>


      <div className="sidebar-footer">
        <div className="status-dot" />

        <div>
          <strong>Engine Online</strong>
          <span>Deterministic analysis</span>
        </div>
      </div>

    </aside>
  );
}


export default Sidebar;
