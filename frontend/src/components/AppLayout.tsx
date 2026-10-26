import { extensions } from "../extensions";
import { useState, type ReactNode } from "react";
import { Dropdown } from "react-bootstrap";
import { Link, NavLink } from "react-router-dom";
import { useAuth } from "../auth/AuthContext";
import { getThemePreference, setThemePreference, type ThemePreference } from "../theme";
import { ToastProvider } from "./Toasts";
import { CommandPalette } from "./CommandPalette";

interface NavItem {
  to: string;
  label: string;
  icon: string;
}

// Home, Threat models and Threat library are the everyday tasks; Constructs
// and Audit log live under Settings because they are visited rarely.
const TOP_ITEMS: NavItem[] = [
  { to: "/dashboard", label: "Home", icon: "bi-speedometer2" },
  { to: "/applications", label: "Threat models", icon: "bi-diagram-3" },
  { to: "/threat-kb", label: "Threat library", icon: "bi-book" },
];

const BOTTOM_ITEMS: NavItem[] = [
  { to: "/settings", label: "Settings", icon: "bi-gear" },
  { to: "/help", label: "Help", icon: "bi-question-circle" },
];

const TOP_ALL: NavItem[] = [...TOP_ITEMS, ...extensions.navItems.filter((i) => i.placement !== "bottom")];
const BOTTOM_ALL: NavItem[] = [...extensions.navItems.filter((i) => i.placement === "bottom"), ...BOTTOM_ITEMS];

const SIDEBAR_STORAGE_KEY = "kresheen-sidebar";
const COLLAPSE_WIDTH_BREAKPOINT = 992;

function readStoredCollapse(): boolean | null {
  try {
    const value = window.localStorage.getItem(SIDEBAR_STORAGE_KEY);
    if (value === "collapsed") return true;
    if (value === "expanded") return false;
  } catch {
    // Storage can be blocked; fall through to the viewport-based default.
  }
  return null;
}

function writeStoredCollapse(collapsed: boolean): void {
  try {
    window.localStorage.setItem(SIDEBAR_STORAGE_KEY, collapsed ? "collapsed" : "expanded");
  } catch {
    // Not persisted, but still applied for this session.
  }
}

function initialCollapse(): boolean {
  const stored = readStoredCollapse();
  if (stored !== null) return stored;
  return typeof window !== "undefined" && window.innerWidth < COLLAPSE_WIDTH_BREAKPOINT;
}

const THEME_OPTIONS: Array<{ value: ThemePreference; label: string; icon: string }> = [
  { value: "light", label: "Light", icon: "bi-sun" },
  { value: "dark", label: "Dark", icon: "bi-moon-stars" },
  { value: "system", label: "Match system", icon: "bi-circle-half" },
];

function NavIcon({ icon }: { icon: string }) {
  return <i className={`bi ${icon} pc-nav-icon`} aria-hidden="true" />;
}

export function AppLayout({ children }: { children: ReactNode }) {
  const { logout, role, email } = useAuth();
  const [collapsed, setCollapsed] = useState<boolean>(initialCollapse);
  const [theme, setTheme] = useState<ThemePreference>(getThemePreference);

  function toggleCollapsed() {
    setCollapsed((current) => {
      const next = !current;
      writeStoredCollapse(next);
      return next;
    });
  }

  function chooseTheme(preference: ThemePreference) {
    setTheme(preference);
    setThemePreference(preference);
  }

  const navLinkClass = ({ isActive }: { isActive: boolean }) =>
    `nav-link pc-nav-link text-light d-flex align-items-center gap-2${isActive ? " active fw-bold" : ""}`;

  return (
    <ToastProvider>
      <div className="d-flex" style={{ height: "100vh" }}>
        <nav
          className={`d-flex flex-column flex-shrink-0 pc-sidebar${collapsed ? " pc-sidebar-collapsed" : ""}`}
          style={{ width: collapsed ? 64 : 220, height: "100vh", overflowY: "auto" }}
        >
          <div className="d-flex align-items-center justify-content-between px-3 py-3">
            <Link
              to="/dashboard"
              className="navbar-brand pc-brand text-decoration-none mb-0"
              title="Kresheen"
              aria-label="Kresheen, home"
            >
              {collapsed ? <i className="bi bi-shield-lock" aria-hidden="true" /> : "Kresheen"}
            </Link>
          </div>
          <div className="nav flex-column px-2 flex-grow-1">
            {TOP_ALL.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                className={navLinkClass}
                title={collapsed ? item.label : undefined}
                aria-label={item.label}
              >
                <NavIcon icon={item.icon} />
                {!collapsed && <span>{item.label}</span>}
              </NavLink>
            ))}
            <hr className="pc-nav-divider" />
            {BOTTOM_ALL.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                className={navLinkClass}
                title={collapsed ? item.label : undefined}
                aria-label={item.label}
              >
                <NavIcon icon={item.icon} />
                {!collapsed && <span>{item.label}</span>}
              </NavLink>
            ))}
          </div>

          <button
            type="button"
            className="btn btn-sm btn-outline-light mx-2 mb-2 d-flex align-items-center justify-content-center gap-1"
            style={{ opacity: 0.75 }}
            title="Search (Ctrl K)"
            aria-label="Search"
          >
            <i className="bi bi-search" aria-hidden="true" />
            {!collapsed && <span className="small">Search Ctrl K</span>}
          </button>

          <button
            type="button"
            className="btn btn-sm btn-outline-light mx-2 mb-2 d-flex align-items-center justify-content-center gap-1"
            onClick={toggleCollapsed}
            title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
            aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
            aria-pressed={collapsed}
          >
            <i className={`bi ${collapsed ? "bi-chevron-right" : "bi-chevron-left"}`} aria-hidden="true" />
            {!collapsed && <span className="small">Collapse</span>}
          </button>

          <Dropdown drop="up" className="px-2 mb-3">
            <Dropdown.Toggle
              variant="outline-light"
              size="sm"
              id="user-menu"
              className="w-100 d-flex align-items-center gap-2 text-truncate"
              title={collapsed ? (email ?? role ?? "Account") : undefined}
            >
              <i className="bi bi-person-circle" aria-hidden="true" />
              {!collapsed && <span className="text-truncate">{email ?? role ?? "Account"}</span>}
            </Dropdown.Toggle>
            <Dropdown.Menu>
              <Dropdown.Header>Theme</Dropdown.Header>
              {THEME_OPTIONS.map((option) => (
                <Dropdown.Item
                  key={option.value}
                  onClick={() => chooseTheme(option.value)}
                  active={theme === option.value}
                >
                  <i className={`bi ${option.icon} me-2`} aria-hidden="true" />
                  {option.label}
                  {theme === option.value && <i className="bi bi-check2 ms-2" aria-hidden="true" />}
                </Dropdown.Item>
              ))}
              <Dropdown.Divider />
              <Dropdown.Item as={Link} to="/settings#account">
                Change password
              </Dropdown.Item>
              <Dropdown.Item onClick={() => void logout()}>Sign out</Dropdown.Item>
            </Dropdown.Menu>
          </Dropdown>
        </nav>
        <div className="flex-grow-1 pc-main-scroll" style={{ height: "100vh", overflowY: "auto" }}>
          {children}
        </div>
        <CommandPalette />
      </div>
    </ToastProvider>
  );
}
