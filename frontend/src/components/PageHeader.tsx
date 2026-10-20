import type { ReactNode } from "react";
import { Link } from "react-router-dom";

export interface Crumb {
  label: string;
  to?: string;
}

// One header for every page: optional breadcrumb, title, one-line subtitle,
// and an actions slot on the right. Pair with the `pc-page` / `pc-page-narrow`
// wrapper classes in theme.css so every page has the same gutters and width.
export function PageHeader({
  title,
  subtitle,
  actions,
  crumbs,
  compact = false,
}: {
  title: ReactNode;
  subtitle?: ReactNode;
  actions?: ReactNode;
  crumbs?: Crumb[];
  compact?: boolean;
}) {
  return (
    <header className={`pc-page-header${compact ? " pc-page-header-compact" : ""}`}>
      {crumbs && crumbs.length > 0 && (
        <nav aria-label="Breadcrumb" className="pc-crumbs">
          {crumbs.map((crumb, index) => (
            <span key={`${crumb.label}-${index}`}>
              {index > 0 && <span className="pc-crumb-sep" aria-hidden="true">/</span>}
              {crumb.to ? <Link to={crumb.to}>{crumb.label}</Link> : <span>{crumb.label}</span>}
            </span>
          ))}
        </nav>
      )}
      <div className="pc-page-header-row">
        <div className="pc-page-header-text">
          <h1 className="pc-page-title">{title}</h1>
          {subtitle && <p className="pc-page-subtitle">{subtitle}</p>}
        </div>
        {actions && <div className="pc-page-actions">{actions}</div>}
      </div>
    </header>
  );
}
