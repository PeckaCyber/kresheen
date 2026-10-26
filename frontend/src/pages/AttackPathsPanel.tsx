import { Badge, Card } from "react-bootstrap";
import { RiskBadge } from "../components/RiskBadge";

export interface AttackPathHopOut {
  from_name: string;
  to_name: string;
  flow_label: string | null;
  crosses_boundary: boolean;
  authenticated: boolean | null;
  encrypted: boolean | null;
}

export interface AttackPathOut {
  source_name: string;
  target_name: string;
  target_type: string;
  is_crown_jewel: boolean;
  risk: string;
  risk_factors: string[];
  boundary_crossings: number;
  hops: AttackPathHopOut[];
}

function PathRoute({ path }: { path: AttackPathOut }) {
  return (
    <div className="small">
      <strong>{path.source_name}</strong>
      {path.hops.map((hop, index) => (
        <span key={index}>
          {" "}
          &rarr;{" "}
          {hop.crosses_boundary && (
            <Badge bg="secondary" className="me-1">
              crosses boundary
            </Badge>
          )}
          {index === path.hops.length - 1 ? <strong>{hop.to_name}</strong> : hop.to_name}
          {hop.flow_label && <span className="text-muted"> ({hop.flow_label})</span>}
        </span>
      ))}
    </div>
  );
}

export function AttackPathsPanel({ paths }: { paths: AttackPathOut[] }) {
  if (paths.length === 0) {
    return (
      <p className="text-muted mb-0">
        No attack paths found from an external entity to a data store or sensitive asset.
      </p>
    );
  }

  return (
    <div className="d-flex flex-column gap-2">
      {paths.map((path, index) => (
        <Card key={index} body>
          <div className="d-flex justify-content-between align-items-start mb-2">
            <div>
              <RiskBadge level={path.risk}>{path.risk}</RiskBadge>
              {path.is_crown_jewel && (
                <Badge bg="dark" className="ms-1">
                  crown jewel
                </Badge>
              )}
              <span className="text-muted small ms-2">
                {path.boundary_crossings} boundary crossing{path.boundary_crossings === 1 ? "" : "s"}
              </span>
            </div>
          </div>
          <PathRoute path={path} />
          <ul className="text-muted small mb-0 mt-2">
            {path.risk_factors.map((factor, index) => (
              <li key={index}>{factor}</li>
            ))}
          </ul>
        </Card>
      ))}
    </div>
  );
}
