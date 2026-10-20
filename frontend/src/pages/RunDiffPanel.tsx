import { Badge, Table } from "react-bootstrap";
import { RiskBadge } from "../components/RiskBadge";

export interface ComponentDiffOut {
  key: string;
  type: string;
  name: string;
}

export interface FlowDiffOut {
  key: string;
  source_name: string;
  target_name: string;
}

export interface ThreatDiffOut {
  key: string;
  title: string;
  severity: string;
}

export interface FindingDiffOut {
  title: string;
  severity: string;
  domain: string;
}

export interface RunDiffOut {
  current_run_id: string;
  previous_run_id: string | null;
  new_components: ComponentDiffOut[];
  removed_components: ComponentDiffOut[];
  new_flows: FlowDiffOut[];
  removed_flows: FlowDiffOut[];
  new_threats: ThreatDiffOut[];
  resolved_threats: ThreatDiffOut[];
  new_findings: FindingDiffOut[];
  resolved_findings: FindingDiffOut[];
}

function SeverityBadge({ severity }: { severity: string }) {
  return <RiskBadge level={severity}>{severity}</RiskBadge>;
}

function ComponentList({ title, entries, variant }: { title: string; entries: ComponentDiffOut[]; variant: "success" | "danger" }) {
  if (entries.length === 0) return null;
  return (
    <div className="mb-3">
      <h3 className="h6">{title}</h3>
      <ul className="list-unstyled mb-0">
        {entries.map((entry) => (
          <li key={entry.key}>
            <Badge bg={variant}>{variant === "success" ? "+" : "−"}</Badge> {entry.name}{" "}
            <span className="text-muted small">({entry.type})</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

function FlowList({ title, entries, variant }: { title: string; entries: FlowDiffOut[]; variant: "success" | "danger" }) {
  if (entries.length === 0) return null;
  return (
    <div className="mb-3">
      <h3 className="h6">{title}</h3>
      <ul className="list-unstyled mb-0">
        {entries.map((entry) => (
          <li key={entry.key}>
            <Badge bg={variant}>{variant === "success" ? "+" : "−"}</Badge> {entry.source_name} &rarr;{" "}
            {entry.target_name}
          </li>
        ))}
      </ul>
    </div>
  );
}

function ThreatList({ title, entries, variant }: { title: string; entries: ThreatDiffOut[]; variant: "success" | "danger" }) {
  if (entries.length === 0) return null;
  return (
    <div className="mb-3">
      <h3 className="h6">{title}</h3>
      <Table size="sm" striped className="mb-0">
        <tbody>
          {entries.map((entry) => (
            <tr key={entry.key}>
              <td>
                <Badge bg={variant}>{variant === "success" ? "+" : "−"}</Badge>
              </td>
              <td>
                <SeverityBadge severity={entry.severity} />
              </td>
              <td>{entry.title}</td>
            </tr>
          ))}
        </tbody>
      </Table>
    </div>
  );
}

function FindingList({ title, entries, variant }: { title: string; entries: FindingDiffOut[]; variant: "success" | "danger" }) {
  if (entries.length === 0) return null;
  return (
    <div className="mb-3">
      <h3 className="h6">{title}</h3>
      <Table size="sm" striped className="mb-0">
        <tbody>
          {entries.map((entry, index) => (
            <tr key={`${entry.title}-${index}`}>
              <td>
                <Badge bg={variant}>{variant === "success" ? "+" : "−"}</Badge>
              </td>
              <td>
                <SeverityBadge severity={entry.severity} />
              </td>
              <td>{entry.title}</td>
              <td className="text-muted small">{entry.domain}</td>
            </tr>
          ))}
        </tbody>
      </Table>
    </div>
  );
}

export function RunDiffPanel({ diff }: { diff: RunDiffOut }) {
  if (diff.previous_run_id === null) {
    return <p className="text-muted mb-0">This is the first run for this application -- nothing to compare yet.</p>;
  }

  const nothingChanged =
    diff.new_components.length === 0 &&
    diff.removed_components.length === 0 &&
    diff.new_flows.length === 0 &&
    diff.removed_flows.length === 0 &&
    diff.new_threats.length === 0 &&
    diff.resolved_threats.length === 0 &&
    diff.new_findings.length === 0 &&
    diff.resolved_findings.length === 0;

  if (nothingChanged) {
    return <p className="text-muted mb-0">No changes since the previous run.</p>;
  }

  return (
    <div>
      <ComponentList title="New components" entries={diff.new_components} variant="success" />
      <ComponentList title="Removed components" entries={diff.removed_components} variant="danger" />
      <FlowList title="New connections" entries={diff.new_flows} variant="success" />
      <FlowList title="Removed connections" entries={diff.removed_flows} variant="danger" />
      <ThreatList title="New threats" entries={diff.new_threats} variant="success" />
      <ThreatList title="Resolved threats" entries={diff.resolved_threats} variant="danger" />
      <FindingList title="New findings" entries={diff.new_findings} variant="success" />
      <FindingList title="Resolved findings" entries={diff.resolved_findings} variant="danger" />
    </div>
  );
}
