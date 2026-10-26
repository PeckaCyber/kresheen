import { useEffect, useState } from "react";
import { Badge, Button, Form, Table } from "react-bootstrap";
import { apiFetch, ApiError } from "../api/client";
import { RiskBadge } from "../components/RiskBadge";
import { useToast } from "../components/Toasts";

export type ActionStatus = "todo" | "in_progress" | "done" | "wont_do";

export interface ActionOut {
  id: string;
  text: string;
  score: number;
  max_risk: "critical" | "high" | "medium" | "low";
  basis: "observed" | "specific" | "generic";
  threat_count: number;
  element_count: number;
  elements: string[];
  cwe_refs: string[];
  // Optional so older responses still type-check.
  verification?: string[];
  fix_examples?: string[];
  threat_keys: string[];
  status: ActionStatus;
  note: string;
}

export interface ActionPlanOut {
  actions: ActionOut[];
  summary: { total: number; by_status: Record<string, number>; open_threats_covered: number };
}
const STATUS_LABELS: Record<ActionStatus, string> = {
  todo: "To do",
  in_progress: "In progress",
  done: "Done",
  wont_do: "Won't do",
};
const BASIS_HINTS: Record<ActionOut["basis"], string> = {
  observed: "Fixes a misconfiguration found in your ingested configuration",
  specific: "Fixes a threat backed by a scanner finding or a fact you stated about this design",
  generic: "Generic hardening that applies to any element of this type",
};
const TOP_COUNT = 10;
const isOpen = (action: ActionOut) => action.status === "todo" || action.status === "in_progress";

// The open threats pivoted to the fixes that address them, ranked, so a reader
// knows what to do first. Status here is the user's
// decision about the fix; it does not change the underlying threats' statuses.
export function ActionPlanPanel({
  applicationId,
  runId,
  refreshKey,
  onLoaded,
}: {
  applicationId: string;
  runId: string;
  // Anything that changes when threat triage changes, so the plan stays current.
  refreshKey?: unknown;
  // Lets the page header show how many actions are open.
  onLoaded?: (plan: ActionPlanOut) => void;
}) {
  const toast = useToast();
  const [plan, setPlan] = useState<ActionPlanOut | null>(null);
  const [failed, setFailed] = useState(false);
  const [showAll, setShowAll] = useState(false);
  const [showClosed, setShowClosed] = useState(false);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [declining, setDeclining] = useState<{ id: string; reason: string } | null>(null);

  const base = `/api/applications/${applicationId}/runs/${runId}/action-plan`;

  useEffect(() => {
    let current = true;
    apiFetch<ActionPlanOut>(base)
      .then((out) => {
        if (!current) return;
        setPlan(out);
        setFailed(false);
        onLoaded?.(out);
      })
      .catch(() => current && setFailed(true));
    return () => {
      current = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [base, refreshKey]);

  async function setStatus(action: ActionOut, status: ActionStatus, note = "") {
    try {
      const out = await apiFetch<ActionPlanOut>(`${base}/${action.id}/status`, {
        method: "PUT",
        body: JSON.stringify({ status, note }),
      });
      setPlan(out);
      onLoaded?.(out);
      setDeclining(null);
      toast.success("Status updated");
    } catch (err) {
      toast.error(err instanceof ApiError ? err.message : "Could not save that status");
    }
  }

  function handleSelect(action: ActionOut, status: ActionStatus) {
    if (status === "wont_do") setDeclining({ id: action.id, reason: action.note });
    else void setStatus(action, status);
  }

  if (failed) return <p className="text-danger mb-0">Could not load the action plan.</p>;
  if (!plan) return <p className="text-muted mb-0">Loading...</p>;

  const open = plan.actions.filter(isOpen);
  const closed = plan.actions.filter((a) => !isOpen(a));
  const listed = showAll ? open : open.slice(0, TOP_COUNT);

  function row(action: ActionOut, rank: number | null) {
    const isExpanded = expanded === action.id;
    return (
      <tbody key={action.id}>
        <tr>
          <td className="text-muted">{rank ?? ""}</td>
          <td>
            <div>{action.text}</div>
            <Button
              variant="link"
              size="sm"
              className="p-0 small"
              onClick={() => setExpanded(isExpanded ? null : action.id)}
              aria-expanded={isExpanded}
            >
              {action.threat_count} threat{action.threat_count === 1 ? "" : "s"} on {action.element_count} element
              {action.element_count === 1 ? "" : "s"}
            </Button>
            {isExpanded && (
              <div className="small text-muted mt-1">
                {action.elements.join(", ")}
                {action.element_count > action.elements.length &&
                  ` and ${action.element_count - action.elements.length} more`}
                {action.cwe_refs.length > 0 && <div>{action.cwe_refs.join(", ")}</div>}
              </div>
            )}
            {isExpanded && (action.verification ?? []).length > 0 && (
              <div className="small mt-2">
                <div className="fw-semibold">How to verify it worked</div>
                <ul className="mb-1">
                  {(action.verification ?? []).map((step) => (
                    <li key={step}>{step}</li>
                  ))}
                </ul>
              </div>
            )}
            {isExpanded &&
              (action.fix_examples ?? []).map((example) => (
                <pre key={example} className="small border rounded p-2 mt-1 bg-body" aria-label="Example fix">
                  {example}
                </pre>
              ))}
            {action.note && <div className="small fst-italic mt-1">Note: {action.note}</div>}
          </td>
          <td>
            <RiskBadge level={action.max_risk}>{action.max_risk}</RiskBadge>
          </td>
          <td>
            <Badge
              bg={action.basis === "observed" ? "danger" : action.basis === "specific" ? "primary" : "light"}
              text={action.basis === "generic" ? "muted" : undefined}
              className="fw-normal"
              title={BASIS_HINTS[action.basis]}
            >
              {action.basis}
            </Badge>
          </td>
          <td>
            <Form.Select
              size="sm"
              aria-label={`Status of: ${action.text}`}
              value={action.status}
              onChange={(e) => handleSelect(action, e.target.value as ActionStatus)}
            >
              {(Object.keys(STATUS_LABELS) as ActionStatus[]).map((status) => (
                <option key={status} value={status}>
                  {STATUS_LABELS[status]}
                </option>
              ))}
            </Form.Select>
          </td>
        </tr>
        {declining?.id === action.id && (
          <tr>
            <td />
            <td colSpan={4}>
              <Form.Label className="small mb-1">Why is this fix not being done? (required)</Form.Label>
              <div className="d-flex gap-2">
                <Form.Control
                  size="sm"
                  value={declining.reason}
                  onChange={(e) => setDeclining({ id: action.id, reason: e.target.value })}
                  aria-label="Reason for declining this fix"
                />
                <Button
                  size="sm"
                  disabled={!declining.reason.trim()}
                  onClick={() => void setStatus(action, "wont_do", declining.reason)}
                >
                  Save
                </Button>
                <Button size="sm" variant="outline-secondary" onClick={() => setDeclining(null)}>
                  Cancel
                </Button>
              </div>
            </td>
          </tr>
        )}
      </tbody>
    );
  }

  const header = (
    <thead>
      <tr>
        <th />
        <th>Fix</th>
        <th>Risk</th>
        <th>Why listed</th>
        <th style={{ width: 150 }}>Status</th>
      </tr>
    </thead>
  );

  return (
    <div>
      <div className="d-flex flex-wrap align-items-center gap-3 mb-2">
        <span className="small">
          <strong>{open.length}</strong> open action{open.length === 1 ? "" : "s"} covering{" "}
          <strong>{plan.summary.open_threats_covered}</strong> open threat
          {plan.summary.open_threats_covered === 1 ? "" : "s"}. Fixes for misconfigurations found in your configuration
          come first, then design-specific ones, then generic hardening.
        </span>
        <a className="ms-auto small" href={`${base}.csv`} download>
          Download checklist (CSV)
        </a>
      </div>

      {open.length === 0 ? (
        <p className="text-muted mb-0">No open actions: every threat is mitigated, accepted or not applicable.</p>
      ) : (
        <Table size="sm" hover responsive className="align-middle mb-2">
          {header}
          {listed.map((action, index) => row(action, index + 1))}
        </Table>
      )}
      {open.length > TOP_COUNT && (
        <Button variant="link" size="sm" className="p-0 mb-2" onClick={() => setShowAll((v) => !v)}>
          {showAll ? `Show only the top ${TOP_COUNT}` : `Show all ${open.length} open actions`}
        </Button>
      )}

      {closed.length > 0 && (
        <div className="mt-2">
          <Button variant="link" size="sm" className="p-0" onClick={() => setShowClosed((v) => !v)}>
            {showClosed ? "Hide" : "Show"} {closed.length} done or declined
          </Button>
          {showClosed && (
            <Table size="sm" responsive className="align-middle mt-2 mb-0">
              {header}
              {closed.map((action) => row(action, null))}
            </Table>
          )}
        </div>
      )}
    </div>
  );
}
