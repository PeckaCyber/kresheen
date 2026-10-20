import { useEffect, useState } from "react";
import { Button, Form } from "react-bootstrap";
import { apiFetch, ApiError } from "../api/client";
import { RiskBadge } from "../components/RiskBadge";
import { useToast } from "../components/Toasts";

export interface FixSpec {
  property_key: string;
  kind: "bool" | "text";
  options: string[];
  suggested_value: boolean | null;
  suggestion_reason: string;
  alternative: { key: string; value: boolean; label: string } | null;
}

export interface CompletenessItem {
  id: string;
  check: string;
  element_kind: "component" | "flow" | "model";
  element_id: string | null;
  element_name: string;
  message: string;
  why: string;
  impact: "high" | "medium" | "low";
  fix: FixSpec | null;
}

export interface CompletenessOut {
  score: number | null;
  answered: number;
  total: number;
  items: CompletenessItem[];
}

const CHECK_TITLES: Record<string, string> = {
  data_classification: "What data do these hold?",
  encrypted_at_rest: "Encryption at rest",
  authenticates_callers: "Authentication of callers",
  encrypted_in_transit: "Encryption in transit across trust boundaries",
  unanalysed_input: "Inputs that were not analysed",
  no_boundaries: "Trust boundaries",
  isolated_component: "Components not connected to anything",
  no_external_actor: "Users and third parties",
};
const GROUP_PREVIEW = 5;

export function scoreVariant(score: number | null): string {
  if (score === null) return "secondary";
  return score >= 80 ? "success" : score >= 50 ? "warning" : "danger";
}

// What the model does not say yet, with one-click answers. An
// answer is stored as an ordinary owner-stated property, so it changes threats and ranking
// exactly as if it had been set in the component's side panel.
export function CompletenessPanel({
  applicationId,
  runId,
  refreshKey,
  onLoaded,
  onAnswered,
}: {
  applicationId: string;
  runId: string;
  refreshKey?: unknown;
  onLoaded?: (out: CompletenessOut) => void;
  // Called after an answer is stored, so the page can reload the diagram and threats.
  onAnswered?: () => void | Promise<void>;
}) {
  const toast = useToast();
  const [data, setData] = useState<CompletenessOut | null>(null);
  const [failed, setFailed] = useState(false);
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const [busy, setBusy] = useState<string | null>(null);
  const url = `/api/applications/${applicationId}/runs/${runId}`;

  useEffect(() => {
    let current = true;
    apiFetch<CompletenessOut>(`${url}/completeness`)
      .then((out) => {
        if (!current) return;
        setData(out);
        setFailed(false);
        onLoaded?.(out);
      })
      .catch(() => current && setFailed(true));
    return () => {
      current = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [url, refreshKey]);

  async function answer(item: CompletenessItem, properties: Record<string, boolean | string>) {
    if (!item.element_id || item.element_kind === "model") return;
    setBusy(item.id);
    try {
      await apiFetch(`${url}/element-properties`, {
        method: "PATCH",
        body: JSON.stringify({ element_kind: item.element_kind, element_id: item.element_id, properties }),
      });
      await onAnswered?.();
      const out = await apiFetch<CompletenessOut>(`${url}/completeness`);
      setData(out);
      onLoaded?.(out);
      toast.success("Answer saved");
    } catch (err) {
      toast.error(err instanceof ApiError ? err.message : "Could not save that answer");
    } finally {
      setBusy(null);
    }
  }

  if (failed) return <p className="text-danger mb-0">Could not load the completeness check.</p>;
  if (!data) return <p className="text-muted mb-0">Loading...</p>;

  const groups: { check: string; items: CompletenessItem[] }[] = [];
  for (const item of data.items) {
    const group = groups.find((g) => g.check === item.check);
    if (group) group.items.push(item);
    else groups.push({ check: item.check, items: [item] });
  }

  function controls(item: CompletenessItem) {
    const fix = item.fix;
    if (!fix) return null;
    const disabled = busy === item.id;
    if (fix.kind === "bool") {
      return (
        <div className="d-flex flex-wrap align-items-center gap-2">
          {[true, false].map((value) => (
            <Button
              key={String(value)}
              size="sm"
              disabled={disabled}
              variant={fix.suggested_value === value ? "primary" : "outline-secondary"}
              title={fix.suggested_value === value ? `Suggested: ${fix.suggestion_reason}` : undefined}
              aria-label={`${value ? "Yes" : "No"}: ${item.message}`}
              onClick={() => void answer(item, { [fix.property_key]: value })}
            >
              {value ? "Yes" : "No"}
            </Button>
          ))}
          {fix.suggested_value !== null && (
            <span className="small text-muted">
              Suggested {fix.suggested_value ? "yes" : "no"}: {fix.suggestion_reason}
            </span>
          )}
        </div>
      );
    }
    return (
      <div className="d-flex flex-wrap align-items-center gap-2">
        <Form.Select
          size="sm"
          style={{ width: "auto" }}
          disabled={disabled}
          aria-label={item.message}
          value=""
          onChange={(e) => e.target.value && void answer(item, { [fix.property_key]: e.target.value })}
        >
          <option value="">Choose a class...</option>
          {fix.options.map((option) => (
            <option key={option} value={option}>
              {option}
            </option>
          ))}
        </Form.Select>
        {fix.alternative && (
          <Button
            size="sm"
            variant="outline-secondary"
            disabled={disabled}
            onClick={() => void answer(item, { [fix.alternative!.key]: fix.alternative!.value })}
          >
            {fix.alternative.label}
          </Button>
        )}
      </div>
    );
  }

  return (
    <div>
      {data.score === null ? (
        <p className="small text-muted">
          There are no component facts to ask about yet. Draw or ingest components and this will list what to state.
        </p>
      ) : (
        <div className="mb-3">
          {/* Plain markup: react-bootstrap's ProgressBar puts aria-label on the wrapper, leaving the
              element with role="progressbar" unnamed for screen readers. */}
          <div className="progress">
            <div
              className={`progress-bar bg-${scoreVariant(data.score)}`}
              role="progressbar"
              aria-label="Model completeness"
              aria-valuenow={data.score}
              aria-valuemin={0}
              aria-valuemax={100}
              style={{ width: `${data.score}%` }}
            >
              {data.score}%
            </div>
          </div>
          <div className="small text-muted mt-1">
            {data.answered} of {data.total} facts that shape your threats are stated. Unstated ones get the generic
            result, so answering them makes the threats and the action plan specific to your system.
          </div>
        </div>
      )}
      {groups.length === 0 ? (
        <p className="mb-0">Nothing left to state. The model has no open questions.</p>
      ) : (
        groups.map((group) => {
          const open = expanded[group.check] === true;
          const shown = open ? group.items : group.items.slice(0, GROUP_PREVIEW);
          return (
            <div key={group.check} className="mb-3">
              <h3 className="h6 mb-2">
                {CHECK_TITLES[group.check] ?? group.check}{" "}
                <RiskBadge level={group.items[0].impact} className="fw-normal">
                  {group.items.length}
                </RiskBadge>
              </h3>
              {shown.map((item) => (
                <div key={item.id} className="border-bottom py-2">
                  <div>{item.message}</div>
                  <div className="small text-muted mb-1">{item.why}</div>
                  {controls(item)}
                </div>
              ))}
              {group.items.length > GROUP_PREVIEW && (
                <Button
                  variant="link"
                  size="sm"
                  className="p-0 mt-1"
                  onClick={() => setExpanded((prev) => ({ ...prev, [group.check]: !open }))}
                >
                  {open ? "Show fewer" : `Show all ${group.items.length}`}
                </Button>
              )}
            </div>
          );
        })
      )}
    </div>
  );
}
