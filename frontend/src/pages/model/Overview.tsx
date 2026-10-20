import { useState } from "react";
import { Button } from "react-bootstrap";
import { apiFetch, ApiError } from "../../api/client";
import { RiskBadge } from "../../components/RiskBadge";
import { SEVERITY_ORDER, severityColor } from "../../severity";
import type { ActionOut, ActionPlanOut } from "../ActionPlanPanel";
import { AttackPathsPanel, type AttackPathOut } from "../AttackPathsPanel";
import { CompletenessPanel, type CompletenessItem, type CompletenessOut } from "../CompletenessPanel";
import { RunDiffPanel, type RunDiffOut } from "../RunDiffPanel";
import type { ThreatsOut } from "../ThreatsPanel";
import type { ModelTabKey } from "./ModelTabs";

const isOpenAction = (action: ActionOut) => action.status === "todo" || action.status === "in_progress";
const TOP_QUESTIONS = 3;
const TOP_ACTIONS = 5;

// Quick inline Yes/No for a boolean completeness question, mirroring
// CompletenessPanel's own `answer()` is not shared, so this is a small,
// self-contained duplicate of the same PATCH call, not a shared helper.
function QuickAnswer({
  applicationId,
  runId,
  item,
  onAnswered,
  onNeedsFullPanel,
}: {
  applicationId: string;
  runId: string;
  item: CompletenessItem;
  onAnswered: () => void | Promise<void>;
  onNeedsFullPanel: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const fix = item.fix;

  if (!fix || fix.kind !== "bool" || !item.element_id || item.element_kind === "model") {
    return (
      <Button variant="link" size="sm" className="p-0" onClick={onNeedsFullPanel}>
        Answer this in Model completeness below
      </Button>
    );
  }

  const propertyKey = fix.property_key;
  const suggestedValue = fix.suggested_value;

  async function answer(value: boolean) {
    if (!item.element_id) return;
    setBusy(true);
    setError(null);
    try {
      await apiFetch(`/api/applications/${applicationId}/runs/${runId}/element-properties`, {
        method: "PATCH",
        body: JSON.stringify({
          element_kind: item.element_kind,
          element_id: item.element_id,
          properties: { [propertyKey]: value },
        }),
      });
      await onAnswered();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not save that answer.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <div className="d-flex gap-2">
        {[true, false].map((value) => (
          <Button
            key={String(value)}
            size="sm"
            disabled={busy}
            variant={suggestedValue === value ? "primary" : "outline-secondary"}
            aria-label={`${value ? "Yes" : "No"}: ${item.message}`}
            onClick={() => void answer(value)}
          >
            {value ? "Yes" : "No"}
          </Button>
        ))}
      </div>
      {error && <div className="small text-danger mt-1">{error}</div>}
    </div>
  );
}

function WhatToDoNext({
  applicationId,
  runId,
  completeness,
  actionPlan,
  onAnswered,
  onGoToTab,
  onShowAllQuestions,
}: {
  applicationId: string;
  runId: string;
  completeness: CompletenessOut | null;
  actionPlan: ActionPlanOut | null;
  onAnswered: () => void | Promise<void>;
  onGoToTab: (tab: ModelTabKey) => void;
  onShowAllQuestions: () => void;
}) {
  const questions = (completeness?.items ?? []).slice(0, TOP_QUESTIONS);
  const openActions = (actionPlan?.actions ?? []).filter(isOpenAction).slice(0, TOP_ACTIONS);

  return (
    <section className="pc-panel mb-3" aria-label="What to do next">
      <div className="pc-panel-head">
        <span>What to do next</span>
      </div>
      <div className="pc-panel-body">
        <h3 className="h6">Questions that shape your threats</h3>
        {completeness === null ? (
          <p className="text-muted small mb-3">Loading...</p>
        ) : questions.length === 0 ? (
          <p className="text-muted small mb-3">Nothing left to state -- the model has no open questions.</p>
        ) : (
          <div className="mb-3">
            {questions.map((item) => (
              <div key={item.id} className="border-bottom py-2">
                <div>{item.message}</div>
                <div className="small text-muted mb-1">{item.why}</div>
                <QuickAnswer
                  applicationId={applicationId}
                  runId={runId}
                  item={item}
                  onAnswered={onAnswered}
                  onNeedsFullPanel={onShowAllQuestions}
                />
              </div>
            ))}
            {completeness.items.length > TOP_QUESTIONS && (
              <Button variant="link" size="sm" className="p-0 mt-1" onClick={onShowAllQuestions}>
                Answer all {completeness.items.length} questions
              </Button>
            )}
          </div>
        )}

        <h3 className="h6">Top fixes</h3>
        {actionPlan === null ? (
          <p className="text-muted small mb-0">Loading...</p>
        ) : openActions.length === 0 ? (
          <p className="text-muted small mb-0">No open actions: every threat is mitigated, accepted or not applicable.</p>
        ) : (
          <div>
            <ul className="list-unstyled mb-2">
              {openActions.map((action) => (
                <li key={action.id} className="d-flex align-items-start gap-2 border-bottom py-2">
                  <RiskBadge level={action.max_risk}>{action.max_risk}</RiskBadge>
                  <span className="flex-grow-1">{action.text}</span>
                  <span className="small text-muted">
                    {action.threat_count} threat{action.threat_count === 1 ? "" : "s"}
                  </span>
                </li>
              ))}
            </ul>
            <Button variant="link" size="sm" className="p-0" onClick={() => onGoToTab("actions")}>
              See the full action plan
            </Button>
          </div>
        )}
      </div>
    </section>
  );
}

function RiskBreakdown({ summary }: { summary: ThreatsOut["summary"] | undefined }) {
  const openByRisk = summary?.open_by_risk ?? {};
  const total = SEVERITY_ORDER.reduce((sum, s) => sum + (openByRisk[s] ?? 0), 0);
  return (
    <section className="pc-panel h-100" aria-label="Risk breakdown">
      <div className="pc-panel-head">
        <span>Risk breakdown</span>
      </div>
      <div className="pc-panel-body">
        {total === 0 ? (
          <p className="text-muted small mb-0">No open threats to break down.</p>
        ) : (
          <div>
            <div className="pc-segbar mb-3" role="img" aria-label="Open threats by risk">
              {SEVERITY_ORDER.filter((s) => (openByRisk[s] ?? 0) > 0).map((s) => (
                <span key={s} style={{ flexGrow: openByRisk[s], background: severityColor(s) }} title={`${s}: ${openByRisk[s]}`} />
              ))}
            </div>
            <ul className="list-unstyled mb-0 small">
              {SEVERITY_ORDER.map((s) => (
                <li key={s} className="d-flex align-items-center py-1">
                  <span className="pc-legend-swatch" style={{ background: severityColor(s) }} />
                  <span className="text-capitalize flex-grow-1">{s}</span>
                  <strong>{openByRisk[s] ?? 0}</strong>
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </section>
  );
}

function AttackPathsCard({ paths }: { paths: AttackPathOut[] | null }) {
  return (
    <section className="pc-panel h-100" aria-label="Attack paths">
      <div className="pc-panel-head">
        <span>Attack paths</span>
      </div>
      <div className="pc-panel-body">
        {paths === null ? (
          <p className="text-muted small mb-0">Loading...</p>
        ) : (
          <AttackPathsPanel paths={paths} />
        )}
      </div>
    </section>
  );
}

export function Overview({
  applicationId,
  runId,
  componentCount,
  completeness,
  actionPlan,
  threatsSummary,
  attackPaths,
  diff,
  refreshKey,
  onAnswered,
  onGoToTab,
  onCompletenessLoaded,
}: {
  applicationId: string;
  runId: string;
  componentCount: number;
  completeness: CompletenessOut | null;
  actionPlan: ActionPlanOut | null;
  threatsSummary: ThreatsOut["summary"] | undefined;
  attackPaths: AttackPathOut[] | null;
  diff: RunDiffOut | null;
  // Anything that changes when threats change (ApplicationDetail's threatsData), so
  // the completeness check re-fetches when triage changes it.
  refreshKey?: unknown;
  onAnswered: () => void | Promise<void>;
  onGoToTab: (tab: ModelTabKey) => void;
  // Lifts the full completeness check (score, items) up to ApplicationDetail --
  // the stat strip's Completeness tile and this panel's own top-3 preview both
  // read it from there. This is the only place CompletenessPanel is mounted now
  // that "Model completeness" is part of Overview rather than its own tab.
  onCompletenessLoaded: (out: CompletenessOut) => void;
}) {
  const [showAllQuestions, setShowAllQuestions] = useState(false);

  if (componentCount === 0) {
    return (
      <section className="pc-panel" aria-label="Start your model">
        <div className="pc-panel-body text-center py-5">
          <p className="mb-3">This model has no components yet.</p>
          <Button onClick={() => onGoToTab("diagram")}>Start by adding components on the Diagram tab</Button>
        </div>
      </section>
    );
  }

  return (
    <div>
      <WhatToDoNext
        applicationId={applicationId}
        runId={runId}
        completeness={completeness}
        actionPlan={actionPlan}
        onAnswered={onAnswered}
        onGoToTab={onGoToTab}
        onShowAllQuestions={() => setShowAllQuestions(true)}
      />
      <div className="row g-3 mb-3">
        <div className="col-md-6">
          <RiskBreakdown summary={threatsSummary} />
        </div>
        <div className="col-md-6">
          <AttackPathsCard paths={attackPaths} />
        </div>
      </div>
      <section className="pc-panel mb-3" aria-label="What changed since the last run">
        <div className="pc-panel-head">
          <span>What changed since the last run</span>
        </div>
        <div className="pc-panel-body">{diff ? <RunDiffPanel diff={diff} /> : <p className="text-muted small mb-0">Loading...</p>}</div>
      </section>
      <section className="pc-panel mb-3" id="model-completeness-section" aria-label="Model completeness">
        <div className="pc-panel-head d-flex justify-content-between align-items-center">
          <span>Model completeness</span>
          <Button variant="link" size="sm" className="p-0 text-uppercase" onClick={() => setShowAllQuestions((v) => !v)}>
            {showAllQuestions ? "Hide" : "Show all questions"}
          </Button>
        </div>
        {/* Always mounted (not conditionally rendered) so it fetches and keeps the
            lifted `completeness` state (stat strip, the top-3 preview above) current
            even while this disclosure is collapsed -- only its visibility toggles. */}
        <div className="pc-panel-body" style={{ display: showAllQuestions ? undefined : "none" }}>
          <CompletenessPanel
            applicationId={applicationId}
            runId={runId}
            refreshKey={refreshKey}
            onAnswered={onAnswered}
            onLoaded={onCompletenessLoaded}
          />
        </div>
      </section>
    </div>
  );
}
