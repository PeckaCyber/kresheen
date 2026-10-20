import { Fragment, useEffect, useMemo, useState } from "react";
import { Alert, Badge, Button, Form, Table } from "react-bootstrap";
import { apiFetch, ApiError } from "../api/client";
import { threatMethodologiesWith, methodologyCategories, isMethodologyAvailable, categoryLabel, categoryDescription, CIA_DESCRIPTIONS, methodologyDescription, type Methodology } from "../methodology";
import { RiskBadge } from "../components/RiskBadge";
import { InfoTip } from "../components/InfoTip";
import { useToast } from "../components/Toasts";
import { ExplainThreat } from "./ExplainThreat";

export type ThreatStatus = "open" | "mitigated" | "accepted" | "not_applicable";

export type CIAImpact = "Confidentiality" | "Integrity" | "Availability";

export interface DreadScore {
  damage: number;
  reproducibility: number;
  exploitability: number;
  affected_users: number;
  discoverability: number;
  average: number;
}

type DreadAxis = Exclude<keyof DreadScore, "average">;

const DREAD_AXES: { key: DreadAxis; label: string }[] = [
  { key: "damage", label: "Damage" },
  { key: "reproducibility", label: "Reproducibility" },
  { key: "exploitability", label: "Exploitability" },
  { key: "affected_users", label: "Affected users" },
  { key: "discoverability", label: "Discoverability" },
];

const DEFAULT_DREAD_DRAFT: Record<DreadAxis, number> = {
  damage: 5,
  reproducibility: 5,
  exploitability: 5,
  affected_users: 5,
  discoverability: 5,
};

export interface ThreatEvidence {
  finding_id: string;
  title: string;
  severity: string;
  // component: on this component. repository: found in the repo it was defined in, not confirmed in its image.
  scope: "component" | "repository";
}

export interface ThreatOut {
  key: string;
  rule_id: string;
  element_kind: "component" | "flow" | "boundary";
  element_id: string;
  element_name: string;
  element_type: string;
  methodology: Methodology;
  category: string | null;
  cia_impacts: CIAImpact[];
  title: string;
  description: string;
  // Impact of the threat if it happens (fixed by its rule).
  severity: "critical" | "high" | "medium" | "low";
  // Risk = impact x likelihood, what threats are ranked by. Absent on older responses.
  risk?: "critical" | "high" | "medium" | "low";
  // Why it is on the list: observed in the config/scan, specific to a stated fact, or a generic
  // checklist item (models/threat.py::Threat.basis). Absent on older responses.
  basis?: "observed" | "specific" | "generic";
  // How to check a mitigation worked, and an example fix (from a plugin; absent in the open-source core).
  verification?: string[];
  fix_example?: string;
  // The mitigation the example implements (a rule lists several alternatives).
  fix_example_for?: string;
  likelihood?: "very_rare" | "rare" | "possible" | "likely" | "almost_certain";
  likelihood_factors?: string[];
  // Findings that show the weakness is really there; they raise likelihood, they are not the threat.
  evidence?: ThreatEvidence[];
  evidence_total?: number;
  mitigations: string[];
  cwe_refs: string[];
  attack_refs: string[];
  risk_factors: string[];
  origin: "predefined" | "custom_rule" | "manual";
  taxonomy_ids?: string[];
  manual_threat_id: string | null;
  status: ThreatStatus;
  note: string;
  dread: DreadScore | null;
}

export interface CoverageGapOut {
  kind: string;
  name: string;
  reason: string;
}

export interface DocConflictOut {
  kind: string;
  name: string;
  reason: string;
}

export interface ThreatsOut {
  threats: ThreatOut[];
  summary: {
    total: number;
    by_status: Record<string, number>;
    open_by_severity: Record<string, number>;
    open_by_risk?: Record<string, number>;
  };
  // Entry-point facts (Ingress, RBAC bindings) no rule ever evaluated. Absent on older responses.
  coverage_gaps?: CoverageGapOut[];
  // A diagram component with no matching ingested infrastructure. Absent on older responses.
  doc_conflicts?: DocConflictOut[];
  // Methodologies selected on the application that this installation does not offer: nothing was generated for them.
  unavailable_methodologies?: string[];
}

export const STATUS_LABELS: Record<ThreatStatus, string> = {
  open: "Open",
  mitigated: "Mitigated",
  accepted: "Accepted",
  not_applicable: "Not applicable",
};

// Accepting a risk or calling it not applicable is a decision someone must justify later
// so both need a reason; the server enforces it too.
const REASON_REQUIRED: ThreatStatus[] = ["accepted", "not_applicable"];
const BULK_STATUSES: ThreatStatus[] = ["mitigated", "accepted", "not_applicable", "open"];

const STATUS_BADGE: Record<ThreatStatus, string> = {
  open: "danger",
  mitigated: "success",
  accepted: "warning",
  not_applicable: "secondary",
};

const CIA_BADGE: Record<CIAImpact, string> = {
  Confidentiality: "info",
  Integrity: "primary",
  Availability: "warning",
};

const LIKELIHOOD_LABELS: Record<string, string> = {
  very_rare: "very rare",
  rare: "rare",
  possible: "possible",
  likely: "likely",
  almost_certain: "almost certain",
};

function riskOf(threat: ThreatOut): ThreatOut["severity"] {
  return threat.risk ?? threat.severity;
}

interface ThreatsPanelProps {
  applicationId: string;
  runId: string;
  threats: ThreatOut[];
  // Called after a status is saved so the owner can refetch (summary counts live there).
  onChanged: () => void | Promise<void>;
  // Set to show only one component's threats (the node side panel); hides the element column.
  elementId?: string;
  // When given, an "Add threat" button is shown (opens the owner's add-threat dialog).
  onAddThreat?: () => void;
  // When given, manual threats get an "Edit this threat" button.
  onEditThreat?: (threat: ThreatOut) => void;
  // True for a model with no data sources: the empty state then explains drawing, not scanning.
  blankModel?: boolean;
  // Entry-point facts no rule ever evaluated (engine/threats/coverage.py). Shown once, not per element.
  coverageGaps?: CoverageGapOut[];
  // Diagram components with no matching ingested infrastructure (engine/threats/doc_conflicts.py).
  docConflicts?: DocConflictOut[];
  // Selected methodologies this installation cannot generate for (ThreatsOut.unavailable_methodologies).
  unavailableMethodologies?: string[];
  // Pre-selects the whole-model list's element filter (the side panel's "view all threats" link).
  presetElement?: { name: string; nonce: number } | null;
}

const BASIS_HINTS: Record<NonNullable<ThreatOut["basis"]>, string> = {
  observed: "Found in your ingested configuration or backed by a scanner finding",
  specific: "Applies because of a fact about this design (a boundary crossing, a stated property) or was added by hand",
  generic: "A generic checklist item that applies to any element of this type",
};

export function ThreatsPanel({
  applicationId,
  runId,
  threats,
  onChanged,
  elementId,
  onAddThreat,
  onEditThreat,
  blankModel,
  coverageGaps,
  docConflicts,
  unavailableMethodologies,
  presetElement,
}: ThreatsPanelProps) {
  const toast = useToast();
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [methodologyFilter, setMethodologyFilter] = useState<string>("all");
  const [categoryFilter, setCategoryFilter] = useState<string>("all");
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [elementFilter, setElementFilter] = useState<string>("all");
  const [showGeneric, setShowGeneric] = useState(false);
  // A status change that still needs its reason before it is sent.
  const [declining, setDeclining] = useState<{ key: string; status: ThreatStatus; reason: string } | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [bulk, setBulk] = useState<{ status: ThreatStatus; reason: string }>({ status: "mitigated", reason: "" });
  const [expandedKey, setExpandedKey] = useState<string | null>(null);
  const [noteDrafts, setNoteDrafts] = useState<Record<string, string>>({});
  const [dreadDrafts, setDreadDrafts] = useState<Record<string, Record<DreadAxis, number>>>({});

  const scoped = useMemo(
    () => (elementId ? threats.filter((t) => t.element_id === elementId) : threats),
    [threats, elementId],
  );
  useEffect(() => {
    if (presetElement) {
      setElementFilter(presetElement.name);
      setStatusFilter("all");
      setSeverityFilter("all");
      setMethodologyFilter("all");
      setCategoryFilter("all");
      setShowGeneric(true);
    }
  }, [presetElement]);
  const elementNames = useMemo(
    () => [...new Set(threats.map((t) => t.element_name))].sort((a, b) => a.localeCompare(b)),
    [threats],
  );
  const visible = scoped.filter(
    (t) =>
      (elementId !== undefined || elementFilter === "all" || t.element_name === elementFilter) &&
      (statusFilter === "all" || t.status === statusFilter) &&
      (methodologyFilter === "all" || t.methodology === methodologyFilter) &&
      (categoryFilter === "all" || t.category === categoryFilter) &&
      (severityFilter === "all" || riskOf(t) === severityFilter),
  );

  // On the whole-model list, generic checklist items are collapsed once anything more specific
  // exists, so real findings are not buried. A model that is all generic (a fresh hand-drawn one)
  // shows everything, or the user would see an empty list.
  const hasSpecific = scoped.some((t) => t.basis === "observed" || t.basis === "specific");
  const collapseGeneric = !elementId && hasSpecific && !showGeneric;
  const listed = collapseGeneric ? visible.filter((t) => t.basis !== "generic") : visible;
  const hiddenGeneric = visible.length - listed.length;
  const addressed = scoped.filter((t) => t.status !== "open").length;
  const addressedPct = scoped.length ? Math.round((100 * addressed) / scoped.length) : 0;
  const highOpen = scoped.filter((t) => t.status === "open" && (riskOf(t) === "critical" || riskOf(t) === "high")).length;
  const specificCount = scoped.filter((t) => t.basis === "observed" || t.basis === "specific").length;
  const genericCount = scoped.length - specificCount;

  function dreadDraftFor(threat: ThreatOut): Record<DreadAxis, number> {
    return (
      dreadDrafts[threat.key] ?? {
        damage: threat.dread?.damage ?? DEFAULT_DREAD_DRAFT.damage,
        reproducibility: threat.dread?.reproducibility ?? DEFAULT_DREAD_DRAFT.reproducibility,
        exploitability: threat.dread?.exploitability ?? DEFAULT_DREAD_DRAFT.exploitability,
        affected_users: threat.dread?.affected_users ?? DEFAULT_DREAD_DRAFT.affected_users,
        discoverability: threat.dread?.discoverability ?? DEFAULT_DREAD_DRAFT.discoverability,
      }
    );
  }

  async function saveStatus(threat: ThreatOut, status: ThreatStatus, note: string, dread?: Record<DreadAxis, number>) {
    try {
      await apiFetch(`/api/applications/${applicationId}/runs/${runId}/threats/status`, {
        method: "PUT",
        body: JSON.stringify({ threat_key: threat.key, status, note, ...(dread ? { dread } : {}) }),
      });
      setNoteDrafts((drafts) => {
        const { [threat.key]: _saved, ...rest } = drafts;
        return rest;
      });
      if (dread) {
        setDreadDrafts((drafts) => {
          const { [threat.key]: _saved, ...rest } = drafts;
          return rest;
        });
      }
      if (dread) {
        toast.success("DREAD score saved");
      } else if (status !== threat.status) {
        toast.success("Threat status updated");
      } else {
        toast.success("Saved");
      }
      await onChanged();
    } catch (err) {
      toast.error(err instanceof ApiError ? err.message : "Failed to save the threat status");
    }
  }

  function changeStatus(threat: ThreatOut, status: ThreatStatus) {
    if (REASON_REQUIRED.includes(status) && !threat.note.trim()) {
      setDeclining({ key: threat.key, status, reason: "" });
      return;
    }
    setDeclining(null);
    void saveStatus(threat, status, threat.note);
  }

  async function applyBulk() {
    const keys = [...selected].filter((key) => scoped.some((t) => t.key === key));
    if (keys.length === 0) return;
    try {
      await apiFetch(`/api/applications/${applicationId}/runs/${runId}/threats/status/bulk`, {
        method: "PUT",
        body: JSON.stringify({ threat_keys: keys, status: bulk.status, note: bulk.reason }),
      });
      setSelected(new Set());
      setBulk((prev) => ({ ...prev, reason: "" }));
      toast.success(`${keys.length} threats updated`);
      await onChanged();
    } catch (err) {
      toast.error(err instanceof ApiError ? err.message : "Failed to update those threats");
    }
  }

  function toggleSelected(key: string) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }

  async function deleteManualThreat(threat: ThreatOut) {
    if (!threat.manual_threat_id) return;
    try {
      await apiFetch(`/api/applications/${applicationId}/manual-threats/${threat.manual_threat_id}`, {
        method: "DELETE",
      });
      setExpandedKey(null);
      toast.success("Threat deleted");
      await onChanged();
    } catch (err) {
      toast.error(err instanceof ApiError ? err.message : "Failed to delete the threat");
    }
  }

  const addButton = onAddThreat && (
    <Button size="sm" variant="outline-primary" onClick={onAddThreat}>
      Add threat
    </Button>
  );

  const coverageBanner = !elementId && coverageGaps && coverageGaps.length > 0 && (
    <Alert variant="warning" className="mb-3">
      <strong>{coverageGaps.length}</strong> entry point{coverageGaps.length === 1 ? "" : "s"} in the ingested
      configuration {coverageGaps.length === 1 ? "was" : "were"} never evaluated by any rule (not the same as
      "no threat found"):
      <ul className="mb-0 mt-1">
        {coverageGaps.map((gap, i) => (
          <li key={i}>
            <code>{gap.name}</code>: {gap.reason}
          </li>
        ))}
      </ul>
    </Alert>
  );

  const unavailableBanner = !elementId && unavailableMethodologies && unavailableMethodologies.length > 0 && (
    <Alert variant="warning" className="mb-3">
      This model selects {unavailableMethodologies.join(", ")}, which {unavailableMethodologies.length === 1 ? "is" : "are"} not
      available in this installation, so no threats were generated for {unavailableMethodologies.length === 1 ? "it" : "them"} (not
      the same as "no threat found").
    </Alert>
  );

  const docConflictBanner = !elementId && docConflicts && docConflicts.length > 0 && (
    <Alert variant="warning" className="mb-3">
      <strong>{docConflicts.length}</strong> component{docConflicts.length === 1 ? "" : "s"} in the architecture
      diagram {docConflicts.length === 1 ? "doesn't" : "don't"} match anything ingested (documentation drift):
      <ul className="mb-0 mt-1">
        {docConflicts.map((c, i) => (
          <li key={i}>
            <code>{c.name}</code>: {c.reason}
          </li>
        ))}
      </ul>
    </Alert>
  );

  if (scoped.length === 0) {
    return (
      <div>
        {unavailableBanner}
        {coverageBanner}
        {docConflictBanner}
        <div className="d-flex justify-content-between align-items-center">
          <p className="text-muted mb-0">
            No threats generated{elementId ? " for this element" : ""}.
            {!elementId && (
              <>
                {" "}
                {blankModel ? (
                  <>
                    Threats are generated for each component and connection you draw. Add components in the
                    diagram&apos;s edit mode.
                  </>
                ) : (
                  <>
                    Threats are derived from the diagram&apos;s components, and this run has none. A repository scan
                    finds components only when the repository contains plain Kubernetes manifests (Helm templates
                    are not rendered). Attach a manifest, or add components in the diagram&apos;s edit mode.
                  </>
                )}
              </>
            )}
          </p>
          {addButton}
        </div>
      </div>
    );
  }

  return (
    <div>
      {unavailableBanner}
      {coverageBanner}
      {docConflictBanner}
      <div className="d-flex flex-wrap gap-2 mb-2 align-items-center">
        {!elementId && elementNames.length > 1 && (
          <Form.Select
            size="sm"
            style={{ width: "auto", maxWidth: 240 }}
            aria-label="Filter by element"
            value={elementFilter}
            onChange={(e) => setElementFilter(e.target.value)}
          >
            <option value="all">All elements</option>
            {elementNames.map((name) => (
              <option key={name} value={name}>
                {name}
              </option>
            ))}
          </Form.Select>
        )}
        <Form.Select
          size="sm"
          style={{ width: "auto" }}
          aria-label="Filter by status"
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
        >
          <option value="all">All statuses</option>
          {Object.entries(STATUS_LABELS).map(([value, label]) => (
            <option key={value} value={value}>
              {label}
            </option>
          ))}
        </Form.Select>
        {!elementId && (
        <Form.Select
          size="sm"
          style={{ width: "auto" }}
          aria-label="Filter by risk"
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
        >
          <option value="all">All risk levels</option>
          {["critical", "high", "medium", "low"].map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </Form.Select>
        )}
        {!elementId && (
        <Form.Select
          size="sm"
          style={{ width: "auto" }}
          aria-label="Filter by methodology"
          value={methodologyFilter}
          onChange={(e) => {
            setMethodologyFilter(e.target.value);
            setCategoryFilter("all");
          }}
        >
          <option value="all">All methodologies</option>
          {threatMethodologiesWith(threats.map((t) => t.methodology)).map((methodology) => (
            <option key={methodology} value={methodology}>
              {methodology}
            </option>
          ))}
        </Form.Select>
        )}
        {!elementId && (
        <Form.Select
          size="sm"
          style={{ width: "auto" }}
          aria-label="Filter by category"
          value={categoryFilter}
          onChange={(e) => setCategoryFilter(e.target.value)}
          disabled={methodologyFilter === "all"}
        >
          <option value="all">All categories</option>
          {methodologyFilter !== "all" &&
            (methodologyFilter === "Custom" || !isMethodologyAvailable(methodologyFilter)
              ? [...new Set(threats.filter((t) => t.methodology === methodologyFilter && t.category).map((t) => t.category as string))]
              : methodologyCategories(methodologyFilter)
            ).map((category) => (
              <option key={category} value={category}>
                {categoryLabel(methodologyFilter, category)}
              </option>
            ))}
        </Form.Select>
        )}
        {addButton && <div className="ms-auto">{addButton}</div>}
      </div>

      {!elementId && scoped.length > 0 && (
        <div className="mb-3">
          <div className="progress" style={{ height: 18 }}>
            <div
              className="progress-bar bg-success"
              role="progressbar"
              aria-label="Threats addressed"
              aria-valuenow={addressedPct}
              aria-valuemin={0}
              aria-valuemax={100}
              style={{ width: `${addressedPct}%` }}
            >
              {addressedPct > 8 ? `${addressedPct}%` : ""}
            </div>
          </div>
          <div className="small text-muted mt-1">
            <strong>{addressed}</strong> of {scoped.length} addressed (mitigated, accepted or not applicable).{" "}
            {highOpen === 0 ? "No high or critical risk threats are still open." : `${highOpen} high or critical risk still open.`}
          </div>
        </div>
      )}
      {selected.size > 0 && (
        <div className="d-flex flex-wrap align-items-center gap-2 p-2 mb-2 border rounded bg-body-tertiary" role="region" aria-label="Bulk actions">
          <strong className="small">{selected.size} selected</strong>
          <Form.Select
            size="sm"
            style={{ width: "auto" }}
            aria-label="Set selected threats to"
            value={bulk.status}
            onChange={(e) => setBulk((prev) => ({ ...prev, status: e.target.value as ThreatStatus }))}
          >
            {BULK_STATUSES.map((status) => (
              <option key={status} value={status}>
                {STATUS_LABELS[status]}
              </option>
            ))}
          </Form.Select>
          <Form.Control
            size="sm"
            style={{ width: 280 }}
            aria-label="Reason for the selected threats"
            placeholder={REASON_REQUIRED.includes(bulk.status) ? "Reason (required)" : "Note (optional)"}
            value={bulk.reason}
            onChange={(e) => setBulk((prev) => ({ ...prev, reason: e.target.value }))}
          />
          <Button size="sm" disabled={REASON_REQUIRED.includes(bulk.status) && !bulk.reason.trim()} onClick={() => void applyBulk()}>
            Apply
          </Button>
          <Button size="sm" variant="outline-secondary" onClick={() => setSelected(new Set())}>
            Clear selection
          </Button>
        </div>
      )}
      {!elementId && hasSpecific && genericCount > 0 && (
        <p className="small text-muted mb-2">
          <strong>{specificCount}</strong> observed in your configuration or specific to facts you stated;{" "}
          <strong>{genericCount}</strong> generic checklist item{genericCount === 1 ? "" : "s"} that apply to any
          element of that type.{" "}
          <Button variant="link" size="sm" className="p-0 align-baseline" onClick={() => setShowGeneric((v) => !v)}>
            {showGeneric ? "Hide the generic checklist" : "Show the generic checklist"}
          </Button>
        </p>
      )}
      {listed.length === 0 ? (
        <p className="text-muted mb-0">
          {hiddenGeneric > 0
            ? `Only generic checklist items match these filters (${hiddenGeneric}). Use "Show the generic checklist" above.`
            : "No threats match these filters."}
        </p>
      ) : (
        <Table size="sm" hover responsive className="mb-0 align-middle">
          <thead>
            <tr>
              {!elementId && (
                <th style={{ width: 28 }}>
                  <Form.Check
                    type="checkbox"
                    aria-label="Select all listed threats"
                    checked={listed.length > 0 && listed.every((t) => selected.has(t.key))}
                    onChange={(e) => setSelected(e.target.checked ? new Set(listed.map((t) => t.key)) : new Set())}
                  />
                </th>
              )}
              <th>Risk</th>
              {!elementId && <th>Element</th>}
              {!elementId && <th>Category</th>}
              <th>Threat</th>
              {!elementId && <th>Status</th>}
            </tr>
          </thead>
          <tbody>
            {listed.map((threat) => {
              const expanded = expandedKey === threat.key;
              const noteDraft = noteDrafts[threat.key] ?? threat.note;
              return (
                <Fragment key={threat.key}>
                  <tr
                    style={{ cursor: "pointer" }}
                    onClick={() => setExpandedKey(expanded ? null : threat.key)}
                    aria-expanded={expanded}
                  >
                    {!elementId && (
                      <td onClick={(e) => e.stopPropagation()}>
                        <Form.Check
                          type="checkbox"
                          aria-label={`Select ${threat.title}`}
                          checked={selected.has(threat.key)}
                          onChange={() => toggleSelected(threat.key)}
                        />
                      </td>
                    )}
                    <td>
                      <RiskBadge
                        level={riskOf(threat)}
                        title={`Impact ${threat.severity} × likelihood ${LIKELIHOOD_LABELS[threat.likelihood ?? "possible"]}`}
                      >
                        {riskOf(threat)}
                      </RiskBadge>
                      {(threat.evidence_total ?? 0) > 0 && (
                        <Badge bg="dark" className="ms-1" title="Findings supporting this threat">
                          {threat.evidence_total}
                        </Badge>
                      )}
                    </td>
                    {!elementId && <td>{threat.element_name}</td>}
                    {!elementId && (
                    <td>
                      {threat.category ? (
                        <>
                          <div>
                            <InfoTip text={methodologyDescription(threat.methodology)}>
                              {threat.methodology}
                            </InfoTip>
                          </div>
                          <div className="small text-muted">
                            <InfoTip text={categoryDescription(threat.methodology, threat.category)}>
                              {categoryLabel(threat.methodology, threat.category)}
                            </InfoTip>
                          </div>
                        </>
                      ) : (
                        "—"
                      )}
                      {(threat.cia_impacts ?? []).map((impact) => (
                        <InfoTip key={impact} text={CIA_DESCRIPTIONS[impact]}>
                          <Badge bg={CIA_BADGE[impact]} className="me-1 mt-1" title={impact}>
                            {impact[0]}
                          </Badge>
                        </InfoTip>
                      ))}
                    </td>
                    )}
                    <td>
                      {threat.title}
                      {/* `taxonomy_ids` (the validation harness's T01-T17 ids) stay in the API and
                          exports but are not shown: they mean nothing to a user. */}
                      {threat.basis && (
                        <Badge
                          bg={threat.basis === "observed" ? "danger" : threat.basis === "specific" ? "primary" : "light"}
                          text={threat.basis === "generic" ? "muted" : undefined}
                          className="ms-2 fw-normal"
                          title={BASIS_HINTS[threat.basis]}
                        >
                          {threat.basis}
                        </Badge>
                      )}
                      {threat.origin !== "predefined" && (
                        <Badge bg={threat.origin === "manual" ? "primary" : "info"} className="ms-2">
                          {threat.origin === "manual" ? "Manual" : "Custom rule"}
                        </Badge>
                      )}
                      {elementId && (
                        <div className="small text-muted mt-1">
                          <InfoTip text={methodologyDescription(threat.methodology)}>
                            {threat.methodology}
                          </InfoTip>
                          {threat.category && (
                            <>
                              {": "}
                              <InfoTip text={categoryDescription(threat.methodology, threat.category)}>
                                {categoryLabel(threat.methodology, threat.category)}
                              </InfoTip>
                            </>
                          )}
                          {" \u00b7 "}
                          {STATUS_LABELS[threat.status] ?? threat.status}
                        </div>
                      )}
                    </td>
                    {!elementId && (
                      <td onClick={(e) => e.stopPropagation()}>
                      <Form.Select
                        size="sm"
                        style={{ minWidth: 150 }}
                        aria-label={`Status for ${threat.title}`}
                        value={threat.status}
                        onChange={(e) => changeStatus(threat, e.target.value as ThreatStatus)}
                      >
                        {Object.entries(STATUS_LABELS).map(([value, label]) => (
                          <option key={value} value={value}>
                            {label}
                          </option>
                        ))}
                      </Form.Select>
                      </td>
                    )}
                  </tr>
                  {declining?.key === threat.key && (
                    <tr>
                      <td colSpan={elementId ? 2 : 6} className="bg-body-tertiary">
                        <Form.Label className="small mb-1">
                          Why is this {declining.status === "accepted" ? "risk accepted" : "not applicable"}? (required)
                        </Form.Label>
                        <div className="d-flex gap-2">
                          <Form.Control
                            size="sm"
                            aria-label="Reason for this status"
                            value={declining.reason}
                            onChange={(e) => setDeclining({ ...declining, reason: e.target.value })}
                          />
                          <Button
                            size="sm"
                            disabled={!declining.reason.trim()}
                            onClick={() => {
                              const pending = declining;
                              setDeclining(null);
                              void saveStatus(threat, pending.status, pending.reason);
                            }}
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
                  {expanded && (
                    <tr>
                      <td colSpan={elementId ? 2 : 6} className="bg-body-tertiary">
                        {elementId && (
                          <div className="mb-2" onClick={(e) => e.stopPropagation()}>
                            <Form.Label className="small mb-1">Status</Form.Label>
                      <Form.Select
                        size="sm"
                        style={{ maxWidth: 220 }}
                        aria-label={`Status for ${threat.title}`}
                        value={threat.status}
                        onChange={(e) => changeStatus(threat, e.target.value as ThreatStatus)}
                      >
                        {Object.entries(STATUS_LABELS).map(([value, label]) => (
                          <option key={value} value={value}>
                            {label}
                          </option>
                        ))}
                      </Form.Select>
                          </div>
                        )}
                        <p className="mb-2">{threat.description}</p>
                        <ExplainThreat key={threat.key} applicationId={applicationId} runId={runId} threatKey={threat.key} />
                        {threat.risk_factors.length > 0 && (
                          <p className="small mb-2">
                            <strong>Why it applies:</strong> {threat.risk_factors.join("; ")}
                          </p>
                        )}
                        {threat.likelihood && (
                          <p className="small mb-2">
                            <strong>Risk:</strong> {riskOf(threat)} (impact {threat.severity} × likelihood{" "}
                            {LIKELIHOOD_LABELS[threat.likelihood]})
                            {(threat.likelihood_factors ?? []).length > 0 && (
                              <> — {(threat.likelihood_factors ?? []).join("; ")}</>
                            )}
                          </p>
                        )}
                        {(threat.evidence ?? []).length > 0 && (
                          <div className="small mb-2">
                            <strong>Supporting findings</strong>
                            <ul className="mb-1">
                              {(threat.evidence ?? []).map((item) => (
                                <li key={item.finding_id}>
                                  <RiskBadge level={item.severity} className="me-1">
                                    {item.severity}
                                  </RiskBadge>
                                  {item.title}
                                  {item.scope === "repository" && (
                                    <span className="text-muted"> (source repository, not confirmed in this component)</span>
                                  )}
                                </li>
                              ))}
                            </ul>
                            {(threat.evidence_total ?? 0) > (threat.evidence ?? []).length && (
                              <span className="text-muted">
                                and {(threat.evidence_total ?? 0) - (threat.evidence ?? []).length} more, lower severity
                              </span>
                            )}
                          </div>
                        )}
                        <p className="small fw-semibold mb-1">Suggested mitigations</p>
                        {threat.mitigations.length === 0 ? (
                          <p className="small text-muted">None recorded.</p>
                        ) : (
                          <ul className="small">
                            {threat.mitigations.map((mitigation) => (
                              <li key={mitigation}>{mitigation}</li>
                            ))}
                          </ul>
                        )}
                        {(threat.verification ?? []).length > 0 && (
                          <>
                            <p className="small fw-semibold mb-1">How to verify</p>
                            <ul className="small">
                              {(threat.verification ?? []).map((step) => (
                                <li key={step}>{step}</li>
                              ))}
                            </ul>
                          </>
                        )}
                        {threat.fix_example && (
                          <>
                            <p className="small fw-semibold mb-1">
                              Example fix{threat.fix_example_for ? ` for: ${threat.fix_example_for}` : ""}
                            </p>
                            <pre className="small border rounded p-2 bg-body" aria-label="Example fix">
                              {threat.fix_example}
                            </pre>
                          </>
                        )}
                        <p className="small text-muted mb-2">
                          {[...threat.cwe_refs, ...threat.attack_refs].join(" · ")}
                        </p>
                        <Form.Group controlId={`threat-note-${threat.key}`}>
                          <Form.Label className="small mb-1">Note (why mitigated, accepted, or not applicable)</Form.Label>
                          <Form.Control
                            as="textarea"
                            rows={2}
                            maxLength={2000}
                            value={noteDraft}
                            onChange={(e) => setNoteDrafts((d) => ({ ...d, [threat.key]: e.target.value }))}
                          />
                        </Form.Group>
                        <Button
                          size="sm"
                          className="mt-2"
                          disabled={noteDraft === threat.note}
                          onClick={() => void saveStatus(threat, threat.status, noteDraft)}
                        >
                          Save note
                        </Button>

                        <div className="mt-3">
                          <p className="small fw-semibold mb-1">DREAD score (optional)</p>
                          <div className="d-flex flex-wrap gap-2 mb-2">
                            {DREAD_AXES.map((axis) => (
                              <Form.Group key={axis.key} controlId={`dread-${axis.key}-${threat.key}`} style={{ width: 110 }}>
                                <Form.Label className="small mb-0">{axis.label}</Form.Label>
                                <Form.Control
                                  type="number"
                                  size="sm"
                                  min={1}
                                  max={10}
                                  value={dreadDraftFor(threat)[axis.key]}
                                  onChange={(e) =>
                                    setDreadDrafts((d) => ({
                                      ...d,
                                      [threat.key]: {
                                        ...dreadDraftFor(threat),
                                        [axis.key]: Math.min(10, Math.max(1, Number(e.target.value) || 1)),
                                      },
                                    }))
                                  }
                                />
                              </Form.Group>
                            ))}
                          </div>
                          <p className="small text-muted mb-1">
                            Average:{" "}
                            {(
                              Object.values(dreadDraftFor(threat)).reduce((sum, v) => sum + v, 0) / DREAD_AXES.length
                            ).toFixed(1)}
                          </p>
                          <Button
                            size="sm"
                            variant="outline-primary"
                            onClick={() => void saveStatus(threat, threat.status, threat.note, dreadDraftFor(threat))}
                          >
                            Save DREAD score
                          </Button>
                        </div>

                        {threat.origin === "manual" && onEditThreat && (
                          <Button
                            size="sm"
                            variant="outline-primary"
                            className="mt-2 ms-2"
                            onClick={() => onEditThreat(threat)}
                          >
                            Edit this threat
                          </Button>
                        )}
                        {threat.origin === "manual" && (
                          <Button
                            size="sm"
                            variant="outline-danger"
                            className="mt-2 ms-2"
                            onClick={() => void deleteManualThreat(threat)}
                          >
                            Delete this threat
                          </Button>
                        )}
                      </td>
                    </tr>
                  )}
                </Fragment>
              );
            })}
          </tbody>
        </Table>
      )}
    </div>
  );
}

// `notAnalysed`: some input was stored but never analysed (sourceStatus.ts),
// so "0 open" must not read as a clean bill of health.
export function threatHeaderBadge(summary: ThreatsOut["summary"] | undefined, notAnalysed = false) {
  if (!summary) return null;
  if (notAnalysed && !summary.by_status.open) {
    return (
      <Badge bg="warning" text="dark" className="ms-2">
        0 open, some inputs not analysed
      </Badge>
    );
  }
  return (
    <Badge bg={summary.by_status.open ? STATUS_BADGE.open : STATUS_BADGE.mitigated} className="ms-2">
      {summary.by_status.open ?? 0} open
    </Badge>
  );
}
