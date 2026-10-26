import { useEffect, useState, type FormEvent, type MouseEvent } from "react";
import { Alert, Badge, Button, Dropdown, Form, Modal, Table } from "react-bootstrap";
import { useNavigate, useSearchParams } from "react-router-dom";
import { apiFetch, ApiError } from "../api/client";
import { extensions } from "../extensions";
import { useToast } from "../components/Toasts";
import { PageHeader } from "../components/PageHeader";
import { CreateApplicationModal, type CreatePreset } from "./CreateApplicationModal";
import { IntakeWizard } from "./IntakeWizard";
import { Onboarding } from "./Onboarding";
import { SAMPLES, type SampleKey } from "./samples";
import { worseOf } from "./threatSignal";
import { RiskBadge } from "../components/RiskBadge";
import { DashboardApplication } from "./dashboard/types";

export interface RollupOut {
  application_count: number;
  worst_severity: string | null;
  finding_count: number;
  stale_count: number;
  open_threat_count?: number;
  worst_threat_risk?: string | null;
  not_analysed_count?: number;
}

export interface GroupOut {
  id: string;
  name: string;
  description: string;
  created_at: string;
  rollup: RollupOut;
  my_role?: string | null;
}

interface GroupListOut {
  groups: GroupOut[];
  ungrouped: RollupOut;
  overall: RollupOut;
}

// Path segment (and `group_id` query value) for applications with no group.
export const UNGROUPED_ID = "ungrouped";

type SortKey =
  "name" | "group" | "worst_risk" | "open_threats" | "addressed" | "completeness" | "last_run" | "reviewed";
type SortOrder = "asc" | "desc";

interface SortState {
  key: SortKey;
  order: SortOrder;
}

function formatDaysAgo(days: number | null): string {
  if (days === null) return "never";
  if (days === 0) return "today";
  return `${days} day${days === 1 ? "" : "s"} ago`;
}

function formatReviewedDate(reviewedAt: string | null): string {
  if (!reviewedAt) return "never";
  const date = new Date(reviewedAt);
  return date.toLocaleDateString("en-US", { month: "short", day: "numeric", year: "2-digit" });
}

function formatAddressedPercent(addressed: number, total: number): string {
  if (total === 0) return "–";
  return `${Math.round((addressed / total) * 100)}%`;
}

function formatCompletenessPercent(score: number | null): string {
  if (score === null) return "–";
  return `${score}%`;
}

function getWorstRisk(app: DashboardApplication): string | null {
  return worseOf(app.worst_severity, app.worst_threat_risk);
}

export function GroupsPage() {
  const toast = useToast();
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const [applications, setApplications] = useState<DashboardApplication[] | null>(null);
  const [groups, setGroups] = useState<GroupOut[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState("");
  const [sortState, setSortState] = useState<SortState>({ key: "worst_risk", order: "desc" });
  const selectedGroupId = searchParams.get("group") ?? null;

  // Group management modals
  const [editing, setEditing] = useState<GroupOut | null>(null);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<GroupOut | null>(null);
  const [showGroupsModal, setShowGroupsModal] = useState(false);

  // Create/upload modals
  const [createOpen, setCreateOpen] = useState(false);
  const [describeOpen, setDescribeOpen] = useState(false);
  const [createPreset, setCreatePreset] = useState<CreatePreset | undefined>(undefined);
  const [sampleBusy, setSampleBusy] = useState<SampleKey | null>(null);

  function loadApplications() {
    return apiFetch<{ applications: DashboardApplication[] }>("/api/dashboard")
      .then(({ applications }) => setApplications(applications))
      .catch(() => setError("Failed to load threat models."));
  }

  function loadGroups() {
    return apiFetch<GroupListOut>("/api/groups")
      .then(({ groups }) => setGroups(groups))
      .catch(() => setError("Failed to load groups."));
  }

  useEffect(() => {
    void loadApplications();
    void loadGroups();
  }, []);

  function openCreate(preset?: CreatePreset) {
    setCreatePreset(preset);
    setCreateOpen(true);
  }

  async function handleSample(sample: SampleKey) {
    setSampleBusy(sample);
    try {
      const out = await apiFetch<{ application_id: string; run_id: string }>("/api/applications/sample", {
        method: "POST",
        body: JSON.stringify({ sample }),
      });
      navigate(`/applications/${out.application_id}/runs/${out.run_id}`);
    } catch (err) {
      toast.error(err instanceof ApiError ? err.message : "Could not create the sample model");
    } finally {
      setSampleBusy(null);
    }
  }

  function openForm(group: GroupOut | null) {
    setEditing(group);
    setName(group?.name ?? "");
    setDescription(group?.description ?? "");
    setFormError(null);
    setShowGroupsModal(true);
  }

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setSubmitting(true);
    setFormError(null);
    try {
      await apiFetch(editing ? `/api/groups/${editing.id}` : "/api/groups", {
        method: editing ? "PUT" : "POST",
        body: JSON.stringify({ name, description }),
      });
      setName("");
      setDescription("");
      setEditing(null);
      await loadGroups();
    } catch (err) {
      setFormError(err instanceof ApiError ? err.message : "Failed to save the group.");
    } finally {
      setSubmitting(false);
    }
  }

  async function handleDeleteConfirmed() {
    if (!deleteTarget) return;
    try {
      await apiFetch(`/api/groups/${deleteTarget.id}`, { method: "DELETE" });
      await loadGroups();
      toast.success("Group deleted");
    } catch {
      toast.error("Failed to delete the group");
    } finally {
      setDeleteTarget(null);
    }
  }

  async function handleDeleteApplication(app: DashboardApplication) {
    try {
      await apiFetch(`/api/applications/${app.id}`, { method: "DELETE" });
      await loadApplications();
      toast.success("Threat model deleted");
    } catch {
      toast.error("Failed to delete the threat model");
    }
  }

  async function handleMoveApplication(app: DashboardApplication, newGroupId: string) {
    try {
      await apiFetch(`/api/applications/${app.id}/group`, {
        method: "PATCH",
        body: JSON.stringify({ group_id: newGroupId === UNGROUPED_ID ? null : newGroupId }),
      });
      await loadApplications();
      toast.success("Threat model moved");
    } catch (err) {
      toast.error(err instanceof ApiError ? err.message : "Failed to move the threat model");
    }
  }

  // Filter applications
  const filtered = (applications ?? []).filter((app) => {
    // Search filter
    if (searchTerm && !app.name.toLowerCase().includes(searchTerm.toLowerCase())) {
      return false;
    }
    // Group filter
    if (selectedGroupId !== null) {
      const appGroupId = app.group_id ?? UNGROUPED_ID;
      if (appGroupId !== selectedGroupId) {
        return false;
      }
    }
    return true;
  });

  // Sort applications
  const sorted = [...filtered].sort((a, b) => {
    let aVal: any;
    let bVal: any;

    switch (sortState.key) {
      case "name":
        aVal = a.name.toLowerCase();
        bVal = b.name.toLowerCase();
        break;
      case "group":
        aVal = (a.group_name ?? "Ungrouped").toLowerCase();
        bVal = (b.group_name ?? "Ungrouped").toLowerCase();
        break;
      case "worst_risk": {
        const aRisk = getWorstRisk(a);
        const bRisk = getWorstRisk(b);
        // Higher is worse, so "desc" puts critical first and "none" last.
        const badness: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
        aVal = badness[aRisk ?? ""] ?? 0;
        bVal = badness[bRisk ?? ""] ?? 0;
        break;
      }
      case "open_threats":
        aVal = a.open_threat_count;
        bVal = b.open_threat_count;
        break;
      case "addressed":
        aVal = a.total_threat_count > 0 ? a.addressed_count / a.total_threat_count : 0;
        bVal = b.total_threat_count > 0 ? b.addressed_count / b.total_threat_count : 0;
        break;
      case "completeness":
        aVal = a.completeness_score ?? -1;
        bVal = b.completeness_score ?? -1;
        break;
      case "last_run":
        aVal = a.days_since_run ?? 999;
        bVal = b.days_since_run ?? 999;
        break;
      case "reviewed":
        // "never" sorts last; null dates sort as Infinity
        aVal = a.reviewed_at ? new Date(a.reviewed_at).getTime() : -Infinity;
        bVal = b.reviewed_at ? new Date(b.reviewed_at).getTime() : -Infinity;
        break;
    }

    let result = aVal < bVal ? -1 : aVal > bVal ? 1 : 0;
    // Equal risk: more open threats first (in the column's direction).
    if (result === 0 && sortState.key === "worst_risk") result = a.open_threat_count - b.open_threat_count;
    return sortState.order === "desc" ? -result : result;
  });

  const handleSort = (key: SortKey) => {
    if (sortState.key === key) {
      setSortState({ key, order: sortState.order === "asc" ? "desc" : "asc" });
    } else {
      setSortState({ key, order: key === "name" ? "asc" : "desc" });
    }
  };

  const SortIcon = ({ colKey }: { colKey: SortKey }) => {
    if (sortState.key !== colKey) return null;
    return <span className="ms-1">{sortState.order === "asc" ? "▲" : "▼"}</span>;
  };

  const stop = (event: MouseEvent, action: () => void) => {
    event.stopPropagation();
    action();
  };

  const actions = (
    <>
      <Dropdown>
        <Dropdown.Toggle variant="primary" id="new-threat-model">
          New threat model
        </Dropdown.Toggle>
        <Dropdown.Menu>
          <Dropdown.Item onClick={() => setDescribeOpen(true)}>Describe your system (guided)</Dropdown.Item>
          <Dropdown.Item onClick={() => openCreate()}>Upload files or connect a repository</Dropdown.Item>
          <Dropdown.Item onClick={() => openCreate("blank")}>Draw it yourself</Dropdown.Item>
          <Dropdown.Divider />
          <Dropdown.Header>Explore a sample</Dropdown.Header>
          {SAMPLES.map((sample) => (
            <Dropdown.Item
              key={sample.key}
              disabled={sampleBusy !== null}
              onClick={() => void handleSample(sample.key)}
            >
              {sampleBusy === sample.key ? "Creating the sample..." : `Sample: ${sample.title}`}
            </Dropdown.Item>
          ))}
        </Dropdown.Menu>
      </Dropdown>
      <Button variant="outline-secondary" onClick={() => setShowGroupsModal(true)}>
        Manage groups
      </Button>
    </>
  );

  return (
    <div className="pc-page">
      <PageHeader
        title="Threat models"
        subtitle="Every threat model you can see. Filter by group, search, or sort any column."
        actions={actions}
      />

      {error && <Alert variant="danger">{error}</Alert>}

      {!applications ? (
        <p>Loading...</p>
      ) : (
        <>
          {applications.length === 0 && (
            <Onboarding
              onPick={(preset) => openCreate(preset)}
              onDescribe={() => setDescribeOpen(true)}
              onSample={(sample) => void handleSample(sample)}
              sampleBusy={sampleBusy}
            />
          )}
          {applications.length > 0 && (
            <>
              <div className="mb-3 d-flex gap-3 align-items-center flex-wrap">
                <Form.Control
                  type="text"
                  placeholder="Search threat models..."
                  aria-label="Search threat models"
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  style={{ maxWidth: 300 }}
                />
                <Form.Select
                  aria-label="Group"
                  value={selectedGroupId ?? "all"}
                  onChange={(e) => {
                    const val = e.target.value;
                    if (val === "all") {
                      searchParams.delete("group");
                    } else {
                      searchParams.set("group", val);
                    }
                    setSearchParams(searchParams);
                  }}
                  style={{ maxWidth: 200 }}
                >
                  <option value="all">All groups</option>
                  <option value={UNGROUPED_ID}>Ungrouped</option>
                  {groups.map((g) => (
                    <option key={g.id} value={g.id}>
                      {g.name}
                    </option>
                  ))}
                </Form.Select>
                <span className="text-muted">
                  Showing {sorted.length} of {applications.length}
                </span>
              </div>

              <Table hover responsive>
                <thead>
                  <tr>
                    <th style={{ cursor: "pointer" }} onClick={() => handleSort("name")}>
                      Name <SortIcon colKey="name" />
                    </th>
                    <th style={{ cursor: "pointer" }} onClick={() => handleSort("group")}>
                      Group <SortIcon colKey="group" />
                    </th>
                    <th style={{ cursor: "pointer" }} onClick={() => handleSort("worst_risk")}>
                      Worst risk <SortIcon colKey="worst_risk" />
                    </th>
                    <th style={{ cursor: "pointer" }} onClick={() => handleSort("open_threats")}>
                      Open threats <SortIcon colKey="open_threats" />
                    </th>
                    <th style={{ cursor: "pointer" }} onClick={() => handleSort("addressed")}>
                      Addressed <SortIcon colKey="addressed" />
                    </th>
                    <th style={{ cursor: "pointer" }} onClick={() => handleSort("completeness")}>
                      Completeness <SortIcon colKey="completeness" />
                    </th>
                    <th style={{ cursor: "pointer" }} onClick={() => handleSort("last_run")}>
                      Last run <SortIcon colKey="last_run" />
                    </th>
                    <th style={{ cursor: "pointer" }} onClick={() => handleSort("reviewed")}>
                      Reviewed <SortIcon colKey="reviewed" />
                    </th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {sorted.map((app) => {
                    const worstRisk = getWorstRisk(app);
                    const modelLink = app.latest_run_id
                      ? `/applications/${app.id}/runs/${app.latest_run_id}`
                      : `/models/${app.id}`;
                    return (
                      <tr key={app.id}>
                        <td>
                          <Button variant="link" className="p-0" onClick={() => navigate(modelLink)}>
                            {app.name}
                          </Button>
                          <div className="d-flex gap-1 mt-1 flex-wrap">
                            {app.stale && (
                              <Badge bg="warning" text="dark">
                                needs re-run
                              </Badge>
                            )}
                            {app.not_analysed && (
                              <Badge bg="warning" text="dark">
                                inputs not analysed
                              </Badge>
                            )}
                          </div>
                        </td>
                        <td>{app.group_name ?? "Ungrouped"}</td>
                        <td>{worstRisk ? <RiskBadge level={worstRisk}>{worstRisk}</RiskBadge> : "none"}</td>
                        <td>{app.open_threat_count}</td>
                        <td>{formatAddressedPercent(app.addressed_count, app.total_threat_count)}</td>
                        <td>{formatCompletenessPercent(app.completeness_score)}</td>
                        <td>{formatDaysAgo(app.days_since_run)}</td>
                        <td>{formatReviewedDate(app.reviewed_at)}</td>
                        <td>
                          <Dropdown>
                            <Dropdown.Toggle variant="outline-secondary" size="sm" id={`app-menu-${app.id}`} />
                            <Dropdown.Menu>
                              <Dropdown.Item
                                onClick={(e) =>
                                  stop(e, () => {
                                    /* move menu */
                                  })
                                }
                              >
                                Move to group...
                              </Dropdown.Item>
                              <div className="p-2">
                                <Form.Select
                                  size="sm"
                                  aria-label={`Move ${app.name} to another group`}
                                  value={app.group_id ?? UNGROUPED_ID}
                                  onChange={(e) => void handleMoveApplication(app, e.target.value)}
                                >
                                  {groups.map((g) => (
                                    <option key={g.id} value={g.id}>
                                      {g.name}
                                    </option>
                                  ))}
                                  <option value={UNGROUPED_ID}>Ungrouped</option>
                                </Form.Select>
                              </div>
                              <Dropdown.Divider />
                              <Dropdown.Item
                                onClick={(e) =>
                                  stop(e, () => {
                                    if (confirm(`Delete ${app.name}? This removes its data sources and run history.`)) {
                                      void handleDeleteApplication(app);
                                    }
                                  })
                                }
                                className="text-danger"
                              >
                                Delete
                              </Dropdown.Item>
                            </Dropdown.Menu>
                          </Dropdown>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </Table>
            </>
          )}
        </>
      )}

      {/* Group management modal */}
      <Modal show={showGroupsModal} onHide={() => setShowGroupsModal(false)} size="lg">
        <Modal.Header closeButton>
          <Modal.Title>Manage groups</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          <div className="mb-4">
            <h6>Groups</h6>
            {groups.length === 0 ? (
              <p className="text-muted">No groups yet</p>
            ) : (
              <div className="d-flex flex-column gap-2">
                {groups.map((group) => (
                  <div key={group.id} className="d-flex justify-content-between align-items-center p-2 border rounded">
                    <div>
                      <div className="fw-medium">{group.name}</div>
                      <div className="small text-muted">{group.description}</div>
                    </div>
                    <div className="d-flex gap-2">
                      {(group.my_role === undefined || group.my_role === "admin") && (
                        <>
                          {extensions.groupActions.map((action) => (
                            <span key={action.id}>{action.render({ group, onChanged: () => void loadGroups() })}</span>
                          ))}
                          <Button
                            size="sm"
                            variant="outline-secondary"
                            onClick={() => stop({} as any, () => openForm(group))}
                          >
                            Edit
                          </Button>
                          <Button
                            size="sm"
                            variant="outline-danger"
                            onClick={() => stop({} as any, () => setDeleteTarget(group))}
                          >
                            Delete
                          </Button>
                        </>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="border-top pt-3">
            <h6>New group</h6>
            <Form onSubmit={handleSubmit}>
              {formError && <Alert variant="danger">{formError}</Alert>}
              <Form.Group className="mb-2" controlId="group-name">
                <Form.Label>Name</Form.Label>
                <Form.Control value={name} onChange={(event) => setName(event.target.value)} required autoFocus />
              </Form.Group>
              <Form.Group className="mb-2" controlId="group-description">
                <Form.Label>Description</Form.Label>
                <Form.Control
                  as="textarea"
                  rows={2}
                  value={description}
                  onChange={(event) => setDescription(event.target.value)}
                />
              </Form.Group>
              <Button type="submit" disabled={submitting}>
                {editing ? "Save" : "Create"}
              </Button>
            </Form>
          </div>
        </Modal.Body>
      </Modal>

      <Modal show={deleteTarget !== null} onHide={() => setDeleteTarget(null)}>
        <Modal.Header closeButton>
          <Modal.Title>Delete group</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          Delete the group <strong>{deleteTarget?.name}</strong>? Its threat models are not deleted -- they move to
          Ungrouped.
        </Modal.Body>
        <Modal.Footer>
          <Button variant="secondary" onClick={() => setDeleteTarget(null)}>
            Cancel
          </Button>
          <Button variant="danger" onClick={() => void handleDeleteConfirmed()}>
            Delete
          </Button>
        </Modal.Footer>
      </Modal>

      <IntakeWizard
        show={describeOpen}
        onHide={() => setDescribeOpen(false)}
        groupId={null}
        groups={groups.map((g) => ({ id: g.id, name: g.name }))}
        onCreated={(applicationId, runId) => navigate(`/applications/${applicationId}/runs/${runId}`)}
      />
      <CreateApplicationModal
        show={createOpen}
        onHide={() => setCreateOpen(false)}
        groupId={null}
        groups={groups.map((g) => ({ id: g.id, name: g.name }))}
        preset={createPreset}
        onCreated={(applicationId, runId) => navigate(`/applications/${applicationId}/runs/${runId}`)}
      />
    </div>
  );
}
