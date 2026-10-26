import { useEffect, useState } from "react";
import { Alert, Badge, Button, Form, Table } from "react-bootstrap";
import { apiFetch, ApiError } from "../api/client";
import { useToast } from "../components/Toasts";
import {
  DataSourceDraftFields,
  draftToConnectionDetails,
  hasContent,
  newDraft,
  type DataSourceDraft,
} from "./DataSourceForm";
import { SOURCE_STATUS_LABELS, SOURCE_TYPE_LABELS, type SourceResult } from "./sourceStatus";

interface DataSourceOut {
  id: string;
  type: string;
  connection_details: Record<string, unknown>;
  created_at: string;
  // The server never sends the token itself, only whether one is saved and its last four characters.
  has_token?: boolean;
  token_hint?: string | null;
}

// Never the whole connection_details blob -- just enough for a user to recognize which source is which.
function summarize(source: DataSourceOut): string {
  if (source.type === "github_repository") {
    const repoUrl = source.connection_details.repo_url;
    return typeof repoUrl === "string" && repoUrl ? repoUrl : "—";
  }
  const filename = source.connection_details.filename;
  return typeof filename === "string" && filename ? filename : "—";
}

function renderAnalysis(result: SourceResult | undefined) {
  if (!result) return <span className="text-muted small">Not run yet</span>;
  if (result.status === "analysed") {
    const parts = [`${result.component_count} component${result.component_count === 1 ? "" : "s"}`];
    if (result.vulnerability_count > 0) parts.push(`${result.vulnerability_count} vulnerabilities`);
    return (
      <>
        <Badge bg="success">{SOURCE_STATUS_LABELS.analysed}</Badge>{" "}
        <span className="small text-muted">{parts.join(", ")}</span>
        {(result.warnings ?? []).map((warning) => (
          <div key={warning} className="small text-warning-emphasis" data-testid="source-warning">
            <Badge bg="warning" text="dark">
              Incomplete
            </Badge>{" "}
            {warning}
          </div>
        ))}
      </>
    );
  }
  return (
    <>
      <Badge bg="warning" text="dark">
        {SOURCE_STATUS_LABELS[result.status]}
      </Badge>
      <div className="small text-muted">{result.message}</div>
    </>
  );
}

interface DataSourcesPanelProps {
  applicationId: string;
  // Called after a source is added or removed, so the caller (the
  // staleness banner on ApplicationDetail.tsx) can refresh too.
  onChanged?: () => void;
  // The current run's per-source outcome; sources added since that run have
  // no entry and show as "Not run yet".
  sourceResults?: SourceResult[];
}

// Application-scoped, not run-scoped: works even before any run exists or
// after the current run failed. Manages the
// POST/DELETE .../data-sources endpoints.
export function DataSourcesPanel({ applicationId, onChanged, sourceResults }: DataSourcesPanelProps) {
  const toast = useToast();
  const [sources, setSources] = useState<DataSourceOut[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [draft, setDraft] = useState<DataSourceDraft>(newDraft());
  const [adding, setAdding] = useState(false);
  const [removingId, setRemovingId] = useState<string | null>(null);
  const [replacingId, setReplacingId] = useState<string | null>(null);
  const [newToken, setNewToken] = useState("");

  function load() {
    return apiFetch<DataSourceOut[]>(`/api/applications/${applicationId}/data-sources`)
      .then(setSources)
      .catch(() => setError("Failed to load data sources"));
  }

  useEffect(() => {
    void load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [applicationId]);

  async function handleAdd() {
    if (!hasContent(draft)) return;
    setAdding(true);
    try {
      await apiFetch(`/api/applications/${applicationId}/data-sources`, {
        method: "POST",
        body: JSON.stringify({ type: draft.type, connection_details: draftToConnectionDetails(draft) }),
      });
      setDraft(newDraft());
      await load();
      onChanged?.();
      toast.success("Data source added");
    } catch (err) {
      toast.error(err instanceof ApiError ? err.message : "Failed to add that data source");
    } finally {
      setAdding(false);
    }
  }

  async function handleRemove(id: string) {
    setRemovingId(id);
    try {
      await apiFetch(`/api/applications/${applicationId}/data-sources/${id}`, { method: "DELETE" });
      await load();
      onChanged?.();
      toast.success("Data source removed");
    } catch (err) {
      toast.error(err instanceof ApiError ? err.message : "Failed to remove that data source");
    } finally {
      setRemovingId(null);
    }
  }

  async function handleSaveToken(id: string) {
    if (!newToken.trim()) return;
    try {
      await apiFetch(`/api/applications/${applicationId}/data-sources/${id}/token`, {
        method: "PUT",
        body: JSON.stringify({ token: newToken }),
      });
      setReplacingId(null);
      setNewToken("");
      await load();
      toast.success("Token saved");
    } catch (err) {
      toast.error(err instanceof ApiError ? err.message : "Failed to save that token");
    }
  }

  async function handleRemoveToken(id: string) {
    try {
      await apiFetch(`/api/applications/${applicationId}/data-sources/${id}/token`, { method: "DELETE" });
      await load();
      toast.success("Token removed");
    } catch (err) {
      toast.error(err instanceof ApiError ? err.message : "Failed to remove that token");
    }
  }

  function renderToken(source: DataSourceOut) {
    if (source.type !== "github_repository") return null;
    if (replacingId === source.id) {
      return (
        <div className="d-flex gap-1 mt-1">
          <Form.Control
            size="sm"
            type="password"
            aria-label="New GitHub token"
            autoComplete="off"
            value={newToken}
            onChange={(event) => setNewToken(event.target.value)}
          />
          <Button size="sm" disabled={!newToken.trim()} onClick={() => void handleSaveToken(source.id)}>
            Save token
          </Button>
          <Button
            size="sm"
            variant="outline-secondary"
            onClick={() => {
              setReplacingId(null);
              setNewToken("");
            }}
          >
            Cancel
          </Button>
        </div>
      );
    }
    return (
      <div className="small text-muted">
        {source.has_token ? `Token saved${source.token_hint ? ` (ends in ${source.token_hint})` : ""}` : "No token"}{" "}
        <Button variant="link" size="sm" className="p-0 align-baseline" onClick={() => setReplacingId(source.id)}>
          {source.has_token ? "Replace" : "Add token"}
        </Button>
        {source.has_token && (
          <>
            {" "}
            <Button
              variant="link"
              size="sm"
              className="p-0 align-baseline text-danger"
              onClick={() => void handleRemoveToken(source.id)}
            >
              Remove token
            </Button>
          </>
        )}
      </div>
    );
  }

  return (
    <div className="p-3">
      {error && (
        <Alert variant="danger" className="mb-2">
          {error}
        </Alert>
      )}
      {!sources ? (
        <p className="text-muted mb-3">Loading...</p>
      ) : sources.length === 0 ? (
        <p className="text-muted">
          No data sources yet -- add one below, or leave this a blank model you draw by hand.
        </p>
      ) : (
        <Table size="sm" striped responsive className="mb-3">
          <thead>
            <tr>
              <th>Type</th>
              <th>Source</th>
              <th>Analysis</th>
              <th>Added</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {sources.map((source) => (
              <tr key={source.id}>
                <td>
                  <Badge bg="secondary">{SOURCE_TYPE_LABELS[source.type] ?? source.type}</Badge>
                </td>
                <td>
                  {summarize(source)}
                  {renderToken(source)}
                </td>
                <td>{renderAnalysis(sourceResults?.find((result) => result.data_source_id === source.id))}</td>
                <td>{new Date(source.created_at).toLocaleString()}</td>
                <td>
                  <Button
                    variant="outline-danger"
                    size="sm"
                    disabled={removingId === source.id}
                    onClick={() => void handleRemove(source.id)}
                  >
                    Remove
                  </Button>
                </td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}

      <h2 className="h6">Add a data source</h2>
      <DataSourceDraftFields draft={draft} onChange={(update) => setDraft((prev) => ({ ...prev, ...update }))} />
      <Button size="sm" onClick={() => void handleAdd()} disabled={!hasContent(draft) || adding}>
        {adding ? "Adding..." : "Add data source"}
      </Button>
      <p className="text-muted small mt-2 mb-0">Re-run the threat model to pick up any changes you make here.</p>
    </div>
  );
}
