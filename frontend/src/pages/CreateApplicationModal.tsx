import { useEffect, useState, type FormEvent } from "react";
import { Alert, Button, Form, Modal } from "react-bootstrap";
import { apiFetch, ApiError } from "../api/client";
import {
  DataSourceDraftFields,
  draftToConnectionDetails,
  hasContent,
  newDraft,
  type ActiveDataSourceType,
  type DataSourceDraft,
} from "./DataSourceForm";

// What to open the dialog ready for: one of the input types, or "blank" for a canvas the
// user draws. Undefined is the plain form.
export type CreatePreset = ActiveDataSourceType | "blank";

// Select value for "no group"; the API takes null.
const NO_GROUP = "";

interface Props {
  show: boolean;
  onHide: () => void;
  // The group to create in (null = ungrouped). When `groups` is given the user can change it.
  groupId: string | null;
  groups?: { id: string; name: string }[];
  preset?: CreatePreset;
  onCreated: (applicationId: string, runId: string) => void;
}

// Creates an application, attaches the inputs the user filled in, and runs the model. Shared by
// the group page and the all-groups landing page.
export function CreateApplicationModal({ show, onHide, groupId, groups, preset, onCreated }: Props) {
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  // One row to start. Rows left empty are skipped on submit; with none filled in the application
  // is a blank model the user draws by hand.
  const [drafts, setDrafts] = useState<DataSourceDraft[]>([newDraft()]);
  const [group, setGroup] = useState<string>(groupId ?? NO_GROUP);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!show) return;
    setName("");
    setDescription("");
    setError(null);
    setGroup(groupId ?? NO_GROUP);
    const first = newDraft();
    setDrafts([preset && preset !== "blank" ? { ...first, type: preset } : first]);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [show, preset]);

  function updateDraft(key: string, update: Partial<DataSourceDraft>) {
    setDrafts((prev) => prev.map((d) => (d.key === key ? { ...d, ...update } : d)));
  }

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      const application = await apiFetch<{ id: string }>("/api/applications", {
        method: "POST",
        body: JSON.stringify({ name, description, group_id: group === NO_GROUP ? null : group }),
      });
      // A source with nothing filled in is skipped rather than saved empty.
      for (const draft of drafts.filter(hasContent)) {
        await apiFetch(`/api/applications/${application.id}/data-sources`, {
          method: "POST",
          body: JSON.stringify({ type: draft.type, connection_details: draftToConnectionDetails(draft) }),
        });
      }
      const run = await apiFetch<{ id: string }>(`/api/applications/${application.id}/runs`, { method: "POST" });
      onHide();
      onCreated(application.id, run.id);
    } catch (err) {
      setError(
        err instanceof ApiError && err.status !== 422
          ? err.message
          : "Failed to create the threat model. Check your inputs and try again.",
      );
    } finally {
      setSubmitting(false);
    }
  }

  const blank = preset === "blank";
  return (
    <Modal show={show} onHide={onHide} size="lg">
      <Form onSubmit={handleSubmit}>
        <Modal.Header closeButton>
          <Modal.Title>{blank ? "Draw a new threat model" : "New threat model"}</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          {error && <Alert variant="danger">{error}</Alert>}
          <Form.Group className="mb-3" controlId="app-name">
            <Form.Label>Name</Form.Label>
            <Form.Control value={name} onChange={(event) => setName(event.target.value)} required autoFocus />
          </Form.Group>
          <Form.Group className="mb-3" controlId="app-description">
            <Form.Label>Description</Form.Label>
            <Form.Control
              as="textarea"
              rows={2}
              value={description}
              onChange={(event) => setDescription(event.target.value)}
            />
          </Form.Group>
          {groups && (
            <Form.Group className="mb-4" controlId="app-group">
              <Form.Label>Group</Form.Label>
              <Form.Select value={group} onChange={(event) => setGroup(event.target.value)}>
                <option value={NO_GROUP}>Ungrouped</option>
                {groups.map((g) => (
                  <option key={g.id} value={g.id}>
                    {g.name}
                  </option>
                ))}
              </Form.Select>
            </Form.Group>
          )}

          <h2 className="h6">{blank ? "Inputs (optional)" : "Inputs"}</h2>
          <p className="text-muted small">
            {blank
              ? "You will draw the components on a canvas next. You can also attach inputs now."
              : "The threat model is computed from these. Leave them empty to start a blank canvas and draw it yourself."}{" "}
            Documentation and diagram formats other than Threat Dragon JSON are stored for reference only and are
            not analysed yet.
          </p>
          {drafts.map((draft) => (
            <DataSourceDraftFields
              key={draft.key}
              draft={draft}
              onChange={(update) => updateDraft(draft.key, update)}
              onRemove={drafts.length > 1 ? () => setDrafts((prev) => prev.filter((d) => d.key !== draft.key)) : undefined}
            />
          ))}
          <Button variant="outline-secondary" size="sm" type="button" onClick={() => setDrafts((prev) => [...prev, newDraft()])}>
            + Add another input
          </Button>
        </Modal.Body>
        <Modal.Footer>
          <Button variant="secondary" onClick={onHide} type="button">
            Cancel
          </Button>
          <Button type="submit" disabled={submitting}>
            {submitting ? "Creating..." : drafts.some(hasContent) ? "Create and run threat model" : "Create blank model"}
          </Button>
        </Modal.Footer>
      </Form>
    </Modal>
  );
}
