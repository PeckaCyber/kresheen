import { useEffect, useState } from "react";
import { Alert, Button, Form } from "react-bootstrap";
import { apiFetch, ApiError } from "../api/client";
import { isMethodologyAvailable, selectableMethodologies, type Methodology } from "../methodology";

// Model metadata (Threat Dragon parity): free text, not tied to a platform user account -- see
// models/application.py's docstring for why this is separate from
// owner_user_id (attribution: who created this record in the tool).
interface ApplicationMetadata {
  name: string;
  description: string;
  owner: string;
  reviewer: string;
  contributors: string[];
  // Which threat-generation methodologies are active. Multi-select, STRIDE default-on.
  methodologies: Methodology[];
}

function contributorsToText(contributors: string[]): string {
  return contributors.join(", ");
}

function textToContributors(text: string): string[] {
  return text
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

function unavailableLabel(names: string[]): string {
  return names.length === 1 ? `${names[0]} is` : `${names.join(", ")} are`;
}

export function ModelInfoPanel({ applicationId }: { applicationId: string }) {
  const [metadata, setMetadata] = useState<ApplicationMetadata | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [editing, setEditing] = useState(false);
  const [saving, setSaving] = useState(false);
  const [nameDraft, setNameDraft] = useState("");
  const [descriptionDraft, setDescriptionDraft] = useState("");
  const [ownerDraft, setOwnerDraft] = useState("");
  const [reviewerDraft, setReviewerDraft] = useState("");
  const [contributorsDraft, setContributorsDraft] = useState("");
  const [methodologiesDraft, setMethodologiesDraft] = useState<Methodology[]>([]);

  function load() {
    return apiFetch<ApplicationMetadata>(`/api/applications/${applicationId}`)
      .then(setMetadata)
      .catch(() => setError("Failed to load model info."));
  }

  useEffect(() => {
    void load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [applicationId]);

  function startEditing() {
    if (!metadata) return;
    setNameDraft(metadata.name);
    setDescriptionDraft(metadata.description);
    setOwnerDraft(metadata.owner);
    setReviewerDraft(metadata.reviewer);
    setContributorsDraft(contributorsToText(metadata.contributors));
    setMethodologiesDraft(metadata.methodologies);
    setEditing(true);
  }

  function toggleMethodology(methodology: Methodology) {
    setMethodologiesDraft((current) =>
      current.includes(methodology) ? current.filter((m) => m !== methodology) : [...current, methodology],
    );
  }

  async function handleSave() {
    if (!nameDraft.trim()) return;
    setSaving(true);
    setError(null);
    try {
      const updated = await apiFetch<ApplicationMetadata>(`/api/applications/${applicationId}/metadata`, {
        method: "PATCH",
        body: JSON.stringify({
          name: nameDraft.trim(),
          description: descriptionDraft,
          owner: ownerDraft,
          reviewer: reviewerDraft,
          contributors: textToContributors(contributorsDraft),
          methodologies: methodologiesDraft,
        }),
      });
      setMetadata(updated);
      setEditing(false);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Failed to save model info.");
    } finally {
      setSaving(false);
    }
  }

  if (!metadata) return <p className="text-muted p-3 mb-0">{error ?? "Loading..."}</p>;

  // Selected here but not offered by this installation (for example a plugin methodology after its licence lapsed).
  const unavailableSelected = metadata.methodologies.filter((m) => !isMethodologyAvailable(m));

  if (!editing) {
    return (
      <div className="p-3">
        {error && (
          <Alert variant="danger" className="mb-3" onClose={() => setError(null)} dismissible>
            {error}
          </Alert>
        )}
        <dl className="row mb-3">
          <dt className="col-sm-3">Name</dt>
          <dd className="col-sm-9">{metadata.name}</dd>
          <dt className="col-sm-3">Description</dt>
          <dd className="col-sm-9">{metadata.description || <span className="text-muted">Not set</span>}</dd>
          <dt className="col-sm-3">Owner</dt>
          <dd className="col-sm-9">{metadata.owner || <span className="text-muted">Not set</span>}</dd>
          <dt className="col-sm-3">Reviewer</dt>
          <dd className="col-sm-9">{metadata.reviewer || <span className="text-muted">Not set</span>}</dd>
          <dt className="col-sm-3">Contributors</dt>
          <dd className="col-sm-9">
            {metadata.contributors.length > 0 ? metadata.contributors.join(", ") : <span className="text-muted">Not set</span>}
          </dd>
          <dt className="col-sm-3">Methodologies</dt>
          <dd className="col-sm-9">
            {metadata.methodologies.length > 0 ? metadata.methodologies.join(", ") : <span className="text-muted">Not set</span>}
            {unavailableSelected.length > 0 && (
              <div className="small text-warning-emphasis mt-1" role="note">
                {unavailableLabel(unavailableSelected)} not available in this installation, so no threats are generated for{" "}
                {unavailableSelected.length === 1 ? "it" : "them"}.
              </div>
            )}
          </dd>
        </dl>
        <Button size="sm" variant="outline-secondary" onClick={startEditing}>
          Edit
        </Button>
      </div>
    );
  }

  return (
    <div className="p-3">
      {error && (
        <Alert variant="danger" className="mb-3" onClose={() => setError(null)} dismissible>
          {error}
        </Alert>
      )}
      <Form.Group className="mb-2" controlId="model-info-name">
        <Form.Label className="small">Name</Form.Label>
        <Form.Control value={nameDraft} maxLength={200} onChange={(event) => setNameDraft(event.target.value)} required />
      </Form.Group>
      <Form.Group className="mb-2" controlId="model-info-description">
        <Form.Label className="small">Description</Form.Label>
        <Form.Control
          as="textarea"
          rows={2}
          value={descriptionDraft}
          onChange={(event) => setDescriptionDraft(event.target.value)}
        />
      </Form.Group>
      <Form.Group className="mb-2" controlId="model-info-owner">
        <Form.Label className="small">Owner</Form.Label>
        <Form.Control value={ownerDraft} onChange={(event) => setOwnerDraft(event.target.value)} />
      </Form.Group>
      <Form.Group className="mb-2" controlId="model-info-reviewer">
        <Form.Label className="small">Reviewer</Form.Label>
        <Form.Control value={reviewerDraft} onChange={(event) => setReviewerDraft(event.target.value)} />
      </Form.Group>
      <Form.Group className="mb-3" controlId="model-info-contributors">
        <Form.Label className="small">Contributors (comma-separated)</Form.Label>
        <Form.Control value={contributorsDraft} onChange={(event) => setContributorsDraft(event.target.value)} />
      </Form.Group>
      <Form.Group className="mb-3">
        <Form.Label className="small d-block">Methodologies</Form.Label>
        {[...selectableMethodologies(), ...methodologiesDraft.filter((m) => !isMethodologyAvailable(m))].map((methodology) => {
          const unavailable = !isMethodologyAvailable(methodology);
          return (
            <Form.Check
              key={methodology}
              inline
              type="checkbox"
              id={`model-info-methodology-${methodology}`}
              label={unavailable ? `${methodology} (not available)` : methodology}
              checked={methodologiesDraft.includes(methodology)}
              onChange={() => toggleMethodology(methodology)}
            />
          );
        })}
        {methodologiesDraft.some((m) => !isMethodologyAvailable(m)) && (
          <Form.Text className="d-block">
            A methodology that is not available here generates no threats. Untick it to remove it from this model.
          </Form.Text>
        )}
      </Form.Group>
      <div className="d-flex gap-2">
        <Button size="sm" onClick={() => void handleSave()} disabled={!nameDraft.trim() || saving}>
          {saving ? "Saving..." : "Save"}
        </Button>
        <Button size="sm" variant="outline-secondary" onClick={() => setEditing(false)} disabled={saving}>
          Cancel
        </Button>
      </div>
    </div>
  );
}
