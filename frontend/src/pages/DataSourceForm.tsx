import { useState } from "react";
import { Alert, Button, Form } from "react-bootstrap";

export type ActiveDataSourceType = "manifest_upload" | "github_repository" | "architecture_diagram" | "documentation";

export interface DataSourceDraft {
  key: string;
  type: ActiveDataSourceType;
  fileName: string;
  content: string;
  repoUrl: string;
  githubToken: string;
  repoRef: string;
}

export function hasContent(draft: DataSourceDraft): boolean {
  return draft.type === "github_repository" ? draft.repoUrl.trim() !== "" : draft.content !== "";
}

export function newDraft(): DataSourceDraft {
  return {
    key: `draft-${Date.now()}`,
    type: "manifest_upload",
    fileName: "",
    content: "",
    repoUrl: "",
    githubToken: "",
    repoRef: "",
  };
}

// Shared with the create-application flow (Applications.tsx) and the
// post-creation "add a data source" panel (DataSourcesPanel.tsx) -- one
// place decides how a draft becomes the POST body's connection_details.
export function draftToConnectionDetails(draft: DataSourceDraft): Record<string, unknown> {
  return draft.type === "github_repository"
    ? {
        repo_url: draft.repoUrl,
        github_token: draft.githubToken || undefined,
        ref: draft.repoRef || undefined,
      }
    : { content: draft.content, filename: draft.fileName };
}

interface DataSourceDraftFieldsProps {
  draft: DataSourceDraft;
  onChange: (update: Partial<DataSourceDraft>) => void;
  // Omit to hide the Remove button (e.g. a single-draft "add one source" form).
  onRemove?: () => void;
}

const YAML_FILE = /\.ya?ml$/i;

// Several Kubernetes YAML files are one application, so they are joined into a single manifest with
// document separators. A Terraform plan is one JSON document and cannot be joined, so it stays
// single-file. Returns an error message instead of content when the selection cannot be combined.
export async function combineManifestFiles(files: File[]): Promise<{ fileName: string; content: string } | { error: string }> {
  if (files.length === 1) return { fileName: files[0].name, content: await files[0].text() };
  const notYaml = files.filter((file) => !YAML_FILE.test(file.name));
  if (notYaml.length > 0) {
    return { error: `Select several Kubernetes YAML files, or a single Terraform plan (JSON). Not YAML: ${notYaml.map((f) => f.name).join(", ")}.` };
  }
  const texts = await Promise.all(files.map((file) => file.text()));
  const names = files.map((file) => file.name);
  return {
    fileName: `${files.length} files: ${names.slice(0, 3).join(", ")}${names.length > 3 ? ", ..." : ""}`,
    content: texts.map((text) => (text.endsWith("\n") ? text : `${text}\n`)).join("---\n"),
  };
}

export function DataSourceDraftFields({ draft, onChange, onRemove }: DataSourceDraftFieldsProps) {
  const [fileError, setFileError] = useState<string | null>(null);

  async function handleFileChange(list: FileList | null | undefined) {
    const files = list ? Array.from(list) : [];
    if (files.length === 0) return;
    setFileError(null);
    if (draft.type === "manifest_upload") {
      const combined = await combineManifestFiles(files);
      if ("error" in combined) {
        setFileError(combined.error);
        onChange({ fileName: "", content: "" });
        return;
      }
      onChange(combined);
      return;
    }
    onChange({ fileName: files[0].name, content: await files[0].text() });
  }

  return (
    <div className="border rounded p-3 mb-3">
      <div className="d-flex justify-content-between align-items-start mb-2">
        <Form.Select
          style={{ maxWidth: 280 }}
          value={draft.type}
          onChange={(event) => onChange({ type: event.target.value as ActiveDataSourceType })}
        >
          <option value="manifest_upload">Upload a manifest (Terraform plan JSON or Kubernetes YAML)</option>
          <option value="github_repository">GitHub repository</option>
          <option value="architecture_diagram">Architecture diagram</option>
          <option value="documentation">Additional documentation</option>
        </Form.Select>
        {onRemove && (
          <Button variant="outline-secondary" size="sm" onClick={onRemove}>
            Remove
          </Button>
        )}
      </div>

      {draft.type === "github_repository" ? (
        <div>
          <Form.Group className="mb-2" controlId={`${draft.key}-repo-url`}>
            <Form.Label className="small">Repository URL</Form.Label>
            <Form.Control
              placeholder="https://github.com/owner/repo"
              value={draft.repoUrl}
              onChange={(event) => onChange({ repoUrl: event.target.value })}
            />
          </Form.Group>
          <Form.Group className="mb-2" controlId={`${draft.key}-repo-token`}>
            <Form.Label className="small">GitHub token (optional, for private repos)</Form.Label>
            <Form.Control
              type="password"
              value={draft.githubToken}
              onChange={(event) => onChange({ githubToken: event.target.value })}
            />
          </Form.Group>
          <Form.Group controlId={`${draft.key}-repo-ref`}>
            <Form.Label className="small">
              Branch/tag/commit (optional -- defaults to the repository&apos;s default branch)
            </Form.Label>
            <Form.Control
              placeholder="main"
              value={draft.repoRef}
              onChange={(event) => onChange({ repoRef: event.target.value })}
            />
          </Form.Group>
        </div>
      ) : (
        <Form.Group controlId={`${draft.key}-file`}>
          <Form.Label className="small">
            {draft.type === "architecture_diagram"
              ? "Architecture diagram file (Threat Dragon JSON, draw.io, Mermaid or Threagile YAML)"
              : draft.type === "documentation"
                ? "Documentation file"
                : "Manifest files (one Terraform plan, or one or more Kubernetes YAML files)"}
          </Form.Label>
          <Form.Control
            type="file"
            multiple={draft.type === "manifest_upload"}
            accept={
              draft.type === "manifest_upload"
                ? ".json,.yaml,.yml"
                : draft.type === "architecture_diagram"
                  ? ".json,.drawio,.xml,.mmd,.mermaid,.md,.yaml,.yml,.txt"
                  : undefined
            }
            onChange={(event) => void handleFileChange((event.target as HTMLInputElement).files)}
          />
          {fileError && (
            <Alert variant="warning" className="small mt-2 mb-0 py-2">
              {fileError}
            </Alert>
          )}
          {draft.fileName && <div className="text-muted small mt-1">Loaded: {draft.fileName}</div>}
        </Form.Group>
      )}
    </div>
  );
}
