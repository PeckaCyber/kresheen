import { useEffect, useState, type FormEvent } from "react";
import { Alert, Badge, Button, Form, Modal } from "react-bootstrap";
import { apiFetch, ApiError } from "../api/client";
import { fetchCapabilities } from "../api/capabilities";

interface Option {
  id: string;
  label: string;
  help: string;
}

interface Template {
  id: string;
  title: string;
  description: string;
  answers: Partial<Answers>;
}

export interface IntakeOptions {
  system_types: Option[];
  users: Option[];
  authentication: Option[];
  data: Option[];
  third_parties: Option[];
  templates: Template[];
}

interface Answers {
  system_type: string;
  users: string[];
  authentication: string;
  data: string[];
  third_parties: string[];
  has_admin: boolean;
}

type DraftKey = "name" | "description" | keyof Answers;

interface DraftOut {
  answers: Partial<Answers> & { name?: string; description?: string };
  filled: string[];
  warnings: { pattern: string; excerpt: string }[];
}

// Matches the server's cap for the describe-to-draft box (engine/llm/limits.py).
const DRAFT_MAX_CHARS = 20_000;

function SuggestedTag({ show }: { show: boolean }) {
  return show ? (
    <Badge bg="info" text="dark" className="ms-2 fw-normal" data-testid="ai-tag">
      Suggested by AI
    </Badge>
  ) : null;
}

const EMPTY: Answers = {
  system_type: "",
  users: [],
  authentication: "",
  data: [],
  third_parties: [],
  has_admin: false,
};

function toggle(list: string[], id: string): string[] {
  return list.includes(id) ? list.filter((x) => x !== id) : [...list, id];
}

// Guided intake: a few plain questions become a starter model with the
// obvious components drawn and the answers already stated as facts. The result is an ordinary
// editable model; nothing here is remembered afterwards.
export function IntakeWizard({
  show,
  onHide,
  groupId,
  groups,
  onCreated,
}: {
  show: boolean;
  onHide: () => void;
  groupId: string | null;
  groups?: { id: string; name: string }[];
  onCreated: (applicationId: string, runId: string) => void;
}) {
  const [options, setOptions] = useState<IntakeOptions | null>(null);
  const [loadFailed, setLoadFailed] = useState(false);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [answers, setAnswers] = useState<Answers>(EMPTY);
  // "None of these" is an answer in its own right: an empty list alone would be indistinguishable
  // from a question the user skipped.
  const [noSensitiveData, setNoSensitiveData] = useState(false);
  const [template, setTemplate] = useState<string | null>(null);
  const [group, setGroup] = useState<string>(groupId ?? "");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Experimental AI assist. Shown only when the instance switch is on and this user has a key and a model.
  const [aiReady, setAiReady] = useState(false);
  const [describe, setDescribe] = useState("");
  const [drafting, setDrafting] = useState(false);
  const [draftError, setDraftError] = useState<string | null>(null);
  const [warnings, setWarnings] = useState<DraftOut["warnings"]>([]);
  const [aiFilled, setAiFilled] = useState<ReadonlySet<string>>(new Set());

  useEffect(() => {
    setAiReady(false);
    if (!show) return;
    let cancelled = false;
    // Two checks, both must pass: the instance switch, then this user's own key and model.
    fetchCapabilities()
      .then((caps) =>
        caps?.ai?.enabled === true
          ? apiFetch<{ has_api_key: boolean; default_model: string | null }>("/api/agent-config")
          : null,
      )
      .then((cfg) => {
        if (!cancelled) setAiReady(!!cfg && cfg.has_api_key === true && !!cfg.default_model);
      })
      .catch(() => {
        if (!cancelled) setAiReady(false);
      });
    return () => {
      cancelled = true;
    };
  }, [show]);

  function clearAi(...keys: DraftKey[]) {
    setAiFilled((prev) => {
      if (!keys.some((k) => prev.has(k))) return prev;
      const next = new Set(prev);
      keys.forEach((k) => next.delete(k));
      return next;
    });
  }

  useEffect(() => {
    if (!show) return;
    setName("");
    setDescription("");
    setAnswers(EMPTY);
    setNoSensitiveData(false);
    setTemplate(null);
    setError(null);
    setDescribe("");
    setDraftError(null);
    setWarnings([]);
    setAiFilled(new Set());
    setGroup(groupId ?? "");
    if (options) return;
    apiFetch<IntakeOptions>("/api/intake/options")
      .then((out) => {
        setOptions(out);
        setLoadFailed(false);
      })
      .catch(() => setLoadFailed(true));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [show]);

  function applyTemplate(t: Template) {
    setTemplate(t.id);
    const next = { ...EMPTY, ...t.answers } as Answers;
    setAnswers(next);
    setNoSensitiveData(next.data.length === 0);
    setName((current) => current || t.title);
    setAiFilled(new Set());
  }

  async function readFile(file: File | undefined) {
    if (!file) return;
    setDraftError(null);
    if (!/\.(txt|md)$/i.test(file.name)) {
      setDraftError("Only .txt and .md files are supported.");
      return;
    }
    if (file.size > DRAFT_MAX_CHARS * 4) {
      setDraftError(`That file is too large. The limit is ${DRAFT_MAX_CHARS} characters.`);
      return;
    }
    let text: string;
    try {
      text = await new TextDecoder("utf-8", { fatal: true }).decode(await file.arrayBuffer());
    } catch {
      setDraftError("That file is not UTF-8 text.");
      return;
    }
    if (text.length > DRAFT_MAX_CHARS) {
      setDraftError(`That file is too long. The limit is ${DRAFT_MAX_CHARS} characters.`);
      return;
    }
    setDescribe(text);
  }

  async function handleDraft() {
    setDrafting(true);
    setDraftError(null);
    setWarnings([]);
    try {
      const out = await apiFetch<DraftOut>("/api/intake/draft", {
        method: "POST",
        body: JSON.stringify({ text: describe }),
      });
      const a = out.answers;
      // Only the answers the model gave are touched; everything else stays exactly as it was.
      if (out.filled.includes("name") && a.name !== undefined) setName(a.name);
      if (out.filled.includes("description") && a.description !== undefined) setDescription(a.description);
      setAnswers((prev) => {
        const next = { ...prev };
        if (out.filled.includes("system_type") && a.system_type !== undefined) next.system_type = a.system_type;
        if (out.filled.includes("users") && a.users !== undefined) next.users = a.users;
        if (out.filled.includes("authentication") && a.authentication !== undefined)
          next.authentication = a.authentication;
        if (out.filled.includes("data") && a.data !== undefined) next.data = a.data;
        if (out.filled.includes("third_parties") && a.third_parties !== undefined) next.third_parties = a.third_parties;
        if (out.filled.includes("has_admin") && a.has_admin !== undefined) next.has_admin = a.has_admin;
        return next;
      });
      // "No sensitive data" is a real answer: an empty list from the model means the description says so.
      if (out.filled.includes("data") && a.data !== undefined) setNoSensitiveData(a.data.length === 0);
      setAiFilled(new Set(out.filled));
      setWarnings(out.warnings);
    } catch (err) {
      setDraftError(err instanceof ApiError ? err.message : "Could not draft answers.");
    } finally {
      setDrafting(false);
    }
  }

  const missing: string[] = [];
  if (!name.trim()) missing.push("a name");
  if (!answers.system_type) missing.push("what kind of system it is");
  if (answers.users.length === 0) missing.push("who uses it");
  if (!answers.authentication) missing.push("how users log in");
  if (answers.data.length === 0 && !noSensitiveData) missing.push("what sensitive data it handles");

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    if (missing.length > 0) return;
    setSubmitting(true);
    setError(null);
    try {
      const out = await apiFetch<{ application_id: string; run_id: string }>("/api/intake", {
        method: "POST",
        body: JSON.stringify({
          name: name.trim(),
          description,
          ...answers,
          data: noSensitiveData ? [] : answers.data,
          group_id: group === "" ? null : group,
        }),
      });
      onHide();
      onCreated(out.application_id, out.run_id);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not create the threat model.");
    } finally {
      setSubmitting(false);
    }
  }

  function radios(question: keyof Pick<Answers, "system_type" | "authentication">, items: Option[]) {
    return items.map((option) => (
      <Form.Check
        key={option.id}
        type="radio"
        id={`${question}-${option.id}`}
        name={question}
        label={option.label}
        checked={answers[question] === option.id}
        onChange={() => {
          clearAi(question);
          setAnswers((prev) => ({ ...prev, [question]: option.id }));
        }}
        aria-describedby={option.help ? `${question}-${option.id}-help` : undefined}
      />
    ));
  }

  function boxes(question: keyof Pick<Answers, "users" | "third_parties">, items: Option[]) {
    return items.map((option) => (
      <Form.Check
        key={option.id}
        type="checkbox"
        id={`${question}-${option.id}`}
        label={option.label}
        checked={answers[question].includes(option.id)}
        onChange={() => {
          clearAi(question);
          setAnswers((prev) => ({ ...prev, [question]: toggle(prev[question], option.id) }));
        }}
      />
    ));
  }

  return (
    <Modal show={show} onHide={onHide} size="lg" scrollable>
      {/* The form sits between .modal-content and its header/body/footer, so it has to carry the flex layout
          itself: without it the body cannot shrink and scroll and the footer (with Create) is pushed
          off-screen and clipped. */}
      <Form onSubmit={handleSubmit} className="d-flex flex-column flex-grow-1 overflow-hidden" style={{ minHeight: 0 }}>
        <Modal.Header closeButton>
          <Modal.Title>Describe your system</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          {loadFailed && <Alert variant="danger">Could not load the questions.</Alert>}
          {error && <Alert variant="danger">{error}</Alert>}
          <p className="text-muted small">
            Answer a few questions and a starter threat model is drawn for you, with your answers already stated as
            facts. It is an ordinary model: check it against the real system and edit it.
          </p>

          {aiReady && (
            <section className="border rounded p-3 mb-3" aria-labelledby="intake-ai-title" data-testid="intake-ai-box">
              <div className="d-flex align-items-center gap-2 mb-1">
                <h2 className="h6 mb-0" id="intake-ai-title">
                  Describe your system (AI, experimental)
                </h2>
                <Badge bg="warning" text="dark">
                  Experimental
                </Badge>
              </div>
              <p className="small text-muted mb-2">
                Paste a description or load a .txt or .md file. The AI suggests answers to the questions below. The text
                is sent to Anthropic with your own API key. Check every answer: nothing is created until you press
                Create.
              </p>
              <Form.Control
                as="textarea"
                rows={4}
                aria-label="System description"
                value={describe}
                maxLength={DRAFT_MAX_CHARS}
                onChange={(e) => setDescribe(e.target.value)}
                placeholder="For example: a patient portal where patients log in to see health records and pay bills by card."
              />
              <div className="d-flex flex-wrap align-items-center gap-2 mt-2">
                <Form.Control
                  type="file"
                  size="sm"
                  accept=".txt,.md,text/plain,text/markdown"
                  aria-label="Description file"
                  style={{ maxWidth: "20rem" }}
                  onChange={(e) => {
                    const input = e.target as HTMLInputElement;
                    void readFile(input.files?.[0]);
                    input.value = "";
                  }}
                />
                <Button
                  type="button"
                  size="sm"
                  disabled={drafting || !describe.trim()}
                  onClick={() => void handleDraft()}
                >
                  {drafting ? "Drafting..." : "Draft answers"}
                </Button>
              </div>
              {draftError && (
                <Alert variant="danger" className="mt-2 mb-0 py-2">
                  {draftError}
                </Alert>
              )}
              {warnings.length > 0 && (
                <Alert variant="warning" className="mt-2 mb-0 py-2" data-testid="ai-warning">
                  This text contains wording aimed at automated tools (for example: <q>{warnings[0].excerpt}</q>). It
                  was treated as data, not instructions. The event is in the audit log.
                </Alert>
              )}
              {aiFilled.size > 0 && (
                <div className="small text-muted mt-2">
                  Answers marked "Suggested by AI" are drafts. Change them if they are wrong.
                </div>
              )}
            </section>
          )}

          {options && (
            <>
              <div className="mb-3">
                <div className="small fw-semibold mb-1">Start from a template (optional)</div>
                <div className="d-flex flex-wrap gap-2">
                  {options.templates.map((t) => (
                    <Button
                      key={t.id}
                      size="sm"
                      type="button"
                      variant={template === t.id ? "primary" : "outline-secondary"}
                      title={t.description}
                      aria-pressed={template === t.id}
                      onClick={() => applyTemplate(t)}
                    >
                      {t.title}
                    </Button>
                  ))}
                </div>
                {template && (
                  <div className="small text-muted mt-1">
                    {options.templates.find((t) => t.id === template)?.description} Change any answer below.
                  </div>
                )}
              </div>

              <Form.Group className="mb-3" controlId="intake-name">
                <Form.Label>
                  Name
                  <SuggestedTag show={aiFilled.has("name")} />
                </Form.Label>
                <Form.Control
                  value={name}
                  onChange={(e) => {
                    clearAi("name");
                    setName(e.target.value);
                  }}
                  autoFocus
                />
              </Form.Group>

              <fieldset className="mb-3">
                <legend className="h6">
                  What kind of system is it?
                  <SuggestedTag show={aiFilled.has("system_type")} />
                </legend>
                {radios("system_type", options.system_types)}
                {answers.system_type && (
                  <div className="small text-muted">
                    {options.system_types.find((o) => o.id === answers.system_type)?.help}
                  </div>
                )}
              </fieldset>

              <fieldset className="mb-3">
                <legend className="h6">
                  Who uses it? (pick all that apply)
                  <SuggestedTag show={aiFilled.has("users")} />
                </legend>
                {boxes("users", options.users)}
              </fieldset>

              <fieldset className="mb-3">
                <legend className="h6">
                  How do users prove who they are?
                  <SuggestedTag show={aiFilled.has("authentication")} />
                </legend>
                {radios("authentication", options.authentication)}
              </fieldset>

              <fieldset className="mb-3">
                <legend className="h6">
                  What sensitive data does it handle? (pick all that apply)
                  <SuggestedTag show={aiFilled.has("data")} />
                </legend>
                {options.data.map((option) => (
                  <Form.Check
                    key={option.id}
                    type="checkbox"
                    id={`data-${option.id}`}
                    label={
                      <>
                        {option.label} <span className="text-muted small">{option.help}</span>
                      </>
                    }
                    checked={answers.data.includes(option.id)}
                    onChange={() => {
                      clearAi("data");
                      setNoSensitiveData(false);
                      setAnswers((prev) => ({ ...prev, data: toggle(prev.data, option.id) }));
                    }}
                  />
                ))}
                <Form.Check
                  type="checkbox"
                  id="data-none"
                  label="None of these"
                  checked={noSensitiveData}
                  onChange={() => {
                    clearAi("data");
                    setNoSensitiveData((v) => !v);
                    setAnswers((prev) => ({ ...prev, data: [] }));
                  }}
                />
              </fieldset>

              <fieldset className="mb-3">
                <legend className="h6">
                  Which outside services does it talk to? (optional)
                  <SuggestedTag show={aiFilled.has("third_parties")} />
                </legend>
                {boxes("third_parties", options.third_parties)}
              </fieldset>

              <Form.Check
                className="mb-3"
                type="checkbox"
                id="intake-admin"
                label={
                  <>
                    It has an admin interface for staff
                    <SuggestedTag show={aiFilled.has("has_admin")} />
                  </>
                }
                checked={answers.has_admin}
                onChange={() => {
                  clearAi("has_admin");
                  setAnswers((prev) => ({ ...prev, has_admin: !prev.has_admin }));
                }}
              />

              <Form.Group className="mb-3" controlId="intake-description">
                <Form.Label>
                  Notes (optional)
                  <SuggestedTag show={aiFilled.has("description")} />
                </Form.Label>
                <Form.Control
                  as="textarea"
                  rows={2}
                  value={description}
                  onChange={(e) => {
                    clearAi("description");
                    setDescription(e.target.value);
                  }}
                />
              </Form.Group>

              {groups && groups.length > 0 && (
                <Form.Group className="mb-2" controlId="intake-group">
                  <Form.Label>Group</Form.Label>
                  <Form.Select value={group} onChange={(e) => setGroup(e.target.value)}>
                    <option value="">Ungrouped</option>
                    {groups.map((g) => (
                      <option key={g.id} value={g.id}>
                        {g.name}
                      </option>
                    ))}
                  </Form.Select>
                </Form.Group>
              )}
            </>
          )}
        </Modal.Body>
        <Modal.Footer className="justify-content-between">
          <span className="small text-muted" role="status">
            {missing.length > 0 ? `Still to answer: ${missing.join(", ")}.` : "Ready to create."}
          </span>
          <div className="d-flex gap-2">
            <Button variant="secondary" type="button" onClick={onHide}>
              Cancel
            </Button>
            <Button type="submit" disabled={submitting || missing.length > 0 || !options}>
              {submitting ? "Creating..." : "Create threat model"}
            </Button>
          </div>
        </Modal.Footer>
      </Form>
    </Modal>
  );
}
