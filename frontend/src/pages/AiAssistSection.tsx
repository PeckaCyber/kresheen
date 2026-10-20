import { useCallback, useEffect, useState } from "react";
import { Alert, Badge, Button, Form } from "react-bootstrap";
import { ApiError, apiFetch } from "../api/client";
import { useToast } from "../components/Toasts";
import { CollapsibleCard } from "./CollapsibleCard";

// Experimental, opt-in AI assist. Two switches: the owner turns it on for the instance, then each user adds their own
// Anthropic key. Nothing here renders for anyone while the instance switch is off, except the owner's toggle.

const NOTICE_KEY = "kresheen-ai-notice-ack";

function readAck(): boolean {
  try {
    return localStorage.getItem(NOTICE_KEY) === "1";
  } catch {
    return false;
  }
}

function writeAck(): void {
  try {
    localStorage.setItem(NOTICE_KEY, "1");
  } catch {
    // localStorage may be unavailable; the notice just shows again next time
  }
}

interface AiSettings {
  enabled: boolean;
  forced_off: boolean;
}

interface AgentConfig {
  default_model: string | null;
  has_api_key: boolean;
  workspace_id: string | null;
}

interface ModelInfo {
  id: string;
  display_name: string;
}

function InstanceToggle({ onChanged }: { onChanged: () => void }) {
  const [settings, setSettings] = useState<AiSettings | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    apiFetch<AiSettings>("/api/settings/ai")
      .then(setSettings)
      .catch(() => setError("Could not load the AI assist setting."));
  }, []);

  async function toggle(enabled: boolean) {
    setError(null);
    try {
      setSettings(
        await apiFetch<AiSettings>("/api/settings/ai", { method: "PUT", body: JSON.stringify({ enabled }) }),
      );
      onChanged();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not change the AI assist setting.");
    }
  }

  return (
    <div className="mb-3">
      {error && <Alert variant="danger">{error}</Alert>}
      <Form.Check
        type="switch"
        id="ai-instance-toggle"
        label="Turn on AI assist for this instance"
        checked={settings?.enabled ?? false}
        disabled={settings === null || settings.forced_off}
        onChange={(event) => void toggle(event.target.checked)}
      />
      {settings?.forced_off && (
        <Form.Text className="text-muted d-block">
          Turned off by the server administrator (KRESHEEN_AI_DISABLED)
        </Form.Text>
      )}
      <Form.Text className="text-muted d-block">
        Rule-based analysis works fully without it. Each person who wants AI adds their own Anthropic API key.
      </Form.Text>
    </div>
  );
}

function errorMessage(err: unknown, fallback: string): string {
  if (!(err instanceof ApiError)) return fallback;
  if (err.status === 422) return err.message === "Invalid API key." ? "Anthropic did not accept this key. Check it and try again." : err.message;
  if (err.status === 400) return "The server cannot store API keys because KRESHEEN_SECRET_KEY is not set. Ask your administrator.";
  if (err.status === 429) return "Anthropic is rate limiting this key. Wait a bit and try again.";
  if (err.status === 502) return `Anthropic could not be reached or returned an error: ${err.message}`;
  if (err.status === 404) return "AI assist is turned off.";
  return fallback;
}

function KeySection() {
  const toast = useToast();
  const [acked, setAcked] = useState(readAck);
  const [config, setConfig] = useState<AgentConfig | null>(null);
  const [apiKey, setApiKey] = useState("");
  const [model, setModel] = useState("");
  const [workspaceId, setWorkspaceId] = useState("");
  const [models, setModels] = useState<ModelInfo[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const c = await apiFetch<AgentConfig>("/api/agent-config");
      setConfig(c);
      setModel(c.default_model ?? "");
      setWorkspaceId(c.workspace_id ?? "");
    } catch {
      setError("Could not load your AI settings.");
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  if (!acked) {
    return (
      <Alert variant="warning" data-testid="ai-notice">
        <p className="mb-2 fw-semibold">Before you use AI assist</p>
        <ul className="mb-3">
          <li>Text you send (descriptions, documents, threat details) goes to Anthropic using your own API key.</li>
          <li>AI output can be wrong; review it.</li>
          <li>This feature is experimental.</li>
        </ul>
        <Button
          size="sm"
          onClick={() => {
            writeAck();
            setAcked(true);
          }}
        >
          I understand
        </Button>
      </Alert>
    );
  }

  const typedKey = apiKey.trim();
  const workspace = workspaceId.trim();
  const hasKey = config?.has_api_key ?? false;

  async function testKey() {
    setBusy(true);
    setError(null);
    try {
      const list = await apiFetch<ModelInfo[]>("/api/agent-config/models", {
        method: "POST",
        body: JSON.stringify({ ...(typedKey ? { api_key: typedKey } : {}), workspace_id: workspace || null }),
      });
      setModels(list);
      toast.success(list.length ? `Key works. ${list.length} models available.` : "No key to test.");
    } catch (err) {
      setModels([]);
      setError(errorMessage(err, "Could not test the key."));
    } finally {
      setBusy(false);
    }
  }

  async function save() {
    setBusy(true);
    setError(null);
    try {
      const saved = await apiFetch<AgentConfig>("/api/agent-config", {
        method: "PUT",
        body: JSON.stringify({
          ...(typedKey ? { api_key: typedKey } : {}),
          default_model: model || null,
          workspace_id: workspace || null,
        }),
      });
      setConfig(saved);
      setModel(saved.default_model ?? "");
      setWorkspaceId(saved.workspace_id ?? "");
      setApiKey("");
      toast.success("AI settings saved");
    } catch (err) {
      setError(errorMessage(err, "Could not save your AI settings."));
    } finally {
      setBusy(false);
    }
  }

  async function removeKey() {
    setBusy(true);
    setError(null);
    try {
      const saved = await apiFetch<AgentConfig>("/api/agent-config/key", { method: "DELETE" });
      setConfig(saved);
      setModel("");
      setModels([]);
      setApiKey("");
      toast.success("Your key was removed");
    } catch (err) {
      setError(errorMessage(err, "Could not remove your key."));
    } finally {
      setBusy(false);
    }
  }

  // The saved model may not be in the live list until the key is tested; keep it selectable.
  const options =
    model && !models.some((m) => m.id === model) ? [{ id: model, display_name: model }, ...models] : models;

  return (
    <div data-testid="ai-key-section">
      {error && <Alert variant="danger">{error}</Alert>}
      <Form.Group className="mb-3" controlId="ai-api-key">
        <Form.Label>Your Anthropic API key</Form.Label>
        <Form.Control
          type="password"
          autoComplete="off"
          placeholder="sk-ant-..."
          value={apiKey}
          onChange={(event) => setApiKey(event.target.value)}
        />
        <Form.Text className="text-muted">
          {hasKey ? "Key saved. Type a new key here to replace it." : "No key saved yet."} The key is encrypted on the
          server and never shown again.
        </Form.Text>
      </Form.Group>
      <Form.Group className="mb-3" controlId="ai-workspace-id">
        <Form.Label>Workspace ID (optional)</Form.Label>
        <Form.Control
          type="text"
          autoComplete="off"
          placeholder="wrkspc_..."
          value={workspaceId}
          onChange={(event) => setWorkspaceId(event.target.value)}
        />
        <Form.Text className="text-muted">
          Only needed for an organisation-level key that is not tied to a workspace. Copy the ID (it starts with
          wrkspc_) from the Anthropic Console under Settings, Workspaces; the workspace name does not work.
        </Form.Text>
      </Form.Group>
      <Form.Group className="mb-3" controlId="ai-model">
        <Form.Label>Model</Form.Label>
        <Form.Select value={model} onChange={(event) => setModel(event.target.value)} disabled={!hasKey && !typedKey}>
          <option value="">No model chosen</option>
          {options.map((m) => (
            <option key={m.id} value={m.id}>
              {m.display_name}
            </option>
          ))}
        </Form.Select>
        <Form.Text className="text-muted">Press Test key to load the models this key can use.</Form.Text>
      </Form.Group>
      <div className="d-flex gap-2 flex-wrap">
        <Button variant="outline-secondary" disabled={busy || (!typedKey && !hasKey)} onClick={() => void testKey()}>
          Test key
        </Button>
        <Button disabled={busy || (!typedKey && !hasKey)} onClick={() => void save()}>
          Save
        </Button>
        {hasKey && (
          <Button variant="outline-danger" disabled={busy} onClick={() => void removeKey()}>
            Remove my key
          </Button>
        )}
      </div>
    </div>
  );
}

export function AiAssistSection({
  isOwner,
  aiEnabled,
  onInstanceChanged,
}: {
  isOwner: boolean;
  aiEnabled: boolean;
  onInstanceChanged: () => void;
}) {
  if (!isOwner && !aiEnabled) return null;
  return (
    <CollapsibleCard title="AI assist" id="ai">
      <div className="mb-3">
        <Badge bg="warning" text="dark">
          Experimental
        </Badge>
      </div>
      {isOwner && <InstanceToggle onChanged={onInstanceChanged} />}
      {aiEnabled && <KeySection />}
    </CollapsibleCard>
  );
}
