import { useEffect, useState, type FormEvent } from "react";
import { CollapsibleCard } from "./CollapsibleCard";
import { Alert, Button, Form, Table } from "react-bootstrap";
import { apiFetch } from "../api/client";
import { useToast } from "../components/Toasts";

interface TokenOut {
  id: string;
  name: string;
  prefix: string;
  created_at: string;
  last_used_at: string | null;
  expires_at?: string | null;
}

interface CreatedToken extends TokenOut {
  secret: string;
}

export function ApiTokensSection() {
  const toast = useToast();
  const [tokens, setTokens] = useState<TokenOut[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [name, setName] = useState("");
  const [expiresInDays, setExpiresInDays] = useState("90");  // "never" is an explicit choice
  const [created, setCreated] = useState<CreatedToken | null>(null);

  function load() {
    return apiFetch<TokenOut[]>("/api/tokens")
      .then(setTokens)
      .catch(() => setError("Failed to load API tokens"));
  }

  useEffect(() => {
    void load();
  }, []);

  async function handleCreate(event: FormEvent) {
    event.preventDefault();
    try {
      const token = await apiFetch<CreatedToken>("/api/tokens", {
        method: "POST",
        body: JSON.stringify({ name, expires_in_days: expiresInDays === "never" ? null : Number(expiresInDays) }),
      });
      setCreated(token);
      setName("");
      setExpiresInDays("90");
      await load();
      toast.success("Token created");
    } catch {
      toast.error("Failed to create that token");
    }
  }

  async function handleRevoke(id: string) {
    try {
      await apiFetch(`/api/tokens/${id}`, { method: "DELETE" });
      if (created?.id === id) setCreated(null);
      await load();
      toast.success("Token revoked");
    } catch {
      toast.error("Failed to revoke that token");
    }
  }

  return (
    <CollapsibleCard title="API tokens">
        <p className="text-muted small">
          For CI jobs and scripts (<code>kresheen ci</code>). A token acts as you but can only list models and start and read runs; treat it like a password. Changing your password revokes your tokens.
        </p>
        {error && <Alert variant="danger" className="mb-2">{error}</Alert>}
        {created && (
          <Alert variant="warning">
            Copy this token now; it is not shown again.
            <pre className="mb-0 mt-2 user-select-all" data-testid="new-token-secret">
              {created.secret}
            </pre>
          </Alert>
        )}
        {tokens && tokens.length > 0 && (
          <Table size="sm" className="small">
            <thead>
              <tr>
                <th>Name</th>
                <th>Token</th>
                <th>Last used</th>
                <th>Expires</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {tokens.map((token) => (
                <tr key={token.id}>
                  <td>{token.name}</td>
                  <td>
                    <code>{token.prefix}...</code>
                  </td>
                  <td>{token.last_used_at ? new Date(token.last_used_at).toLocaleString() : "never"}</td>
                  <td>
                    {token.expires_at
                      ? new Date(token.expires_at).getTime() <= Date.now()
                        ? <span className="text-danger">expired</span>
                        : new Date(token.expires_at).toLocaleDateString()
                      : "never expires"}
                  </td>
                  <td className="text-end">
                    <Button size="sm" variant="outline-danger" onClick={() => void handleRevoke(token.id)}>
                      Revoke
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
        <Form onSubmit={handleCreate} className="d-flex gap-2">
          <Form.Control
            aria-label="Token name"
            placeholder="Name, e.g. github-actions"
            value={name}
            onChange={(event) => setName(event.target.value)}
          />
          <Form.Select
            aria-label="Token expiry"
            style={{ maxWidth: 150 }}
            value={expiresInDays}
            onChange={(event) => setExpiresInDays(event.target.value)}
          >
            <option value="30">30 days</option>
            <option value="90">90 days</option>
            <option value="365">1 year</option>
            <option value="never">Never expires</option>
          </Form.Select>
          <Button type="submit" disabled={!name.trim()}>
            Create token
          </Button>
        </Form>
        {expiresInDays === "never" && (
          <Alert variant="warning" className="mt-2 mb-0 small">
            A token that never expires stays valid until you revoke it. If it leaks, it works indefinitely. Prefer an expiry and rotate the CI secret.
          </Alert>
        )}
    </CollapsibleCard>
  );
}
