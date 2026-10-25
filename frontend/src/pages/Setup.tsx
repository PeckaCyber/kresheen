import { useEffect, useState, type FormEvent } from "react";
import { Alert, Button, Container, Form } from "react-bootstrap";
import { Navigate, useNavigate } from "react-router-dom";
import { apiFetch } from "../api/client";
import { useAuth } from "../auth/AuthContext";

// The desktop launcher opens /setup#token=... on the first start. The token stays in the fragment, which the
// browser never sends to the server, and is posted once with the new account.
function tokenFromHash(): string {
  return new URLSearchParams(window.location.hash.replace(/^#/, "")).get("token") ?? "";
}

// Server floor (`dashboard/auth.py::MIN_PASSWORD_LENGTH`); checked here only for a friendlier message.
const MIN_PASSWORD_LENGTH = 12;

export function Setup() {
  const { login, isAuthenticated, loading } = useAuth();
  const navigate = useNavigate();
  const [token] = useState(tokenFromHash);
  const [needed, setNeeded] = useState<boolean | null>(null);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    // Drop the token from the address bar and history right away; it is kept in state.
    if (window.location.hash) window.history.replaceState(null, "", window.location.pathname);
    apiFetch<{ needed: boolean }>("/api/auth/setup")
      .then((status) => setNeeded(status.needed))
      .catch(() => setNeeded(false));
  }, []);

  if (!loading && isAuthenticated) return <Navigate to="/dashboard" replace />;
  if (needed === null) return null;
  if (!needed || !token) return <Navigate to="/login" replace />;

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setError(null);
    if (password.length < MIN_PASSWORD_LENGTH) {
      setError(`Use at least ${MIN_PASSWORD_LENGTH} characters.`);
      return;
    }
    if (password !== confirm) {
      setError("The passwords do not match.");
      return;
    }
    setSubmitting(true);
    try {
      await apiFetch("/api/auth/setup", { method: "POST", body: JSON.stringify({ token, email, password }) });
      await login(email, password);
      navigate("/dashboard", { replace: true });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Setup failed.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <Container style={{ maxWidth: 400, marginTop: "4rem" }}>
      <h1 className="h4 mb-2">Welcome to Kresheen</h1>
      <p className="text-muted">Create the account you will sign in with. It is the owner of this install.</p>
      {error && <Alert variant="danger">{error}</Alert>}
      <Form onSubmit={handleSubmit}>
        <Form.Group className="mb-3" controlId="setup-email">
          <Form.Label>Email</Form.Label>
          <Form.Control type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoFocus required />
        </Form.Group>
        <Form.Group className="mb-3" controlId="setup-password">
          <Form.Label>Password</Form.Label>
          <Form.Control
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="new-password"
            required
          />
          <Form.Text>At least {MIN_PASSWORD_LENGTH} characters.</Form.Text>
        </Form.Group>
        <Form.Group className="mb-3" controlId="setup-confirm">
          <Form.Label>Confirm password</Form.Label>
          <Form.Control
            type="password"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            autoComplete="new-password"
            required
          />
        </Form.Group>
        <Button type="submit" disabled={submitting}>
          {submitting ? "Creating..." : "Create account"}
        </Button>
      </Form>
    </Container>
  );
}
