import { extensions } from "../extensions";
import { useEffect, useState, type FormEvent } from "react";
import { Alert, Button, Container, Form } from "react-bootstrap";
import { Navigate, useNavigate } from "react-router-dom";
import { fetchCapabilities, type AuthProviderInfo } from "../api/capabilities";
import { apiFetch } from "../api/client";
import { useAuth } from "../auth/AuthContext";

export function Login() {
  const { login, isAuthenticated, loading, signedOutByTimeout } = useAuth();
  const navigate = useNavigate();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showPassword, setShowPassword] = useState(false);
  const [providers, setProviders] = useState<AuthProviderInfo[]>([]);
  const [desktop, setDesktop] = useState(false);

  useEffect(() => {
    fetchCapabilities()
      .then((caps) => setProviders(caps.auth_providers))
      .catch(() => setProviders([]));
    // Only a desktop install on this computer says so; any failure just leaves the note out.
    apiFetch<{ desktop?: boolean }>("/api/auth/setup")
      .then((status) => setDesktop(status.desktop === true))
      .catch(() => setDesktop(false));
  }, []);

  // A provider can say that passwords are refused for most users; the form then waits behind an owner link.
  const passwordTucked = providers.some((provider) => provider.password_login === false);
  const passwordHidden = passwordTucked && !showPassword;

  if (!loading && isAuthenticated) {
    return <Navigate to="/dashboard" replace />;
  }

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      await login(email, password);
      navigate("/dashboard", { replace: true });
    } catch {
      setError("Invalid email or password.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <Container style={{ maxWidth: 360, marginTop: "4rem" }}>
      <h1 className="h4 mb-3">Kresheen</h1>
      {signedOutByTimeout && !error && (
        <Alert variant="info">You were signed out after a period of inactivity. Sign in again to continue.</Alert>
      )}
      {error && <Alert variant="danger">{error}</Alert>}
      {extensions.loginButtons.map((button) => (
        <div key={button.id} className="mb-3">
          {button.render()}
        </div>
      ))}
      {providers.map((provider) => (
        <a key={provider.id} href={provider.login_url} className="btn btn-outline-primary w-100 mb-3">
          Sign in with {provider.label}
        </a>
      ))}
      {providers.length > 0 && !passwordTucked && (
        <div className="text-muted small text-center mb-3">or use a password</div>
      )}
      {passwordHidden && (
        <Button variant="link" size="sm" className="d-block mx-auto" onClick={() => setShowPassword(true)}>
          Owner password sign-in
        </Button>
      )}
      {!passwordHidden && (
        <Form onSubmit={handleSubmit}>
          <Form.Group className="mb-3" controlId="email">
            <Form.Label>Email</Form.Label>
            <Form.Control
              type="email"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              autoFocus
              required
            />
          </Form.Group>
          <Form.Group className="mb-3" controlId="password">
            <Form.Label>Password</Form.Label>
            <Form.Control
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              required
            />
          </Form.Group>
          <Button type="submit" disabled={submitting}>
            {submitting ? "Signing in..." : "Sign in"}
          </Button>
        </Form>
      )}
      {desktop && (
        <p className="text-muted small mt-4 mb-0">
          This is Kresheen on this computer. Sign in with the account you created the first time you started it. If you
          forgot the password, or are not sure which account it was, run <code>kresheen reset-password</code> (see{" "}
          <a
            href="https://github.com/PeckaCyber/kresheen/blob/main/docs/installation.md#forgot-your-password"
            target="_blank"
            rel="noreferrer"
          >
            Forgot your password
          </a>
          ).
        </p>
      )}
    </Container>
  );
}
