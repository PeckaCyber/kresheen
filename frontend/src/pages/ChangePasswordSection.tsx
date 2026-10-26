import { useState, type FormEvent } from "react";
import { CollapsibleCard } from "./CollapsibleCard";
import { Alert, Button, Form } from "react-bootstrap";
import { ApiError, apiFetch } from "../api/client";
import { useToast } from "../components/Toasts";

// Server floor is 12 chars (`dashboard/auth.py::MIN_PASSWORD_LENGTH`); this
// mirrors it only so the mismatch case shows a clear message instead of a
// generic error -- the server is still the source of truth.
const MIN_PASSWORD_LENGTH = 12;

export function ChangePasswordSection({ defaultOpen }: { defaultOpen?: boolean } = {}) {
  const toast = useToast();
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [ssoOnly, setSsoOnly] = useState(false);

  const mismatch = confirmPassword.length > 0 && newPassword !== confirmPassword;
  const tooShort = newPassword.length > 0 && newPassword.length < MIN_PASSWORD_LENGTH;

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setError(null);
    setSsoOnly(false);
    if (newPassword !== confirmPassword) {
      setError("New password and confirmation do not match");
      return;
    }
    try {
      await apiFetch("/api/auth/change-password", {
        method: "POST",
        body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
      });
      setCurrentPassword("");
      setNewPassword("");
      setConfirmPassword("");
      toast.success("Password changed; other sessions were signed out");
    } catch (err) {
      if (err instanceof ApiError && err.status === 403) {
        setSsoOnly(true);
      } else if (err instanceof ApiError && err.status === 401) {
        setError("Current password is incorrect");
      } else {
        setError("Failed to change password");
      }
    }
  }

  return (
    <CollapsibleCard title="Account" id="account" defaultOpen={defaultOpen}>
      {ssoOnly && (
        <Alert variant="info">This account signs in via single sign-on; there is no password to change here.</Alert>
      )}
      {!ssoOnly && (
        <>
          <p className="text-muted small">Change your own sign-in password.</p>
          {error && <Alert variant="danger">{error}</Alert>}
          <Form onSubmit={handleSubmit}>
            <Form.Group className="mb-3" controlId="current-password">
              <Form.Label>Current password</Form.Label>
              <Form.Control
                type="password"
                autoComplete="current-password"
                value={currentPassword}
                onChange={(event) => setCurrentPassword(event.target.value)}
                required
              />
            </Form.Group>
            <Form.Group className="mb-3" controlId="new-password">
              <Form.Label>New password</Form.Label>
              <Form.Control
                type="password"
                autoComplete="new-password"
                value={newPassword}
                onChange={(event) => setNewPassword(event.target.value)}
                isInvalid={tooShort}
                required
              />
              <Form.Control.Feedback type="invalid">
                Must be at least {MIN_PASSWORD_LENGTH} characters.
              </Form.Control.Feedback>
            </Form.Group>
            <Form.Group className="mb-3" controlId="confirm-password">
              <Form.Label>Confirm new password</Form.Label>
              <Form.Control
                type="password"
                autoComplete="new-password"
                value={confirmPassword}
                onChange={(event) => setConfirmPassword(event.target.value)}
                isInvalid={mismatch}
                required
              />
              <Form.Control.Feedback type="invalid">Passwords do not match.</Form.Control.Feedback>
            </Form.Group>
            <Button
              type="submit"
              disabled={!currentPassword || newPassword.length < MIN_PASSWORD_LENGTH || newPassword !== confirmPassword}
            >
              Change password
            </Button>
          </Form>
        </>
      )}
    </CollapsibleCard>
  );
}
