import { useEffect, useState, type FormEvent } from "react";
import { CollapsibleCard } from "./CollapsibleCard";
import { Alert, Button, Form, Table } from "react-bootstrap";
import { apiFetch } from "../api/client";
import { useToast } from "../components/Toasts";

interface UserOut {
  id: string;
  email: string;
  role: "owner" | "member";
  auth_source: "password" | "sso";
  is_active: boolean;
  created_at: string;
}

interface CreatedUserOut extends UserOut {
  one_time_password: string;
}

export function UsersSection({ defaultOpen }: { defaultOpen?: boolean } = {}) {
  const toast = useToast();
  const [users, setUsers] = useState<UserOut[] | null>(null);
  const [email, setEmail] = useState("");
  const [role, setRole] = useState<"owner" | "member">("member");
  const [created, setCreated] = useState<CreatedUserOut | null>(null);
  const [copied, setCopied] = useState(false);

  function load() {
    return apiFetch<UserOut[]>("/api/users")
      .then(setUsers)
      .catch(() => toast.error("Failed to load users"));
  }

  useEffect(() => {
    void load();
  }, []);

  async function handleCreate(event: FormEvent) {
    event.preventDefault();
    setCopied(false);
    try {
      const user = await apiFetch<CreatedUserOut>("/api/users", {
        method: "POST",
        body: JSON.stringify({ email, role }),
      });
      setCreated(user);
      setEmail("");
      setRole("member");
      await load();
      toast.success("User added");
    } catch {
      toast.error("Failed to add that user");
    }
  }

  async function handleRoleChange(user: UserOut, newRole: "owner" | "member") {
    try {
      await apiFetch(`/api/users/${user.id}`, { method: "PATCH", body: JSON.stringify({ role: newRole }) });
      await load();
      toast.success("Role updated");
    } catch {
      toast.error("Failed to change that user's role");
    }
  }

  async function handleToggleActive(user: UserOut) {
    try {
      await apiFetch(`/api/users/${user.id}`, {
        method: "PATCH",
        body: JSON.stringify({ is_active: !user.is_active }),
      });
      await load();
      toast.success(user.is_active ? "User deactivated" : "User reactivated");
    } catch {
      toast.error(`Failed to ${user.is_active ? "deactivate" : "reactivate"} that user`);
    }
  }

  async function handleCopy(secret: string) {
    try {
      await navigator.clipboard.writeText(secret);
      setCopied(true);
    } catch {
      setCopied(false);
    }
  }

  return (
    <CollapsibleCard title="Users" id="users" defaultOpen={defaultOpen}>
      <p className="text-muted small">Who has access to this deployment.</p>
      {created && (
        <Alert variant="warning">
          <div>
            One-time password for <strong>{created.email}</strong>. Share this with the person; it will not be
            shown again.
          </div>
          <div className="d-flex align-items-center gap-2 mt-2">
            <code className="user-select-all" data-testid="new-user-password">
              {created.one_time_password}
            </code>
            <Button size="sm" variant="outline-secondary" onClick={() => void handleCopy(created.one_time_password)}>
              Copy
            </Button>
            {copied && <span className="small text-muted">Copied.</span>}
          </div>
        </Alert>
      )}
      {users && users.length > 0 && (
        <Table size="sm" className="small">
          <thead>
            <tr>
              <th>Email</th>
              <th>Role</th>
              <th>Source</th>
              <th>Status</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {users.map((user) => (
              <tr key={user.id} className={user.is_active ? undefined : "bg-body-secondary"}>
                <td>{user.email}</td>
                <td>
                  <Form.Select
                    size="sm"
                    aria-label={`Role for ${user.email}`}
                    value={user.role}
                    onChange={(event) => void handleRoleChange(user, event.target.value as "owner" | "member")}
                  >
                    <option value="owner">owner</option>
                    <option value="member">member</option>
                  </Form.Select>
                </td>
                <td>{user.auth_source}</td>
                <td>{user.is_active ? "active" : "disabled"}</td>
                <td className="text-end">
                  <Button
                    size="sm"
                    variant={user.is_active ? "outline-danger" : "outline-secondary"}
                    onClick={() => void handleToggleActive(user)}
                  >
                    {user.is_active ? "Deactivate" : "Reactivate"}
                  </Button>
                </td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}
      <Form onSubmit={handleCreate} className="d-flex gap-2 align-items-start flex-wrap">
        <Form.Control
          aria-label="New user email"
          placeholder="person@example.com"
          type="email"
          value={email}
          onChange={(event) => setEmail(event.target.value)}
        />
        <Form.Select
          aria-label="New user role"
          value={role}
          onChange={(event) => setRole(event.target.value as "owner" | "member")}
          style={{ width: "auto" }}
        >
          <option value="member">member</option>
          <option value="owner">owner</option>
        </Form.Select>
        <Button type="submit" disabled={!email.trim()}>
          Add user
        </Button>
      </Form>
    </CollapsibleCard>
  );
}
