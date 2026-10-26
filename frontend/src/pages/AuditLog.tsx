import { useEffect, useState } from "react";
import { Alert, Button, Table } from "react-bootstrap";
import { apiFetch } from "../api/client";
import { PageHeader } from "../components/PageHeader";

interface AuditEvent {
  id: string;
  at: string;
  user_email: string | null;
  action: string;
  subject: Record<string, string>;
  status_code: number | null;
  via: string;
  client_ip: string | null;
}

const PAGE = 100;

export function AuditLogPage() {
  const [events, setEvents] = useState<AuditEvent[] | null>(null);
  const [hasMore, setHasMore] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [summary, setSummary] = useState<{ count: number; max_entries: number } | null>(null);

  function fetchPage(before?: string) {
    const query = new URLSearchParams({ limit: String(PAGE) });
    if (before) query.set("before", before);
    return apiFetch<AuditEvent[]>(`/api/audit-log?${query.toString()}`).then((page) => {
      setEvents((current) => [...(before ? (current ?? []) : []), ...page]);
      setHasMore(page.length === PAGE);
    });
  }

  useEffect(() => {
    fetchPage().catch(() => setError("Failed to load the audit log (owners only)."));
    apiFetch<{ count: number; max_entries: number }>("/api/audit-log/summary")
      .then(setSummary)
      .catch(() => undefined);
  }, []);

  const summaryBadge = summary && (
    <span className="text-muted small" title="The oldest entries are dropped once the log is full">
      {summary.count.toLocaleString()} / {summary.max_entries.toLocaleString()} entries
    </span>
  );

  return (
    <div className="pc-page">
      <PageHeader
        title="Audit log"
        subtitle="Every change made through the dashboard or an API token, newest first. Request contents are never recorded."
        actions={summaryBadge}
      />
      {error && <Alert variant="danger">{error}</Alert>}
      {events && (
        <Table size="sm" className="small">
          <thead>
            <tr>
              <th>When</th>
              <th>Who</th>
              <th>Action</th>
              <th>Target</th>
              <th>Result</th>
              <th>Via</th>
            </tr>
          </thead>
          <tbody>
            {events.map((event) => (
              <tr key={event.id}>
                <td>{new Date(event.at).toLocaleString()}</td>
                <td>{event.user_email ?? "unknown"}</td>
                <td>
                  <code>{event.action}</code>
                </td>
                <td>{Object.values(event.subject).join(" / ")}</td>
                <td>{event.status_code ?? ""}</td>
                <td>{event.via === "api_token" ? "API token" : "browser"}</td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}
      {events && events.length === 0 && <p>No activity yet.</p>}
      {hasMore && events && (
        <Button
          variant="outline-secondary"
          onClick={() => void fetchPage(events[events.length - 1].at).catch(() => setError("Failed to load more."))}
        >
          Load older
        </Button>
      )}
    </div>
  );
}
