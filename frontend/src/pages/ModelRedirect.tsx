import { useEffect, useState } from "react";
import { Button } from "react-bootstrap";
import { Link, Navigate, useNavigate, useParams } from "react-router-dom";
import { apiFetch, ApiError } from "../api/client";
import type { RunHistoryEntry } from "./RunHistory";

// Route target for /models/:applicationId -- a stable, run-independent link.
// Resolves to the latest *completed* run's page; failing that, to the latest run of any status (a failed first
// run lands on the failed-run page, which has the tools to fix it); or explains that the model has no runs. `runs` comes back oldest-first (same order
// RunHistory.tsx relies on).
export function ModelRedirectPage() {
  const { applicationId } = useParams<{ applicationId: string }>();
  const navigate = useNavigate();
  const [starting, setStarting] = useState(false);
  const [startError, setStartError] = useState<string | null>(null);
  const [status, setStatus] = useState<"loading" | "found" | "none" | "error">("loading");
  const [runId, setRunId] = useState<string | null>(null);

  useEffect(() => {
    if (!applicationId) return;
    let cancelled = false;
    setStatus("loading");
    apiFetch<RunHistoryEntry[]>(`/api/applications/${applicationId}/runs`)
      .then((runs) => {
        if (cancelled) return;
        const latestCompleted = [...runs].reverse().find((run) => run.status === "completed");
        const target = latestCompleted ?? runs[runs.length - 1];
        if (target) {
          setRunId(target.id);
          setStatus("found");
        } else {
          setStatus("none");
        }
      })
      .catch(() => {
        if (!cancelled) setStatus("error");
      });
    return () => {
      cancelled = true;
    };
  }, [applicationId]);

  async function runNow() {
    setStarting(true);
    setStartError(null);
    try {
      const run = await apiFetch<{ id: string }>(`/api/applications/${applicationId}/runs`, { method: "POST" });
      navigate(`/applications/${applicationId}/runs/${run.id}`);
    } catch (err) {
      setStartError(err instanceof ApiError ? err.message : "Could not start a run.");
    } finally {
      setStarting(false);
    }
  }

  if (status === "loading") return null;
  if (status === "found" && runId && applicationId) {
    return <Navigate to={`/applications/${applicationId}/runs/${runId}`} replace />;
  }

  return (
    <div className="pc-page-narrow">
      <p className="text-muted">
        {status === "error" ? "Failed to load this threat model." : "This model has not been run yet."}{" "}
        <Link to="/applications">Back to threat models</Link>
      </p>
      {status === "none" && applicationId && (
        <p>
          <Button variant="primary" disabled={starting} onClick={() => void runNow()}>
            {starting ? "Running..." : "Run this model now"}
          </Button>
        </p>
      )}
      {startError && <p className="text-danger">{startError}</p>}
    </div>
  );
}
