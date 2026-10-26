import { useEffect, useState } from "react";
import { Alert, Button, Spinner } from "react-bootstrap";
import { apiFetch, ApiError } from "../api/client";
import { fetchCapabilities } from "../api/capabilities";

interface Explanation {
  text: string;
  warnings: { pattern: string; excerpt: string }[];
  trimmed?: boolean;
}

interface AgentConfig {
  default_model: string | null;
  has_api_key: boolean;
}

interface Props {
  applicationId: string;
  runId: string;
  threatKey: string;
}

/**
 * "Explain (AI, experimental)" for one threat. Renders nothing unless the instance has AI on and this user has a key
 * and a model. The answer is plain text only (never markdown or HTML), is not saved, and is dropped when the threat
 * is collapsed or another one is opened (the parent keys this component by threat).
 */
export function ExplainThreat({ applicationId, runId, threatKey }: Props) {
  const [available, setAvailable] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<Explanation | null>(null);

  useEffect(() => {
    let cancelled = false;
    async function check() {
      try {
        const capabilities = await fetchCapabilities();
        if (!capabilities.ai?.enabled) return;
        const config = await apiFetch<AgentConfig>("/api/agent-config");
        if (!cancelled && config.has_api_key && config.default_model) setAvailable(true);
      } catch {
        // Any failure means "no AI here": show nothing.
      }
    }
    void check();
    return () => {
      cancelled = true;
    };
  }, []);

  async function explain() {
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      setResult(
        await apiFetch<Explanation>(`/api/applications/${applicationId}/runs/${runId}/threats/explain`, {
          method: "POST",
          body: JSON.stringify({ threat_key: threatKey }),
        }),
      );
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not get an explanation.");
    } finally {
      setBusy(false);
    }
  }

  if (!available) return null;

  const paragraphs = result
    ? result.text
        .split(/\n\s*\n/)
        .map((p) => p.trim())
        .filter(Boolean)
    : [];

  return (
    <div className="mb-3" onClick={(e) => e.stopPropagation()}>
      <Button size="sm" variant="outline-secondary" disabled={busy} onClick={() => void explain()}>
        {busy ? (
          <>
            <Spinner animation="border" size="sm" className="me-1" role="status" aria-hidden="true" />
            Explaining...
          </>
        ) : (
          "Explain (AI, experimental)"
        )}
      </Button>
      {error && (
        <Alert variant="danger" className="small mt-2 mb-0" role="alert">
          {error}
        </Alert>
      )}
      {result && (
        <div className="mt-2" aria-label="AI explanation">
          {result.warnings.length > 0 && (
            <Alert variant="warning" className="small">
              This threat&apos;s text contains wording that looks aimed at an AI reviewer. Treat the explanation with
              care.
              <ul className="mb-0 mt-1">
                {result.warnings.map((w, i) => (
                  <li key={i}>
                    {w.pattern}: {w.excerpt}
                  </li>
                ))}
              </ul>
            </Alert>
          )}
          {paragraphs.map((p, i) => (
            <p key={i} className="mb-2" style={{ whiteSpace: "pre-wrap" }}>
              {p}
            </p>
          ))}
          {result.trimmed && <p className="small text-muted mb-1">Based on shortened component details</p>}
          <p className="small text-muted mb-0">AI-generated, may be wrong. Not saved.</p>
        </div>
      )}
    </div>
  );
}
