import { useEffect, useState } from "react";
import { Button } from "react-bootstrap";
import { apiFetch } from "../api/client";
import { useToast } from "../components/Toasts";

interface ReviewState {
  reviewed_at: string | null;
  reviewed_by: string;
}

// "Mark as reviewed": a person signing the model off, with who and when.
// The stamp is not tied to a version of the model: it says who last looked, not what they looked at,
// so anything changed afterwards is on the reader to notice. It is also in the exported reports.
export function ReviewStamp({ applicationId }: { applicationId: string }) {
  const toast = useToast();
  const [state, setState] = useState<ReviewState | null>(null);
  const [busy, setBusy] = useState(false);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    let current = true;
    apiFetch<ReviewState>(`/api/applications/${applicationId}`)
      .then((out) => current && setState({ reviewed_at: out.reviewed_at, reviewed_by: out.reviewed_by }))
      .catch(() => current && setFailed(true));
    return () => {
      current = false;
    };
  }, [applicationId]);

  async function set(reviewed: boolean) {
    setBusy(true);
    try {
      const out = await apiFetch<ReviewState>(`/api/applications/${applicationId}/review`, {
        method: "PUT",
        body: JSON.stringify({ reviewed }),
      });
      setState({ reviewed_at: out.reviewed_at, reviewed_by: out.reviewed_by });
      toast.success(reviewed ? "Marked as reviewed" : "Review status cleared");
    } catch {
      toast.error("Could not save review status");
    } finally {
      setBusy(false);
    }
  }

  if (failed) return <span className="small text-muted">Could not load.</span>;
  if (!state) return null;
  return (
    <span className="d-inline-flex align-items-center gap-2">
      {state.reviewed_at ? (
        <>
          <span className="small text-success">
            Reviewed {new Date(state.reviewed_at).toLocaleDateString()}
            {state.reviewed_by && ` by ${state.reviewed_by}`}
          </span>
          <Button size="sm" variant="link" className="p-0" disabled={busy} onClick={() => void set(false)}>
            Undo
          </Button>
        </>
      ) : (
        <Button size="sm" variant="outline-success" disabled={busy} onClick={() => void set(true)}>
          Mark as reviewed
        </Button>
      )}
    </span>
  );
}
