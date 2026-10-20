import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { apiFetch } from "../api/client";
import { UNGROUPED_ID, type GroupOut } from "./Groups";

// Small, self-contained (same pattern as RunHistory.tsx): fetches just
// enough to resolve this application's group name, independent of whatever
// else ApplicationDetail.tsx has already loaded.
export function GroupBackLink({ applicationId }: { applicationId: string }) {
  const [label, setLabel] = useState<string | null>(null);
  const [groupId, setGroupId] = useState<string>(UNGROUPED_ID);

  useEffect(() => {
    let cancelled = false;
    Promise.all([
      apiFetch<{ group_id: string | null }>(`/api/applications/${applicationId}`),
      apiFetch<{ groups: GroupOut[] }>("/api/groups"),
    ])
      .then(([application, { groups }]) => {
        if (cancelled) return;
        if (application.group_id === null) {
          setGroupId(UNGROUPED_ID);
          setLabel("Ungrouped");
        } else {
          setGroupId(application.group_id);
          setLabel(groups.find((g) => g.id === application.group_id)?.name ?? "Ungrouped");
        }
      })
      .catch(() => setLabel(null));
    return () => {
      cancelled = true;
    };
  }, [applicationId]);

  if (!label) return null;

  return (
    <Link to={`/applications/groups/${groupId}`} className="small text-decoration-none">
      &larr; {label}
    </Link>
  );
}
