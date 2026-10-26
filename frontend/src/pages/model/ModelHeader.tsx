import { useEffect, useState } from "react";
import { apiFetch } from "../../api/client";
import { PageHeader, type Crumb } from "../../components/PageHeader";
import { UNGROUPED_ID, type GroupOut } from "../Groups";

interface ApplicationSummary {
  name: string;
  group_id: string | null;
}

// The run page's header: application name as the title, a breadcrumb back
// to the threat models list and the owning group. Fetches independently
// of the rest of ApplicationDetail.tsx, same self-contained pattern as
// GroupBackLink.tsx / RunHistory.tsx, so this component has no dependency on
// what else the page has already loaded.
export function ModelHeader({
  applicationId,
  actions,
  compact = false,
}: {
  applicationId: string;
  actions?: React.ReactNode;
  compact?: boolean;
}) {
  const [appName, setAppName] = useState<string | null>(null);
  const [groupId, setGroupId] = useState<string>(UNGROUPED_ID);
  const [groupLabel, setGroupLabel] = useState<string>("Ungrouped");

  useEffect(() => {
    let cancelled = false;
    Promise.all([
      apiFetch<ApplicationSummary>(`/api/applications/${applicationId}`),
      apiFetch<{ groups: GroupOut[] }>("/api/groups"),
    ])
      .then(([application, { groups }]) => {
        if (cancelled) return;
        setAppName(application.name);
        if (application.group_id === null) {
          setGroupId(UNGROUPED_ID);
          setGroupLabel("Ungrouped");
        } else {
          setGroupId(application.group_id);
          setGroupLabel(groups.find((g) => g.id === application.group_id)?.name ?? "Ungrouped");
        }
      })
      .catch(() => {
        if (!cancelled) setAppName(null);
      });
    return () => {
      cancelled = true;
    };
  }, [applicationId]);

  const crumbs: Crumb[] = [
    { label: "Threat models", to: "/applications" },
    { label: groupLabel, to: `/applications?group=${encodeURIComponent(groupId)}` },
    { label: appName ?? "..." },
  ];

  return <PageHeader title={appName ?? "Loading..."} crumbs={crumbs} actions={actions} compact={compact} />;
}
