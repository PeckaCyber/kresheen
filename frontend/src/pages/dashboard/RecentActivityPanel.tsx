import { useMemo } from "react";
import { describeActivity } from "./activity";
import { relativeTime } from "./format";
import type { DashboardApplication, RecentActivityItem } from "./types";

// Owner-only; hidden entirely when there is nothing to show (either the
// caller isn't the owner, or nothing has happened yet).
export function RecentActivityPanel({ events, apps }: { events: RecentActivityItem[]; apps: DashboardApplication[] }) {
  const appNamesById = useMemo(() => Object.fromEntries(apps.map((a) => [a.id, a.name])), [apps]);

  if (events.length === 0) return null;

  return (
    <section className="pc-panel h-100" aria-label="Recent activity">
      <div className="pc-panel-head">
        <span>Recent activity</span>
      </div>
      <div className="pc-panel-body">
        <ul className="list-unstyled mb-0">
          {events.map((event, index) => (
            <li key={`${event.at}-${index}`} className="d-flex justify-content-between gap-2 py-1 small">
              <span>{describeActivity(event, appNamesById)}</span>
              <span className="text-muted flex-shrink-0">{relativeTime(event.at)}</span>
            </li>
          ))}
        </ul>
      </div>
    </section>
  );
}
