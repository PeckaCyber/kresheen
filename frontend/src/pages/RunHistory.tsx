import { Dropdown } from "react-bootstrap";
import { Link } from "react-router-dom";

export interface RunHistoryEntry {
  id: string;
  status: string;
  started_at: string;
}

interface RunHistoryProps {
  applicationId: string;
  currentRunId: string;
  runs: RunHistoryEntry[];
}

// A dropdown of every run for this Application (oldest first, matching
// list_runs_for_application's chronological order), so a user can jump to
// an older run without navigating back through the Applications list.
export function RunHistory({ applicationId, currentRunId, runs }: RunHistoryProps) {
  const index = runs.findIndex((r) => r.id === currentRunId);
  const label = index >= 0 ? `Run ${index + 1} of ${runs.length}` : "Run history";

  return (
    <Dropdown align="end">
      <Dropdown.Toggle size="sm" variant="outline-secondary" id="run-history">
        {label}
      </Dropdown.Toggle>
      <Dropdown.Menu>
        {[...runs].reverse().map((run, reversedIndex) => {
          const position = runs.length - reversedIndex;
          return (
            <Dropdown.Item
              key={run.id}
              as={Link}
              to={`/applications/${applicationId}/runs/${run.id}`}
              active={run.id === currentRunId}
            >
              Run {position} of {runs.length} -- {new Date(run.started_at).toLocaleString()}
              {run.status !== "completed" && ` (${run.status})`}
            </Dropdown.Item>
          );
        })}
      </Dropdown.Menu>
    </Dropdown>
  );
}
