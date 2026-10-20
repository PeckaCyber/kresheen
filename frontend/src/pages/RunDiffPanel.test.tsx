import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { RunDiffPanel, type RunDiffOut } from "./RunDiffPanel";

function emptyDiff(overrides: Partial<RunDiffOut>): RunDiffOut {
  return {
    current_run_id: "RUN-2",
    previous_run_id: "RUN-1",
    new_components: [],
    removed_components: [],
    new_flows: [],
    removed_flows: [],
    new_threats: [],
    resolved_threats: [],
    new_findings: [],
    resolved_findings: [],
    ...overrides,
  };
}

describe("RunDiffPanel", () => {
  it("shows a first-run message when there is nothing to compare", () => {
    render(<RunDiffPanel diff={emptyDiff({ previous_run_id: null })} />);
    expect(screen.getByText(/first run/i)).toBeInTheDocument();
  });

  it("shows a no-changes message when every category is empty", () => {
    render(<RunDiffPanel diff={emptyDiff({})} />);
    expect(screen.getByText(/no changes/i)).toBeInTheDocument();
  });

  it("renders new and removed components", () => {
    render(
      <RunDiffPanel
        diff={emptyDiff({
          new_components: [{ key: "process:worker", type: "process", name: "worker" }],
          removed_components: [{ key: "data_store:cache", type: "data_store", name: "cache" }],
        })}
      />,
    );
    expect(screen.getByText("New components")).toBeInTheDocument();
    expect(screen.getByText("worker")).toBeInTheDocument();
    expect(screen.getByText("Removed components")).toBeInTheDocument();
    expect(screen.getByText("cache")).toBeInTheDocument();
  });

  it("renders new threats and findings with severity", () => {
    render(
      <RunDiffPanel
        diff={emptyDiff({
          new_threats: [{ key: "R1|process:web", title: "New spoofing threat", severity: "high" }],
          resolved_findings: [{ title: "Fixed CVE", severity: "critical", domain: "vulnerability" }],
        })}
      />,
    );
    expect(screen.getByText("New spoofing threat")).toBeInTheDocument();
    expect(screen.getByText("Fixed CVE")).toBeInTheDocument();
    expect(screen.getByText("Resolved findings")).toBeInTheDocument();
  });
});
