import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { MemoryRouter } from "react-router-dom";
import { RunHistory, type RunHistoryEntry } from "./RunHistory";

const RUNS: RunHistoryEntry[] = [
  { id: "RUN-1", status: "completed", started_at: "2026-09-20T10:00:00Z" },
  { id: "RUN-2", status: "failed", started_at: "2026-09-21T10:00:00Z" },
  { id: "RUN-3", status: "completed", started_at: "2026-09-22T10:00:00Z" },
];

function open(currentRunId: string) {
  render(
    <MemoryRouter>
      <RunHistory applicationId="APP-1" currentRunId={currentRunId} runs={RUNS} />
    </MemoryRouter>,
  );
  fireEvent.click(screen.getByRole("button"));
}

describe("RunHistory", () => {
  it("labels the toggle with the current run's position", () => {
    render(
      <MemoryRouter>
        <RunHistory applicationId="APP-1" currentRunId="RUN-2" runs={RUNS} />
      </MemoryRouter>,
    );
    expect(screen.getByRole("button", { name: "Run 2 of 3" })).toBeInTheDocument();
  });

  it("lists every run, newest first, linking to its own run", () => {
    open("RUN-2");

    const links = screen.getAllByRole("link");
    expect(links).toHaveLength(3);
    expect(links[0]).toHaveAttribute("href", "/applications/APP-1/runs/RUN-3");
    expect(links[2]).toHaveAttribute("href", "/applications/APP-1/runs/RUN-1");
  });

  it("marks a non-completed run's status in its label", () => {
    open("RUN-1");
    expect(screen.getByText(/\(failed\)/)).toBeInTheDocument();
  });
});
