import { fireEvent, render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { DashboardPage } from "./Dashboard";
import { EMPTY_SUMMARY } from "./dashboard/types";

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" } });
}

const app = (over: Record<string, unknown> = {}) => ({
  id: "A",
  name: "A",
  group_id: null,
  group_name: null,
  latest_run_id: "R",
  worst_severity: null,
  finding_count: 0,
  open_threat_count: 0,
  worst_threat_risk: null,
  not_analysed: false,
  stale: false,
  days_since_run: 0,
  addressed_count: 0,
  total_threat_count: 0,
  open_by_risk: {},
  open_by_category: {},
  completeness_score: null,
  reviewed_at: null,
  open_action_count: null,
  ...over,
});

const payload = (over: Record<string, unknown> = {}) => ({
  applications: [],
  trend: [],
  summary: { ...EMPTY_SUMMARY },
  recent_activity: [],
  ...over,
});

describe("DashboardPage", () => {
  const fetchMock = vi.fn();
  beforeEach(() => {
    fetchMock.mockReset();
    vi.stubGlobal("fetch", fetchMock);
  });

  function open(body: unknown) {
    fetchMock.mockResolvedValue(jsonResponse(body));
    render(
      <MemoryRouter>
        <DashboardPage />
      </MemoryRouter>,
    );
  }

  it("rolls up the stat tiles from the summary", async () => {
    open(
      payload({
        applications: [app({ id: "1", name: "Fresh", open_threat_count: 4, worst_threat_risk: "high" })],
        summary: { ...EMPTY_SUMMARY, application_count: 3, open_threat_count: 12, open_by_risk: { high: 4, low: 8 } },
      }),
    );
    expect(within(await screen.findByTestId("dash-tile-models")).getByText("3")).toBeInTheDocument();
    expect(within(screen.getByTestId("dash-tile-openThreats")).getByText("12")).toBeInTheDocument();
    expect(within(screen.getByTestId("dash-tile-highCritical")).getByText("4")).toBeInTheDocument();
  });

  it("refetches with the selected days when the time range control is used", async () => {
    open(payload({ applications: [app({ id: "1" })] }));
    await screen.findByTestId("dash-tile-models");
    expect(fetchMock).toHaveBeenCalledWith("/api/dashboard?days=90", expect.anything());

    fireEvent.click(screen.getByRole("button", { name: "30d" }));

    await vi.waitFor(() => {
      expect(fetchMock).toHaveBeenCalledWith("/api/dashboard?days=30", expect.anything());
    });
  });

  it("shows the trend empty state instead of a chart with fewer than two points", async () => {
    open(payload({ applications: [app({ id: "1" })], trend: [{ day: "2026-09-26", open: 5, new: 0, resolved: 0, open_by_risk: {} }] }));
    expect(await screen.findByText(/Trend appears after a second day of data/)).toBeInTheDocument();
  });

  it("formats a non-zero risk share that rounds to 0% as <1%", async () => {
    open(
      payload({
        applications: [app({ id: "1", open_threat_count: 201 })],
        summary: { ...EMPTY_SUMMARY, application_count: 1, open_threat_count: 201, open_by_risk: { critical: 1, low: 200 } },
      }),
    );
    expect(await screen.findByText("<1%")).toBeInTheDocument();
  });

  it("shows a friendly empty state with no applications instead of empty panels", async () => {
    open(payload());
    expect(await screen.findByRole("heading", { name: "Create your first threat model" })).toBeInTheDocument();
    const link = screen.getByRole("link", { name: "Create your first threat model" });
    expect(link).toHaveAttribute("href", "/applications");
  });

  it("opens the All applications drawer with the unified column set", async () => {
    open(
      payload({
        applications: [
          app({
            id: "1",
            name: "Sample shop",
            group_name: "Retail",
            open_threat_count: 2,
            worst_threat_risk: "high",
            addressed_count: 1,
            total_threat_count: 4,
            completeness_score: 80,
            days_since_run: 3,
            reviewed_at: "2026-09-01T00:00:00Z",
          }),
        ],
        summary: { ...EMPTY_SUMMARY, application_count: 1 },
      }),
    );
    fireEvent.click(await screen.findByTestId("dash-tile-models"));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText("All applications")).toBeInTheDocument();
    for (const header of ["Application", "Group", "Worst risk", "Open", "Addressed", "Completeness", "Last run", "Reviewed"]) {
      expect(within(dialog).getByText(header)).toBeInTheDocument();
    }
    expect(within(dialog).getByText("Sample shop")).toBeInTheDocument();
    expect(within(dialog).getByText("Retail")).toBeInTheDocument();
    expect(within(dialog).getByText("3 days ago")).toBeInTheDocument();
  });
});
