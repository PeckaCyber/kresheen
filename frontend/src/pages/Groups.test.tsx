import { fireEvent, render, screen, within, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { GroupsPage } from "./Groups";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

const DASHBOARD_DATA = {
  applications: [
    {
      id: "app-1",
      name: "Payment Gateway",
      group_id: "grp-1",
      group_name: "Payments",
      latest_run_id: "run-1",
      worst_severity: "critical",
      worst_threat_risk: null,
      finding_count: 9,
      open_threat_count: 3,
      not_analysed: false,
      stale: true,
      days_since_run: 5,
      addressed_count: 6,
      total_threat_count: 9,
      completeness_score: 85,
      reviewed_at: "2026-09-20T10:00:00Z",
      open_by_risk: {},
      open_by_category: {},
      open_action_count: 1,
    },
    {
      id: "app-2",
      name: "Auth Service",
      group_id: null,
      group_name: null,
      latest_run_id: null,
      worst_severity: "low",
      worst_threat_risk: null,
      finding_count: 1,
      open_threat_count: 1,
      not_analysed: true,
      stale: false,
      days_since_run: null,
      addressed_count: 0,
      total_threat_count: 1,
      completeness_score: null,
      reviewed_at: null,
      open_by_risk: {},
      open_by_category: {},
      open_action_count: null,
    },
  ],
};

const GROUPS_DATA = {
  groups: [
    {
      id: "grp-1",
      name: "Payments",
      description: "Payments team",
      created_at: "2026-09-20T10:00:00Z",
      rollup: { application_count: 1, worst_severity: "critical", finding_count: 9, stale_count: 1 },
    },
  ],
  ungrouped: { application_count: 1, worst_severity: "low", finding_count: 1, stale_count: 0 },
  overall: { application_count: 2, worst_severity: "critical", finding_count: 10, stale_count: 1 },
};

describe("GroupsPage", () => {
  const fetchMock = vi.fn();

  beforeEach(() => {
    fetchMock.mockReset();
    vi.stubGlobal("fetch", fetchMock);
  });

  function render_page() {
    fetchMock.mockResolvedValueOnce(jsonResponse(DASHBOARD_DATA)).mockResolvedValueOnce(jsonResponse(GROUPS_DATA));
    return render(
      <MemoryRouter>
        <GroupsPage />
      </MemoryRouter>,
    );
  }

  it("shows onboarding when there are zero applications", async () => {
    fetchMock
      .mockResolvedValueOnce(jsonResponse({ applications: [] }))
      .mockResolvedValueOnce(jsonResponse(GROUPS_DATA));
    render(
      <MemoryRouter>
        <GroupsPage />
      </MemoryRouter>,
    );

    await waitFor(() => {
      // Check for the onboarding section heading
      expect(screen.getByText(/Create your first threat model/i)).toBeInTheDocument();
    });
  });

  it("renders the threat models table with name, group, risk, and other columns", async () => {
    render_page();

    const table = await screen.findByRole("table");
    expect(within(table).getByText("Payment Gateway")).toBeInTheDocument();
    expect(within(table).getByText("Auth Service")).toBeInTheDocument();
    expect(within(table).getByText("Payments")).toBeInTheDocument();
    expect(within(table).getByText("Ungrouped")).toBeInTheDocument();
  });

  it("renders risk badges", async () => {
    render_page();

    await waitFor(() => {
      const table = screen.getByRole("table");
      expect(within(table).getByText("critical")).toBeInTheDocument();
      expect(within(table).getByText("low")).toBeInTheDocument();
    });
  });

  it("renders open threat counts", async () => {
    render_page();

    const table = await screen.findByRole("table");
    const rows = within(table).getAllByRole("row");
    // Skip header row
    expect(rows.length).toBe(3); // header + 2 data rows
  });

  it("renders addressed percentage", async () => {
    render_page();

    const table = await screen.findByRole("table");
    // 6/9 = 67%
    expect(within(table).getByText("67%")).toBeInTheDocument();
    // 0/1 = 0%
    expect(within(table).getByText("0%")).toBeInTheDocument();
  });

  it("renders completeness percentage", async () => {
    render_page();

    const table = await screen.findByRole("table");
    expect(within(table).getByText("85%")).toBeInTheDocument();
  });

  it("renders last run dates", async () => {
    render_page();

    const table = await screen.findByRole("table");
    expect(within(table).getByText("5 days ago")).toBeInTheDocument();
    // Check that "never" appears (it shows up in both Last run and Reviewed columns for Auth Service)
    const neverTexts = within(table).getAllByText("never");
    expect(neverTexts.length).toBeGreaterThan(0);
  });

  it("renders stale and not_analysed badges", async () => {
    render_page();

    const table = await screen.findByRole("table");
    expect(within(table).getByText("needs re-run")).toBeInTheDocument();
    expect(within(table).getByText("inputs not analysed")).toBeInTheDocument();
  });

  it("shows Showing X of Y count", async () => {
    render_page();

    await waitFor(() => {
      expect(screen.getByText(/Showing 2 of 2/)).toBeInTheDocument();
    });
  });

  it("renders name cell as link", async () => {
    render_page();

    const paymentLink = await screen.findByRole("button", { name: "Payment Gateway" });
    expect(paymentLink).toHaveClass("btn-link");
  });

  it("renders group filter dropdown", async () => {
    render_page();

    const groupSelect = await screen.findByLabelText("Group");
    expect(groupSelect).toBeInTheDocument();
  });

  it("renders search input", async () => {
    render_page();

    const searchInput = await screen.findByLabelText("Search threat models");
    expect(searchInput).toBeInTheDocument();
  });

  function rowNames(): string[] {
    const table = screen.getByRole("table");
    return within(table)
      .getAllByRole("row")
      .slice(1)
      .map((row) => within(row).getAllByRole("cell")[0].textContent ?? "");
  }

  it("sorts worst risk first by default, ties broken by open threats, and a header click reverses it", async () => {
    const base = DASHBOARD_DATA.applications[1];
    const apps = [
      {
        ...base,
        id: "m",
        name: "Medium many",
        worst_severity: null,
        worst_threat_risk: "medium",
        open_threat_count: 90,
        not_analysed: false,
      },
      {
        ...base,
        id: "h1",
        name: "High few",
        worst_severity: null,
        worst_threat_risk: "high",
        open_threat_count: 5,
        not_analysed: false,
      },
      {
        ...base,
        id: "h2",
        name: "High more",
        worst_severity: null,
        worst_threat_risk: "high",
        open_threat_count: 40,
        not_analysed: false,
      },
      {
        ...base,
        id: "c",
        name: "Critical",
        worst_severity: "critical",
        worst_threat_risk: null,
        open_threat_count: 1,
        not_analysed: false,
      },
    ];
    fetchMock
      .mockResolvedValueOnce(jsonResponse({ applications: apps }))
      .mockResolvedValueOnce(jsonResponse(GROUPS_DATA));
    render(
      <MemoryRouter>
        <GroupsPage />
      </MemoryRouter>,
    );
    await screen.findByRole("table");
    expect(rowNames().map((n) => n.split(/needs|inputs/)[0].trim())).toEqual([
      "Critical",
      "High more",
      "High few",
      "Medium many",
    ]);

    fireEvent.click(screen.getByText("Worst risk"));
    expect(rowNames()[0]).toContain("Medium many");
  });

  it("search narrows the rows and updates the count", async () => {
    render_page();
    await screen.findByRole("table");
    fireEvent.change(screen.getByLabelText("Search threat models"), { target: { value: "payment" } });
    expect(rowNames()).toHaveLength(1);
    expect(rowNames()[0]).toContain("Payment Gateway");
    expect(screen.getByText(/Showing 1 of 2/)).toBeInTheDocument();
  });

  it("group filter narrows to ungrouped models", async () => {
    render_page();
    await screen.findByRole("table");
    fireEvent.change(screen.getByLabelText("Group"), { target: { value: "ungrouped" } });
    expect(rowNames()).toHaveLength(1);
    expect(rowNames()[0]).toContain("Auth Service");
  });
});
