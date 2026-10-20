import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

// A throwaway plugin frontend standing in for `@kresheen/pro`.
vi.mock("@kresheen/pro", () => ({
  default: {
    groupActions: [
      { id: "demo", render: ({ group }: { group: { id: string; name: string } }) => <button type="button">Demo {group.name}</button> },
    ],
  },
}));

import { GroupsPage } from "./Groups";

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" } });
}

const rollup = { application_count: 0, worst_severity: null, finding_count: 0, stale_count: 0 };

function renderPage(myRole: string | null | undefined) {
  const group = { id: "grp-1", name: "Payments", description: "", created_at: "2026-09-20T10:00:00Z", rollup, my_role: myRole };
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL) =>
      String(input).endsWith("/api/groups")
        ? jsonResponse({ groups: [group], ungrouped: rollup, overall: rollup })
        : jsonResponse({ applications: [] }),
    ),
  );
  render(
    <MemoryRouter>
      <GroupsPage />
    </MemoryRouter>,
  );
}

describe("GroupsPage group actions slot", () => {
  beforeEach(() => vi.unstubAllGlobals());

  it("shows a plugin's action on a group the user administers", async () => {
    renderPage("admin");
    fireEvent.click(await screen.findByRole("button", { name: "Manage groups" }));
    expect(await screen.findByRole("button", { name: "Demo Payments" })).toBeInTheDocument();
  });

  it("hides it from someone who does not administer the group", async () => {
    renderPage("editor");
    fireEvent.click(await screen.findByRole("button", { name: "Manage groups" }));
    await screen.findByText("Payments");
    expect(screen.queryByRole("button", { name: "Demo Payments" })).not.toBeInTheDocument();
  });
});
