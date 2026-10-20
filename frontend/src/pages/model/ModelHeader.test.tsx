import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ModelHeader } from "./ModelHeader";

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" } });
}

describe("ModelHeader", () => {
  const fetchMock = vi.fn();

  beforeEach(() => {
    fetchMock.mockReset();
    vi.stubGlobal("fetch", fetchMock);
  });

  it("shows the application's name as the title and links back to the group", async () => {
    fetchMock
      .mockResolvedValueOnce(jsonResponse({ name: "Sample Shop", group_id: "GRP-1" }))
      .mockResolvedValueOnce(jsonResponse({ groups: [{ id: "GRP-1", name: "Payments" }] }));

    render(
      <MemoryRouter>
        <ModelHeader applicationId="APP-1" />
      </MemoryRouter>,
    );

    expect(await screen.findByRole("heading", { name: "Sample Shop" })).toBeInTheDocument();
    const groupLink = await screen.findByRole("link", { name: "Payments" });
    expect(groupLink).toHaveAttribute("href", "/applications?group=GRP-1");
    expect(screen.getByRole("link", { name: "Threat models" })).toHaveAttribute("href", "/applications");
  });

  it("falls back to Ungrouped when the application has no group", async () => {
    fetchMock
      .mockResolvedValueOnce(jsonResponse({ name: "Solo App", group_id: null }))
      .mockResolvedValueOnce(jsonResponse({ groups: [] }));

    render(
      <MemoryRouter>
        <ModelHeader applicationId="APP-2" />
      </MemoryRouter>,
    );

    const groupLink = await screen.findByRole("link", { name: "Ungrouped" });
    expect(groupLink).toHaveAttribute("href", "/applications?group=ungrouped");
  });

  it("renders the actions slot", async () => {
    fetchMock
      .mockResolvedValueOnce(jsonResponse({ name: "Sample Shop", group_id: null }))
      .mockResolvedValueOnce(jsonResponse({ groups: [] }));

    render(
      <MemoryRouter>
        <ModelHeader applicationId="APP-1" actions={<button>Re-run</button>} />
      </MemoryRouter>,
    );

    expect(await screen.findByRole("button", { name: "Re-run" })).toBeInTheDocument();
  });
});
