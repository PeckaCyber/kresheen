import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { GroupBackLink } from "./GroupBackLink";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

describe("GroupBackLink", () => {
  const fetchMock = vi.fn();

  beforeEach(() => {
    fetchMock.mockReset();
    vi.stubGlobal("fetch", fetchMock);
  });

  function open() {
    render(
      <MemoryRouter>
        <GroupBackLink applicationId="APP-1" />
      </MemoryRouter>,
    );
  }

  it("links to the application's group by name", async () => {
    fetchMock
      .mockResolvedValueOnce(jsonResponse({ group_id: "GRP-1" }))
      .mockResolvedValueOnce(jsonResponse({ groups: [{ id: "GRP-1", name: "Payments" }] }));
    open();

    const link = await screen.findByRole("link", { name: /Payments/ });
    expect(link).toHaveAttribute("href", "/applications/groups/GRP-1");
  });

  it("links to the Ungrouped bucket when the application has no group", async () => {
    fetchMock
      .mockResolvedValueOnce(jsonResponse({ group_id: null }))
      .mockResolvedValueOnce(jsonResponse({ groups: [] }));
    open();

    const link = await screen.findByRole("link", { name: /Ungrouped/ });
    expect(link).toHaveAttribute("href", "/applications/groups/ungrouped");
  });

  it("renders nothing while loading or if the fetch fails", () => {
    fetchMock.mockRejectedValueOnce(new Error("network error"));
    open();

    expect(screen.queryByRole("link")).not.toBeInTheDocument();
  });
});
