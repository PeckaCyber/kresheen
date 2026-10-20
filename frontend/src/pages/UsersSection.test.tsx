import { fireEvent, render, screen, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { UsersSection } from "./UsersSection";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

const owner = {
  id: "USER-owner",
  email: "owner@example.com",
  role: "owner",
  auth_source: "password",
  is_active: true,
  created_at: "2026-09-24T00:00:00Z",
};

const member = {
  id: "USER-member",
  email: "member@example.com",
  role: "member",
  auth_source: "sso",
  is_active: true,
  created_at: "2026-09-24T00:00:00Z",
};

describe("UsersSection", () => {
  const fetchMock = vi.fn();

  beforeEach(() => {
    fetchMock.mockReset();
    vi.stubGlobal("fetch", fetchMock);
    Object.assign(navigator, { clipboard: { writeText: vi.fn().mockResolvedValue(undefined) } });
  });

  it("lists users with role, source and status, never a password", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse([owner, member]));
    render(<UsersSection />);
    fireEvent.click(screen.getByRole("button", { name: /Users/ }));

    expect(await screen.findByText("owner@example.com")).toBeInTheDocument();
    expect(screen.getByText("member@example.com")).toBeInTheDocument();
    expect(screen.getByText("sso")).toBeInTheDocument();
    expect(screen.getAllByText("active").length).toBe(2);
    expect(screen.queryByText(/password_hash/)).not.toBeInTheDocument();
  });

  it("shows the one-time password once after adding a user", async () => {
    fetchMock
      .mockResolvedValueOnce(jsonResponse([owner]))
      .mockResolvedValueOnce(jsonResponse({ ...member, one_time_password: "the-generated-secret-1" }))
      .mockResolvedValueOnce(jsonResponse([owner, member]));
    render(<UsersSection />);
    fireEvent.click(screen.getByRole("button", { name: /Users/ }));

    fireEvent.change(await screen.findByLabelText("New user email"), {
      target: { value: "member@example.com" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Add user" }));

    expect(await screen.findByTestId("new-user-password")).toHaveTextContent("the-generated-secret-1");
    expect(screen.getByText(/will not be shown again/)).toBeInTheDocument();
    expect(JSON.parse((fetchMock.mock.calls[1][1] as RequestInit).body as string)).toEqual({
      email: "member@example.com",
      role: "member",
    });
  });

  it("deactivates a user", async () => {
    fetchMock
      .mockResolvedValueOnce(jsonResponse([owner, member]))
      .mockResolvedValueOnce(jsonResponse({ ...member, is_active: false }))
      .mockResolvedValueOnce(jsonResponse([owner, { ...member, is_active: false }]));
    render(<UsersSection />);
    fireEvent.click(screen.getByRole("button", { name: /Users/ }));

    await screen.findByText("member@example.com");
    const memberRow = screen.getByText("member@example.com").closest("tr");
    if (!memberRow) throw new Error("member row not found");
    fireEvent.click(within(memberRow).getByRole("button", { name: "Deactivate" }));

    expect(await screen.findByText("disabled")).toBeInTheDocument();
    expect(fetchMock.mock.calls[1][0]).toBe(`/api/users/${member.id}`);
    expect(JSON.parse((fetchMock.mock.calls[1][1] as RequestInit).body as string)).toEqual({ is_active: false });
  });

  it("changes a user's role", async () => {
    fetchMock
      .mockResolvedValueOnce(jsonResponse([owner, member]))
      .mockResolvedValueOnce(jsonResponse({ ...member, role: "owner" }))
      .mockResolvedValueOnce(jsonResponse([owner, { ...member, role: "owner" }]));
    render(<UsersSection />);
    fireEvent.click(screen.getByRole("button", { name: /Users/ }));

    await screen.findByText("member@example.com");
    fireEvent.change(screen.getByLabelText(`Role for ${member.email}`), { target: { value: "owner" } });

    expect(JSON.parse((fetchMock.mock.calls[1][1] as RequestInit).body as string)).toEqual({ role: "owner" });
    await screen.findByLabelText(`Role for ${member.email}`);
  });
});
