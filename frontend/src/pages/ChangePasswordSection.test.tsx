import { fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ChangePasswordSection } from "./ChangePasswordSection";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

async function openAndFill(current: string, next: string, confirm: string) {
  fireEvent.click(screen.getByRole("button", { name: /Account/ }));
  fireEvent.change(await screen.findByLabelText("Current password"), { target: { value: current } });
  fireEvent.change(screen.getByLabelText("New password"), { target: { value: next } });
  fireEvent.change(screen.getByLabelText("Confirm new password"), { target: { value: confirm } });
}

describe("ChangePasswordSection", () => {
  const fetchMock = vi.fn();

  beforeEach(() => {
    fetchMock.mockReset();
    vi.stubGlobal("fetch", fetchMock);
  });

  it("submits current/new password and shows success", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ ok: true }));
    render(<ChangePasswordSection />);
    await openAndFill("old-password-1", "a-new-strong-password-1", "a-new-strong-password-1");

    fireEvent.click(screen.getByRole("button", { name: "Change password" }));

    const [path, init] = fetchMock.mock.calls[0];
    expect(path).toBe("/api/auth/change-password");
    expect(JSON.parse((init as RequestInit).body as string)).toEqual({
      current_password: "old-password-1",
      new_password: "a-new-strong-password-1",
    });
  });

  it("shows a client-side mismatch warning without calling the API", async () => {
    render(<ChangePasswordSection />);
    await openAndFill("old-password-1", "a-new-strong-password-1", "does-not-match-1");

    expect(screen.getByText("Passwords do not match.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Change password" })).toBeDisabled();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("shows an error for the wrong current password", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ detail: "Current password is incorrect" }, 401));
    render(<ChangePasswordSection />);
    await openAndFill("wrong-password-1", "a-new-strong-password-1", "a-new-strong-password-1");

    fireEvent.click(screen.getByRole("button", { name: "Change password" }));

    expect(await screen.findByText("Current password is incorrect")).toBeInTheDocument();
  });

  it("tells an SSO-only user there is nothing to change", async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse({ detail: "This account signs in via single sign-on; there is no password to change" }, 403),
    );
    render(<ChangePasswordSection />);
    await openAndFill("whatever-1", "a-new-strong-password-1", "a-new-strong-password-1");

    fireEvent.click(screen.getByRole("button", { name: "Change password" }));

    expect(await screen.findByText(/single sign-on/)).toBeInTheDocument();
  });
});
