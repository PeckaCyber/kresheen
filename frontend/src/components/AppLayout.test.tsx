import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { AuthProvider } from "../auth/AuthContext";
import { AppLayout } from "./AppLayout";

const STORAGE_KEY = "kresheen-sidebar";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

function renderLayout() {
  return render(
    <MemoryRouter initialEntries={["/dashboard"]}>
      <AuthProvider>
        <AppLayout>
          <div>content</div>
        </AppLayout>
      </AuthProvider>
    </MemoryRouter>,
  );
}

describe("AppLayout sidebar", () => {
  beforeEach(() => {
    window.localStorage.clear();
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => jsonResponse({ csrf_token: "tok", expires_at: "2026-01-01T00:00:00Z", role: "owner" })),
    );
  });

  it("lists Home, Threat models, Threat library, Settings and Help, and drops Constructs and Audit log", async () => {
    renderLayout();

    expect(await screen.findByRole("link", { name: "Home" })).toHaveAttribute("href", "/dashboard");
    expect(screen.getByRole("link", { name: "Threat models" })).toHaveAttribute("href", "/applications");
    expect(screen.getByRole("link", { name: "Threat library" })).toHaveAttribute("href", "/threat-kb");
    expect(screen.getByRole("link", { name: "Settings" })).toHaveAttribute("href", "/settings");
    expect(screen.getByRole("link", { name: "Help" })).toHaveAttribute("href", "/help");

    expect(screen.queryByRole("link", { name: "Constructs" })).not.toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Audit log" })).not.toBeInTheDocument();
  });

  it("brand links to /dashboard", async () => {
    renderLayout();
    expect(await screen.findByRole("link", { name: "Kresheen, home" })).toHaveAttribute("href", "/dashboard");
  });

  it("starts expanded on a wide viewport with no stored preference, and remembers a collapse", async () => {
    window.innerWidth = 1280;
    renderLayout();
    await screen.findByRole("link", { name: "Home" });

    expect(screen.getByText("Threat models")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Collapse sidebar" }));

    expect(window.localStorage.getItem(STORAGE_KEY)).toBe("collapsed");
    expect(screen.queryByText("Threat models")).not.toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Threat models" })).toBeInTheDocument();
  });

  it("starts collapsed below 992px when nothing is stored yet", async () => {
    window.innerWidth = 700;
    renderLayout();
    await screen.findByRole("link", { name: "Home" });

    expect(screen.queryByText("Threat models")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Expand sidebar" })).toBeInTheDocument();
  });

  it("honours a stored preference over the viewport width", async () => {
    window.innerWidth = 1280;
    window.localStorage.setItem(STORAGE_KEY, "collapsed");
    renderLayout();
    await screen.findByRole("link", { name: "Home" });

    expect(screen.getByRole("button", { name: "Expand sidebar" })).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Expand sidebar" }));
    expect(window.localStorage.getItem(STORAGE_KEY)).toBe("expanded");
    expect(screen.getByText("Threat models")).toBeInTheDocument();
  });
});
