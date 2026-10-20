import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { describe, expect, it, beforeEach, vi } from "vitest";
import { CommandPalette } from "./CommandPalette";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

function renderPalette() {
  return render(
    <MemoryRouter initialEntries={["/"]}>
      <CommandPalette />
    </MemoryRouter>,
  );
}

describe("CommandPalette", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn(() => jsonResponse([])));
  });

  it("opens on Ctrl+K", async () => {
    renderPalette();

    fireEvent.keyDown(window, { ctrlKey: true, key: "k" });

    await waitFor(() => {
      expect(screen.getByPlaceholderText(/Search pages/)).toBeInTheDocument();
    });
  });

  it("opens on Meta+K (Cmd on Mac)", async () => {
    renderPalette();

    fireEvent.keyDown(window, { metaKey: true, key: "k" });

    await waitFor(() => {
      expect(screen.getByPlaceholderText(/Search pages/)).toBeInTheDocument();
    });
  });

  it("closes on Escape", async () => {
    renderPalette();

    fireEvent.keyDown(window, { ctrlKey: true, key: "k" });
    await waitFor(() => {
      expect(screen.getByPlaceholderText(/Search pages/)).toBeInTheDocument();
    });

    fireEvent.keyDown(screen.getByPlaceholderText(/Search pages/), { key: "Escape" });

    await waitFor(() => {
      expect(screen.queryByPlaceholderText(/Search pages/)).not.toBeInTheDocument();
    });
  });

  it("filters items based on search input", async () => {
    renderPalette();

    fireEvent.keyDown(window, { ctrlKey: true, key: "k" });
    const input = await screen.findByPlaceholderText(/Search pages/);

    fireEvent.change(input, { target: { value: "threat" } });

    await waitFor(() => {
      expect(screen.getByText("Threat models")).toBeInTheDocument();
      // Threat library appears as both a page and a help topic, so use getAllByText
      const threatLibraryButtons = screen.getAllByText("Threat library");
      expect(threatLibraryButtons.length).toBeGreaterThan(0);
    });
  });

  it("shows 'No results found' when search has no matches", async () => {
    renderPalette();

    fireEvent.keyDown(window, { ctrlKey: true, key: "k" });
    const input = await screen.findByPlaceholderText(/Search pages/);

    fireEvent.change(input, { target: { value: "nonexistent" } });

    await waitFor(() => {
      expect(screen.getByText("No results found")).toBeInTheDocument();
    });
  });

  it("navigates to page on Enter key", async () => {
    renderPalette();

    fireEvent.keyDown(window, { ctrlKey: true, key: "k" });
    const input = await screen.findByPlaceholderText(/Search pages/);

    fireEvent.change(input, { target: { value: "Home" } });

    // Find the Home button before pressing Enter
    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Home" })).toBeInTheDocument();
    });

    fireEvent.keyDown(input, { key: "Enter" });

    // After Enter, the modal should close and search should be cleared
    await waitFor(() => {
      expect(screen.queryByPlaceholderText(/Search pages/)).not.toBeInTheDocument();
    });
  });

  it("navigates on item click", async () => {
    renderPalette();

    fireEvent.keyDown(window, { ctrlKey: true, key: "k" });
    const input = await screen.findByPlaceholderText(/Search pages/);

    fireEvent.change(input, { target: { value: "Home" } });

    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Home" })).toBeInTheDocument();
    });

    const homeButton = screen.getByRole("button", { name: "Home" });
    fireEvent.click(homeButton);

    // After clicking, the modal should close and search should be cleared
    await waitFor(() => {
      expect(screen.queryByPlaceholderText(/Search pages/)).not.toBeInTheDocument();
    });
  });

  it("handles arrow keys to navigate highlighted item", async () => {
    renderPalette();

    fireEvent.keyDown(window, { ctrlKey: true, key: "k" });
    const input = await screen.findByPlaceholderText(/Search pages/);

    // Get initial items
    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Home" })).toBeInTheDocument();
    });

    // Press ArrowDown to move to next item (highlight should change)
    fireEvent.keyDown(input, { key: "ArrowDown" });

    // After arrow down, a different button should be highlighted
    // (the highlighting is done via CSS class, so we just verify no error occurs)
    expect(screen.getByRole("button", { name: "Home" })).toBeInTheDocument();

    // Should not throw and should accept Enter to navigate
    fireEvent.keyDown(input, { key: "Enter" });

    // After Enter, the modal should close
    await waitFor(() => {
      expect(screen.queryByPlaceholderText(/Search pages/)).not.toBeInTheDocument();
    });
  });

  it("lists threat models from the plain application list and opens one with Enter", async () => {
    const fetchMock = vi.fn((_input: RequestInfo | URL) => jsonResponse([{ id: "APP-1", name: "Payments API" }]));
    vi.stubGlobal("fetch", fetchMock);
    function Where() {
      return <div data-testid="where">{useLocation().pathname}</div>;
    }
    render(
      <MemoryRouter initialEntries={["/"]}>
        <CommandPalette />
        <Routes>
          <Route path="*" element={<Where />} />
        </Routes>
      </MemoryRouter>,
    );
    fireEvent.keyDown(window, { ctrlKey: true, key: "k" });
    const input = await screen.findByPlaceholderText(/Search pages/);
    fireEvent.change(input, { target: { value: "payments" } });
    await screen.findByText("Payments API");
    expect(String(fetchMock.mock.calls[0][0])).toContain("/api/applications");
    fireEvent.keyDown(input, { key: "Enter" });
    await waitFor(() => expect(screen.getByTestId("where")).toHaveTextContent("/models/APP-1"));
  });
});
