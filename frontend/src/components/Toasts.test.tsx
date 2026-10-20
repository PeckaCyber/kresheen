import { render, screen } from "@testing-library/react";
import { describe, expect, it, beforeEach, vi } from "vitest";
import { act } from "react";
import { ToastProvider, useToast } from "./Toasts";

function TestComponent() {
  const { success, error } = useToast();
  return (
    <div>
      <button onClick={() => success("Success message")}>Show Success</button>
      <button onClick={() => error("Error message")}>Show Error</button>
    </div>
  );
}

describe("Toasts", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  it("renders ToastProvider and useToast hook works", () => {
    render(
      <ToastProvider>
        <TestComponent />
      </ToastProvider>,
    );
    expect(screen.getByRole("button", { name: "Show Success" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Show Error" })).toBeInTheDocument();
  });

  it("shows success toast and auto-hides after 4 seconds", async () => {
    render(
      <ToastProvider>
        <TestComponent />
      </ToastProvider>,
    );

    act(() => {
      screen.getByRole("button", { name: "Show Success" }).click();
    });

    expect(screen.getByText("Success message")).toBeInTheDocument();

    // Should still be visible after 3 seconds
    act(() => {
      vi.advanceTimersByTime(3000);
    });
    expect(screen.getByText("Success message")).toBeInTheDocument();

    // Should be gone after 4 seconds
    act(() => {
      vi.advanceTimersByTime(1000);
    });
    expect(screen.queryByText("Success message")).not.toBeInTheDocument();
  });

  it("shows error toast and auto-hides after 8 seconds", async () => {
    render(
      <ToastProvider>
        <TestComponent />
      </ToastProvider>,
    );

    act(() => {
      screen.getByRole("button", { name: "Show Error" }).click();
    });

    expect(screen.getByText("Error message")).toBeInTheDocument();

    // Should still be visible after 7 seconds
    act(() => {
      vi.advanceTimersByTime(7000);
    });
    expect(screen.getByText("Error message")).toBeInTheDocument();

    // Should be gone after 8 seconds
    act(() => {
      vi.advanceTimersByTime(1000);
    });
    expect(screen.queryByText("Error message")).not.toBeInTheDocument();
  });

  it("useToast returns no-op functions when used without provider", () => {
    const { success, error } = renderHook(() => useToast());
    expect(() => {
      success("Test message");
      error("Error message");
    }).not.toThrow();
  });
});

function renderHook<T>(hook: () => T): T {
  let result: T;
  const TestComponent = () => {
    result = hook();
    return null;
  };
  render(<TestComponent />);
  return result!;
}
