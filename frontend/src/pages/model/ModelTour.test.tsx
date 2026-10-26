import { render, screen, fireEvent } from "@testing-library/react";
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { ModelTour } from "./ModelTour";

describe("ModelTour", () => {
  beforeEach(() => {
    localStorage.clear();
  });

  afterEach(() => {
    localStorage.clear();
  });

  it("shows when kresheen-tour-done is not set", () => {
    const mockOnGoToTab = vi.fn();
    render(<ModelTour onGoToTab={mockOnGoToTab} />);
    expect(screen.getByRole("dialog", { name: "Quick tour" })).toBeInTheDocument();
  });

  it("hides when kresheen-tour-done is set to 1", () => {
    localStorage.setItem("kresheen-tour-done", "1");
    const mockOnGoToTab = vi.fn();
    const { container } = render(<ModelTour onGoToTab={mockOnGoToTab} />);
    expect(container.querySelector('[role="dialog"]')).not.toBeInTheDocument();
  });

  it("displays the first step on initial render", () => {
    const mockOnGoToTab = vi.fn();
    render(<ModelTour onGoToTab={mockOnGoToTab} />);
    expect(screen.getByText("Overview")).toBeInTheDocument();
    expect(
      screen.getByText(
        "Start here. It shows the few things worth doing next: questions that sharpen your threats, and the fixes that matter most.",
      ),
    ).toBeInTheDocument();
    expect(screen.getByText("1 of 4")).toBeInTheDocument();
  });

  it("moves to next step when Next button is clicked", () => {
    const mockOnGoToTab = vi.fn();
    render(<ModelTour onGoToTab={mockOnGoToTab} />);
    const nextButton = screen.getByRole("button", { name: "Next" });
    fireEvent.click(nextButton);
    expect(screen.getByText("Diagram")).toBeInTheDocument();
    expect(
      screen.getByText(
        "Your system as boxes and arrows. Click any box to see its threats and state what you know about it.",
      ),
    ).toBeInTheDocument();
    expect(screen.getByText("2 of 4")).toBeInTheDocument();
  });

  it("moves to previous step when Back button is clicked", () => {
    const mockOnGoToTab = vi.fn();
    render(<ModelTour onGoToTab={mockOnGoToTab} />);
    const nextButton = screen.getByRole("button", { name: "Next" });
    fireEvent.click(nextButton);
    const backButton = screen.getByRole("button", { name: "Back" });
    fireEvent.click(backButton);
    expect(screen.getByText("Overview")).toBeInTheDocument();
    expect(screen.getByText("1 of 4")).toBeInTheDocument();
  });

  it("disables Back button on first step", () => {
    const mockOnGoToTab = vi.fn();
    render(<ModelTour onGoToTab={mockOnGoToTab} />);
    const backButton = screen.getByRole("button", { name: "Back" });
    expect(backButton).toBeDisabled();
  });

  it("shows Go to tab button on each step", () => {
    const mockOnGoToTab = vi.fn();
    render(<ModelTour onGoToTab={mockOnGoToTab} />);
    expect(screen.getByRole("button", { name: "Go to Overview" })).toBeInTheDocument();
  });

  it("calls onGoToTab with correct tab key when Go to tab button is clicked", () => {
    const mockOnGoToTab = vi.fn();
    render(<ModelTour onGoToTab={mockOnGoToTab} />);
    const goToButton = screen.getByRole("button", { name: "Go to Overview" });
    fireEvent.click(goToButton);
    expect(mockOnGoToTab).toHaveBeenCalledWith("overview");
  });

  it("calls onGoToTab with threats tab key on threats step", () => {
    const mockOnGoToTab = vi.fn();
    render(<ModelTour onGoToTab={mockOnGoToTab} />);
    const nextButton = screen.getByRole("button", { name: "Next" });
    fireEvent.click(nextButton);
    fireEvent.click(nextButton);
    const goToButton = screen.getByRole("button", { name: "Go to Threats" });
    fireEvent.click(goToButton);
    expect(mockOnGoToTab).toHaveBeenCalledWith("threats");
  });

  it("calls onGoToTab with actions tab key on action plan step", () => {
    const mockOnGoToTab = vi.fn();
    render(<ModelTour onGoToTab={mockOnGoToTab} />);
    const nextButton = screen.getByRole("button", { name: "Next" });
    fireEvent.click(nextButton);
    fireEvent.click(nextButton);
    fireEvent.click(nextButton);
    const goToButton = screen.getByRole("button", { name: "Go to Action plan" });
    fireEvent.click(goToButton);
    expect(mockOnGoToTab).toHaveBeenCalledWith("actions");
  });

  it("shows Done button on last step instead of Next", () => {
    const mockOnGoToTab = vi.fn();
    render(<ModelTour onGoToTab={mockOnGoToTab} />);
    const nextButton = screen.getByRole("button", { name: "Next" });
    fireEvent.click(nextButton);
    fireEvent.click(nextButton);
    fireEvent.click(nextButton);
    expect(screen.queryByRole("button", { name: "Next" })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Done" })).toBeInTheDocument();
  });

  it("sets kresheen-tour-done to 1 and hides when Done is clicked", () => {
    const mockOnGoToTab = vi.fn();
    const { container } = render(<ModelTour onGoToTab={mockOnGoToTab} />);
    const nextButton = screen.getByRole("button", { name: "Next" });
    fireEvent.click(nextButton);
    fireEvent.click(nextButton);
    fireEvent.click(nextButton);
    const doneButton = screen.getByRole("button", { name: "Done" });
    fireEvent.click(doneButton);
    expect(localStorage.getItem("kresheen-tour-done")).toBe("1");
    expect(container.querySelector('[role="dialog"]')).not.toBeInTheDocument();
  });

  it("sets kresheen-tour-done to 1 and hides when Skip tour is clicked", () => {
    const mockOnGoToTab = vi.fn();
    const { container } = render(<ModelTour onGoToTab={mockOnGoToTab} />);
    const skipButton = screen.getByRole("button", { name: "Skip tour" });
    fireEvent.click(skipButton);
    expect(localStorage.getItem("kresheen-tour-done")).toBe("1");
    expect(container.querySelector('[role="dialog"]')).not.toBeInTheDocument();
  });
});
