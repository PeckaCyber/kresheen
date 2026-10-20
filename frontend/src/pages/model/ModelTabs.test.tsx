import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { isModelTabKey, ModelTabs } from "./ModelTabs";

describe("isModelTabKey", () => {
  it("accepts every known slug", () => {
    for (const slug of ["overview", "diagram", "threats", "actions", "findings", "settings"]) {
      expect(isModelTabKey(slug)).toBe(true);
    }
  });

  it("rejects an unknown slug or undefined", () => {
    expect(isModelTabKey("not-a-tab")).toBe(false);
    expect(isModelTabKey(undefined)).toBe(false);
  });
});

describe("ModelTabs", () => {
  it("shows the counts in the Threats, Action plan and Findings labels", () => {
    render(
      <ModelTabs active="overview" onSelect={() => {}} counts={{ threats: 12, actions: 4, findings: 2 }} />,
    );
    expect(screen.getByText("Threats (12)")).toBeInTheDocument();
    expect(screen.getByText("Action plan (4)")).toBeInTheDocument();
    expect(screen.getByText("Findings (2)")).toBeInTheDocument();
  });

  it("calls onSelect with the clicked tab's key", () => {
    const onSelect = vi.fn();
    render(<ModelTabs active="overview" onSelect={onSelect} counts={{ threats: 0, actions: 0, findings: 0 }} />);
    fireEvent.click(screen.getByTestId("model-tab-diagram"));
    expect(onSelect).toHaveBeenCalledWith("diagram");
  });
});
