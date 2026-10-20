import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { StatStrip } from "./StatStrip";

describe("StatStrip", () => {
  it("renders every tile's label and value, and calls onClick for the one clicked", () => {
    const onClickThreats = vi.fn();
    const onClickFindings = vi.fn();
    render(
      <StatStrip
        items={[
          { key: "open-threats", label: "Open threats", value: "3", tone: "accent2", onClick: onClickThreats },
          { key: "findings", label: "Findings", value: "0", tone: "good", onClick: onClickFindings },
        ]}
      />,
    );

    expect(screen.getByText("Open threats")).toBeInTheDocument();
    expect(screen.getByText("3")).toBeInTheDocument();
    expect(screen.getByText("Findings")).toBeInTheDocument();

    fireEvent.click(screen.getByTestId("model-stat-findings"));
    expect(onClickFindings).toHaveBeenCalledTimes(1);
    expect(onClickThreats).not.toHaveBeenCalled();
  });

  it("renders compact chips mode with single-line layout and clickable items", () => {
    const onClickThreats = vi.fn();
    const onClickFindings = vi.fn();
    render(
      <StatStrip
        compact
        items={[
          { key: "open-threats", label: "Open threats", value: "46", tone: "accent2", onClick: onClickThreats },
          { key: "high-critical", label: "High+critical", value: "12", tone: "bad", onClick: onClickFindings },
        ]}
      />,
    );

    expect(screen.getByText("Open threats")).toBeInTheDocument();
    expect(screen.getByText("46")).toBeInTheDocument();
    expect(screen.getByText("High+critical")).toBeInTheDocument();
    expect(screen.getByText("12")).toBeInTheDocument();

    fireEvent.click(screen.getByTestId("model-stat-open-threats"));
    expect(onClickThreats).toHaveBeenCalledTimes(1);
    expect(onClickFindings).not.toHaveBeenCalled();
  });
});
