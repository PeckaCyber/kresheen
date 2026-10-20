import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { InfoTip } from "./InfoTip";

describe("InfoTip", () => {
  it("renders child without wrapper when text is undefined", () => {
    render(
      <InfoTip text={undefined}>
        <button type="button">Click me</button>
      </InfoTip>,
    );
    const button = screen.getByRole("button", { name: "Click me" });
    expect(button.tagName).toBe("BUTTON");
  });

  it("renders tooltip text on hover", () => {
    render(
      <InfoTip text="This is a helpful tooltip">
        <span>Hover me</span>
      </InfoTip>,
    );

    const wrapper = screen.getByRole("button");
    fireEvent.mouseEnter(wrapper);

    // The tooltip should be visible after hovering
    expect(screen.getByText("This is a helpful tooltip")).toBeInTheDocument();
  });

  it("renders tooltip text on focus", () => {
    render(
      <InfoTip text="This is a helpful tooltip">
        <span>Focus me</span>
      </InfoTip>,
    );

    const wrapper = screen.getByRole("button");
    fireEvent.focus(wrapper);

    // The tooltip should be visible after focus
    expect(screen.getByText("This is a helpful tooltip")).toBeInTheDocument();
  });

  it("makes the wrapper focusable with tabIndex", () => {
    render(
      <InfoTip text="Tooltip text">
        <span>Content</span>
      </InfoTip>,
    );

    const wrapper = screen.getByRole("button");
    expect(wrapper).toHaveAttribute("tabIndex", "0");
  });

  it("renders child content unchanged", () => {
    render(
      <InfoTip text="Some tooltip">
        <strong>Bold text</strong>
      </InfoTip>,
    );

    const boldText = screen.getByText("Bold text");
    expect(boldText).toBeInTheDocument();
    expect(boldText.tagName).toBe("STRONG");
  });
});
