import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it } from "vitest";
import { PageHeader } from "./PageHeader";

describe("PageHeader", () => {
  it("renders the title as a heading, the subtitle, actions and linked crumbs", () => {
    render(
      <MemoryRouter>
        <PageHeader
          title="Sample shop"
          subtitle="One line"
          actions={<button type="button">Export</button>}
          crumbs={[{ label: "Threat models", to: "/models" }, { label: "Sample shop" }]}
        />
      </MemoryRouter>,
    );
    expect(screen.getByRole("heading", { level: 1, name: "Sample shop" })).toBeInTheDocument();
    expect(screen.getByText("One line")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Export" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Threat models" })).toHaveAttribute("href", "/models");
  });
});
