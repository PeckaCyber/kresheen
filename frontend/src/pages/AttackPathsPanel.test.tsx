import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { AttackPathsPanel, type AttackPathOut } from "./AttackPathsPanel";

const PATH: AttackPathOut = {
  source_name: "Customer",
  target_name: "Orders DB",
  target_type: "data_store",
  is_crown_jewel: true,
  risk: "critical",
  risk_factors: ["reaches an asset tagged 'PII'", "no hop on this path requires authentication"],
  boundary_crossings: 1,
  hops: [
    {
      from_name: "Customer",
      to_name: "Web",
      flow_label: "HTTPS",
      crosses_boundary: true,
      authenticated: null,
      encrypted: true,
    },
    {
      from_name: "Web",
      to_name: "Orders DB",
      flow_label: "SQL",
      crosses_boundary: false,
      authenticated: null,
      encrypted: null,
    },
  ],
};

describe("AttackPathsPanel", () => {
  it("shows a reassuring empty state when no paths are found", () => {
    render(<AttackPathsPanel paths={[]} />);

    expect(screen.getByText(/No attack paths found/)).toBeInTheDocument();
  });

  it("renders a path's risk, crown-jewel flag, route and risk factors", () => {
    render(<AttackPathsPanel paths={[PATH]} />);

    expect(screen.getByText("critical")).toBeInTheDocument();
    expect(screen.getByText("crown jewel")).toBeInTheDocument();
    expect(screen.getByText("1 boundary crossing")).toBeInTheDocument();
    expect(screen.getByText("Customer")).toBeInTheDocument();
    expect(screen.getByText("Orders DB")).toBeInTheDocument();
    expect(screen.getByText(/reaches an asset tagged 'PII'/)).toBeInTheDocument();
    expect(screen.getByText("crosses boundary")).toBeInTheDocument();
  });

  it("pluralizes the boundary-crossing count", () => {
    render(<AttackPathsPanel paths={[{ ...PATH, boundary_crossings: 2 }]} />);

    expect(screen.getByText("2 boundary crossings")).toBeInTheDocument();
  });
});
