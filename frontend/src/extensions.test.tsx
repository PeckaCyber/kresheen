import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";

// A throwaway plugin frontend standing in for `@kresheen/pro`.
vi.mock("@kresheen/pro", () => ({
  default: {
    navItems: [{ to: "/demo", label: "Demo page", icon: "bi-star" }],
    runTabs: [{ key: "demo", label: "Demo tab", render: () => <div>demo tab body</div> }],
    loginButtons: [{ id: "demo", render: () => <button type="button">Demo login</button> }],
  },
}));

import { extensions } from "./extensions";
import { ModelTabs } from "./pages/model/ModelTabs";

describe("frontend extensions", () => {
  it("exposes what a plugin adds and defaults the other slots to empty", () => {
    expect(extensions.navItems.map((i) => i.label)).toEqual(["Demo page"]);
    expect(extensions.routes).toEqual([]);
    expect(extensions.settingsSections).toEqual([]);
    expect(extensions.dashboardPanels).toEqual([]);
  });

  it("shows a plugin's run tab next to the built-in ones", () => {
    render(
      <MemoryRouter>
        <ModelTabs active="overview" onSelect={() => {}} counts={{ threats: 0, actions: 0, findings: 0 }} />
      </MemoryRouter>,
    );
    expect(screen.getByTestId("model-tab-demo")).toHaveTextContent("Demo tab");
    expect(screen.getByTestId("model-tab-overview")).toBeInTheDocument();
  });
});
