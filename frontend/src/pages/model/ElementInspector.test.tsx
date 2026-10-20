import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import type { ThreatOut } from "../ThreatsPanel";
import { defaultInspectorTab, ElementInspector, elementThreatCount, type InspectorElement, type ElementInspectorProps } from "./ElementInspector";

function makeThreat(overrides: Partial<ThreatOut> = {}): ThreatOut {
  return {
    key: "T-1",
    rule_id: "R-1",
    element_kind: "component",
    element_id: "N-1",
    element_name: "Storefront",
    element_type: "process",
    methodology: "STRIDE",
    category: "Spoofing",
    cia_impacts: [],
    title: "Spoofing of Storefront",
    description: "desc",
    severity: "high",
    risk: "high",
    basis: "generic",
    mitigations: [],
    cwe_refs: [],
    attack_refs: [],
    risk_factors: [],
    origin: "predefined",
    manual_threat_id: null,
    status: "open",
    note: "",
    dread: null,
    ...overrides,
  };
}

const ELEMENT_WITH_OPEN_THREATS: InspectorElement = {
  id: "N-1",
  name: "Storefront",
  type: "process",
  trust_boundary: "internet-facing",
  is_manual: false,
  open_threat_count: 2,
};

const ELEMENT_NO_OPEN_THREATS: InspectorElement = {
  id: "N-2",
  name: "Database",
  type: "data_store",
  trust_boundary: null,
  is_manual: false,
  open_threat_count: 0,
};

function renderInspector(overrides: Partial<ElementInspectorProps> = {}) {
  const props: ElementInspectorProps = {
    element: ELEMENT_WITH_OPEN_THREATS,
    editMode: false,
    onClose: vi.fn(),
    nameDraft: "Storefront",
    onNameDraftChange: vi.fn(),
    onRename: vi.fn(),
    boundaryDraft: "internet-facing",
    onBoundaryDraftChange: vi.fn(),
    onSaveBoundary: vi.fn(),
    boundarySuggestionsListId: "trust-boundary-suggestions",
    hiddenHere: false,
    onToggleHidden: vi.fn(),
    onDeleteRequest: vi.fn(),
    propertySpecs: [],
    onSaveProperties: vi.fn(),
    findings: [],
    applicationId: "APP-1",
    runId: "RUN-1",
    threats: [makeThreat()],
    onThreatsChanged: vi.fn(),
    onAddThreat: vi.fn(),
    onEditThreat: vi.fn(),
    blankModel: false,
    onViewAllThreats: vi.fn(),
    ...overrides,
  };
  render(<ElementInspector {...props} />);
  return props;
}

describe("defaultInspectorTab / elementThreatCount", () => {
  it("defaults to threats when the element has open threats", () => {
    expect(defaultInspectorTab(ELEMENT_WITH_OPEN_THREATS)).toBe("threats");
  });

  it("defaults to properties when the element has no open threats", () => {
    expect(defaultInspectorTab(ELEMENT_NO_OPEN_THREATS)).toBe("properties");
  });

  it("counts only threats on this element", () => {
    const threats = [makeThreat({ element_id: "N-1" }), makeThreat({ key: "T-2", element_id: "N-2" })];
    expect(elementThreatCount(ELEMENT_WITH_OPEN_THREATS, threats)).toBe(1);
  });
});

describe("ElementInspector default tab", () => {
  it("shows the Threats tab's content when the element has open threats", () => {
    renderInspector({ element: ELEMENT_WITH_OPEN_THREATS, threats: [makeThreat()] });
    expect(screen.getByTestId("inspector-tab-threats").className).toContain("active");
    expect(screen.getByText("View all threats for this element")).toBeInTheDocument();
  });

  it("shows the Properties tab's content when the element has no open threats", () => {
    renderInspector({
      element: ELEMENT_NO_OPEN_THREATS,
      threats: [],
      propertySpecs: [{ key: "encrypted", label: "Encrypted at rest", kind: "bool", help: "" }],
    });
    expect(screen.getByTestId("inspector-tab-properties").className).toContain("active");
    expect(screen.getByText("Encrypted at rest")).toBeInTheDocument();
  });

  it("resets to the new element's default tab when the selected element changes", () => {
    const { rerender } = render(
      <ElementInspector
        {...{
          element: ELEMENT_NO_OPEN_THREATS,
          editMode: false,
          onClose: vi.fn(),
          nameDraft: "",
          onNameDraftChange: vi.fn(),
          onRename: vi.fn(),
          boundaryDraft: "",
          onBoundaryDraftChange: vi.fn(),
          onSaveBoundary: vi.fn(),
          boundarySuggestionsListId: "trust-boundary-suggestions",
          hiddenHere: false,
          onToggleHidden: vi.fn(),
          onDeleteRequest: vi.fn(),
          propertySpecs: [],
          onSaveProperties: vi.fn(),
          findings: [],
          applicationId: "APP-1",
          runId: "RUN-1",
          threats: [],
          onThreatsChanged: vi.fn(),
          onAddThreat: vi.fn(),
          onEditThreat: vi.fn(),
          blankModel: false,
          onViewAllThreats: vi.fn(),
        }}
      />,
    );
    expect(screen.getByTestId("inspector-tab-properties").className).toContain("active");

    rerender(
      <ElementInspector
        {...{
          element: ELEMENT_WITH_OPEN_THREATS,
          editMode: false,
          onClose: vi.fn(),
          nameDraft: "",
          onNameDraftChange: vi.fn(),
          onRename: vi.fn(),
          boundaryDraft: "",
          onBoundaryDraftChange: vi.fn(),
          onSaveBoundary: vi.fn(),
          boundarySuggestionsListId: "trust-boundary-suggestions",
          hiddenHere: false,
          onToggleHidden: vi.fn(),
          onDeleteRequest: vi.fn(),
          propertySpecs: [],
          onSaveProperties: vi.fn(),
          findings: [],
          applicationId: "APP-1",
          runId: "RUN-1",
          threats: [makeThreat()],
          onThreatsChanged: vi.fn(),
          onAddThreat: vi.fn(),
          onEditThreat: vi.fn(),
          blankModel: false,
          onViewAllThreats: vi.fn(),
        }}
      />,
    );
    expect(screen.getByTestId("inspector-tab-threats").className).toContain("active");
  });
});

describe("ElementInspector tab switching", () => {
  it("switches to Properties and Findings when clicked", () => {
    renderInspector({
      element: ELEMENT_WITH_OPEN_THREATS,
      threats: [makeThreat()],
      findings: [{ id: "F-1", title: "Vulnerable dependency" }],
      propertySpecs: [{ key: "encrypted", label: "Encrypted at rest", kind: "bool", help: "" }],
    });

    // Starts on Threats.
    expect(screen.getByText("View all threats for this element")).toBeInTheDocument();
    expect(screen.getByTestId("inspector-tab-findings")).toHaveTextContent("Findings (1)");

    fireEvent.click(screen.getByTestId("inspector-tab-properties"));
    expect(screen.getByText("Encrypted at rest")).toBeInTheDocument();
    expect(screen.queryByText("View all threats for this element")).not.toBeInTheDocument();

    fireEvent.click(screen.getByTestId("inspector-tab-findings"));
    expect(screen.getByText("Vulnerable dependency")).toBeInTheDocument();
    expect(screen.queryByText("Encrypted at rest")).not.toBeInTheDocument();
  });

  it("hides the Findings tab entirely when the element has no findings", () => {
    renderInspector({ findings: [] });
    expect(screen.queryByTestId("inspector-tab-findings")).not.toBeInTheDocument();
  });

  it("shows the threats tab count for this element only", () => {
    renderInspector({
      threats: [makeThreat({ key: "T-1", element_id: "N-1" }), makeThreat({ key: "T-2", element_id: "N-9" })],
    });
    expect(screen.getByTestId("inspector-tab-threats")).toHaveTextContent("Threats (1)");
  });
});

describe("ElementInspector close", () => {
  it("calls onClose when the close button is clicked", () => {
    const onClose = vi.fn();
    renderInspector({ onClose });
    fireEvent.click(screen.getByRole("button", { name: "Close inspector" }));
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("calls onClose on Escape", () => {
    const onClose = vi.fn();
    renderInspector({ onClose });
    fireEvent.keyDown(window, { key: "Escape" });
    expect(onClose).toHaveBeenCalledTimes(1);
  });
});
