import { Nav } from "react-bootstrap";
import { extensions } from "../../extensions";

// URL-addressed tabs. Keep this list and
// App.tsx's route in sync -- an unknown slug in the URL falls back to
// "overview" (see isModelTabKey / ApplicationDetail.tsx).
export const MODEL_TAB_SLUGS = ["overview", "diagram", "threats", "actions", "findings", "settings"] as const;

export type ModelTabKey = (typeof MODEL_TAB_SLUGS)[number];

export function isModelTabKey(value: string | undefined): value is ModelTabKey {
  return value !== undefined && (MODEL_TAB_SLUGS as readonly string[]).includes(value);
}

export interface ModelTabCounts {
  threats: number;
  actions: number;
  findings: number;
}

export function ModelTabs({
  active,
  onSelect,
  counts,
}: {
  active: string;
  onSelect: (tab: string) => void;
  counts: ModelTabCounts;
}) {
  const tabs: { key: string; label: string }[] = [
    { key: "overview", label: "Overview" },
    { key: "diagram", label: "Diagram" },
    { key: "threats", label: `Threats (${counts.threats})` },
    { key: "actions", label: `Action plan (${counts.actions})` },
    { key: "findings", label: `Findings (${counts.findings})` },
    { key: "settings", label: "Model settings" },
    ...extensions.runTabs.map((t) => ({ key: t.key, label: t.label })),
  ];

  return (
    <Nav
      variant="tabs"
      activeKey={active}
      className="mb-3"
      onSelect={(key) => {
        if (key) onSelect(key);
      }}
    >
      {tabs.map((tab) => (
        <Nav.Item key={tab.key}>
          <Nav.Link eventKey={tab.key} data-testid={`model-tab-${tab.key}`}>
            {tab.label}
          </Nav.Link>
        </Nav.Item>
      ))}
    </Nav>
  );
}
