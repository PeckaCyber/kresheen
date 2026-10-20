import { useEffect, useState } from "react";
import { Badge, Button, Form, InputGroup, Nav, Table } from "react-bootstrap";
import { ElementPropertiesForm, type ElementProperties, type PropertySpec } from "../ElementPropertiesForm";
import { ThreatsPanel, type ThreatOut } from "../ThreatsPanel";

// Sounil Yu's Distributed/Immutable/Ephemeral resilience heuristic, computed
// client-side from whichever of these owner-stated properties are set (see
// engine/threats/properties.py's docstring). null when none are stated --
// unknown is not the same as 0/3. Moved here from ApplicationDetail.tsx:
// this was only ever used by the node inspector.
const DIE_KEYS = ["die_distributed", "die_immutable", "die_ephemeral"] as const;

function dieResilience(properties: ElementProperties | undefined): number | null {
  if (!properties) return null;
  const stated = DIE_KEYS.filter((key) => properties[key] !== undefined);
  if (stated.length === 0) return null;
  return DIE_KEYS.filter((key) => properties[key] === true).length;
}

// The element the inspector shows -- a structural subset of
// ApplicationDetail.tsx's DfdNode (not exported, so this stays independent
// of the node-appearance code owned elsewhere in that file). A DfdNode can
// be passed straight through since it satisfies every field here.
export interface InspectorElement {
  id: string;
  name: string;
  type: string;
  trust_boundary: string | null;
  is_manual: boolean;
  // Open threats on this element (threatSignal.ts) -- decides the default tab.
  open_threat_count?: number;
  properties?: ElementProperties;
}

export interface InspectorFinding {
  id: string;
  title: string;
}

export const INSPECTOR_TABS = ["threats", "properties", "findings"] as const;
export type InspectorTabKey = (typeof INSPECTOR_TABS)[number];

// Threats scoped to one element -- same filter ThreatsPanel applies
// internally when given `elementId`, kept here too so the tab label's count
// matches what the tab actually shows.
export function elementThreatCount(element: InspectorElement, threats: ThreatOut[]): number {
  return threats.filter((t) => t.element_id === element.id).length;
}

// Threats first when the element has open threats (the thing most
// worth looking at), otherwise Properties. Never defaults to Findings.
export function defaultInspectorTab(element: InspectorElement): InspectorTabKey {
  return (element.open_threat_count ?? 0) > 0 ? "threats" : "properties";
}

export interface ElementInspectorProps {
  element: InspectorElement;
  editMode: boolean;
  onClose: () => void;
  // Rename (manually-added components only).
  nameDraft: string;
  onNameDraftChange: (value: string) => void;
  onRename: () => void;
  // Trust boundary.
  boundaryDraft: string;
  onBoundaryDraftChange: (value: string) => void;
  onSaveBoundary: () => void;
  boundarySuggestionsListId: string;
  // "Show on this diagram" toggle -- hides/shows the element on the diagram
  // being viewed only (other diagrams of the same model are unaffected).
  hiddenHere: boolean;
  onToggleHidden: () => void;
  // Delete (manually-added components only).
  onDeleteRequest: () => void;
  // Properties tab.
  propertySpecs: PropertySpec[];
  onSaveProperties: (next: ElementProperties) => void | Promise<void>;
  // Findings tab (only shown when non-empty).
  findings: InspectorFinding[];
  // Threats tab.
  applicationId: string;
  runId: string;
  threats: ThreatOut[];
  onThreatsChanged: () => void | Promise<void>;
  onAddThreat: () => void;
  onEditThreat: (threat: ThreatOut) => void;
  blankModel: boolean;
  onViewAllThreats: () => void;
}

// The Diagram tab's element inspector: a right-hand panel, docked
// next to the canvas on a wide viewport or an Offcanvas below 1100px (see
// ApplicationDetail.tsx). This component
// only renders the header/tabs/body -- positioning, backdrop and the
// docked-vs-Offcanvas choice belong to the caller.
export function ElementInspector({
  element,
  editMode,
  onClose,
  nameDraft,
  onNameDraftChange,
  onRename,
  boundaryDraft,
  onBoundaryDraftChange,
  onSaveBoundary,
  boundarySuggestionsListId,
  hiddenHere,
  onToggleHidden,
  onDeleteRequest,
  propertySpecs,
  onSaveProperties,
  findings,
  applicationId,
  runId,
  threats,
  onThreatsChanged,
  onAddThreat,
  onEditThreat,
  blankModel,
  onViewAllThreats,
}: ElementInspectorProps) {
  const threatCount = elementThreatCount(element, threats);
  const [tab, setTab] = useState<InspectorTabKey>(() => defaultInspectorTab(element));

  // A newly-selected element gets its own default tab, not whatever tab the
  // previous element happened to be showing.
  useEffect(() => {
    setTab(defaultInspectorTab(element));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [element.id]);

  useEffect(() => {
    function onKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape") onClose();
    }
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [onClose]);

  const dieScore = dieResilience(element.properties);

  return (
    <div className="pc-inspector" data-testid="element-inspector">
      <div className="pc-inspector-header">
        <div className="pc-inspector-title">
          <h2 className="h6 mb-1">{element.name}</h2>
          <p className="text-muted small mb-1">
            {element.type}
            {element.is_manual && (
              <Badge bg="secondary" className="ms-2">
                manually added
              </Badge>
            )}
            {dieScore !== null && (
              <Badge bg="info" className="ms-2" title="Distributed / Immutable / Ephemeral resilience properties stated">
                Resilience (DIE): {dieScore}/3
              </Badge>
            )}
            {element.properties?.is_ai_ml_component === true && (
              <Badge bg="dark" className="ms-2">
                AI/ML component
              </Badge>
            )}
          </p>
          <p className="text-muted small mb-0">{element.trust_boundary ?? "no trust boundary set"}</p>
        </div>
        <Button variant="link" className="pc-inspector-close" aria-label="Close inspector" onClick={onClose}>
          &times;
        </Button>
      </div>

      <Nav
        variant="pills"
        activeKey={tab}
        className="pc-inspector-tabs mb-2"
        onSelect={(key) => {
          if (key && (INSPECTOR_TABS as readonly string[]).includes(key)) setTab(key as InspectorTabKey);
        }}
      >
        <Nav.Item>
          <Nav.Link eventKey="threats" data-testid="inspector-tab-threats">
            Threats ({threatCount})
          </Nav.Link>
        </Nav.Item>
        <Nav.Item>
          <Nav.Link eventKey="properties" data-testid="inspector-tab-properties">
            Properties
          </Nav.Link>
        </Nav.Item>
        {findings.length > 0 && (
          <Nav.Item>
            <Nav.Link eventKey="findings" data-testid="inspector-tab-findings">
              Findings ({findings.length})
            </Nav.Link>
          </Nav.Item>
        )}
      </Nav>

      <div className="pc-inspector-body">
        {tab === "threats" && (
          <>
            <div className="d-flex justify-content-end mb-2">
              <Button size="sm" variant="outline-primary" onClick={onViewAllThreats}>
                View all threats for this element
              </Button>
            </div>
            <ThreatsPanel
              applicationId={applicationId}
              runId={runId}
              threats={threats}
              onChanged={onThreatsChanged}
              elementId={element.id}
              onAddThreat={onAddThreat}
              onEditThreat={onEditThreat}
              blankModel={blankModel}
            />
          </>
        )}

        {tab === "properties" && (
          <>
            {editMode && element.is_manual && (
              <Form.Group className="mb-3" controlId="inspector-name-draft">
                <Form.Label className="small">Name</Form.Label>
                <InputGroup size="sm">
                  <Form.Control
                    value={nameDraft}
                    maxLength={200}
                    onChange={(event) => onNameDraftChange(event.target.value)}
                    onKeyDown={(event) => {
                      if (event.key === "Enter") {
                        event.preventDefault();
                        onRename();
                      }
                    }}
                  />
                  <Button
                    variant="outline-primary"
                    disabled={!nameDraft.trim() || nameDraft.trim() === element.name}
                    onClick={onRename}
                  >
                    Rename
                  </Button>
                </InputGroup>
              </Form.Group>
            )}

            {editMode && (
              <Form.Group className="mb-3" controlId="inspector-boundary-draft">
                <Form.Label className="small">Trust boundary</Form.Label>
                <Form.Control
                  list={boundarySuggestionsListId}
                  value={boundaryDraft}
                  placeholder="e.g. internal, internet-facing, third-party"
                  onChange={(event) => onBoundaryDraftChange(event.target.value)}
                />
                <div className="d-flex gap-2 mt-2">
                  <Button size="sm" onClick={onSaveBoundary}>
                    Save
                  </Button>
                  <Button
                    size="sm"
                    variant={hiddenHere ? "outline-secondary" : "primary"}
                    aria-pressed={!hiddenHere}
                    title="Lit = shown on the diagram you're viewing. Click to hide it here (other diagrams are unaffected); click again to show it."
                    onClick={onToggleHidden}
                  >
                    Show on this diagram
                  </Button>
                  {element.is_manual && (
                    <Button size="sm" variant="outline-danger" onClick={onDeleteRequest}>
                      Delete component
                    </Button>
                  )}
                </div>
              </Form.Group>
            )}

            <ElementPropertiesForm specs={propertySpecs} value={element.properties ?? {}} onSave={onSaveProperties} />
          </>
        )}

        {tab === "findings" && findings.length > 0 && (
          <Table size="sm" striped>
            <tbody>
              {findings.map((finding) => (
                <tr key={finding.id}>
                  <td>{finding.title}</td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </div>
    </div>
  );
}
