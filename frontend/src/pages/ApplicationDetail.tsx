import { extensions } from "../extensions";
import {
  Background,
  Controls,
  Handle,
  MiniMap,
  Position,
  ReactFlow,
  ReactFlowProvider,
  SelectionMode,
  useEdgesState,
  useNodesState,
  type Connection,
  type Edge,
  type Node,
  type NodeProps,
  type OnSelectionChangeFunc,
  type ReactFlowInstance,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import { Alert, Badge, Button, Form, InputGroup, Modal, Offcanvas, Table } from "react-bootstrap";
import { Link, useNavigate, useParams } from "react-router-dom";
import { apiFetch, ApiError } from "../api/client";
import { dfdEditApi, type DiagramElementLayoutOut } from "./dfdEditApi";
import { isTextEntryTarget, useEditHistory } from "./useEditHistory";
import { AddThreatModal, type ElementChoice } from "./AddThreatModal";
import { DataSourcesPanel } from "./DataSourcesPanel";
import { ModelInfoPanel } from "./ModelInfoPanel";
import { ExportMenu } from "./ExportMenu";
import { ElementPropertiesForm, type ElementProperties, type PropertySpec } from "./ElementPropertiesForm";
import { type AttackPathOut } from "./AttackPathsPanel";
import { ActionPlanPanel, type ActionPlanOut } from "./ActionPlanPanel";
import { isConfigObject, orderBoundaries, placeInRows, rowsBottom, splitKind } from "./dfdLayout";
import { ReviewStamp } from "./ReviewStamp";
import { type CompletenessOut } from "./CompletenessPanel";
import { type RunDiffOut } from "./RunDiffPanel";
import { RunHistory, type RunHistoryEntry } from "./RunHistory";
import { openThreatSignal, worseOf } from "./threatSignal";
import { partlyAnalysedSources, SOURCE_TYPE_LABELS, unanalysedSources, type SourceResult } from "./sourceStatus";
import { ThreatsPanel, type ThreatOut, type ThreatsOut } from "./ThreatsPanel";
import { ModelHeader } from "./model/ModelHeader";
import { StatStrip, type StatStripItem } from "./model/StatStrip";
import { ModelTabs, isModelTabKey } from "./model/ModelTabs";
import { ModelTour } from "./model/ModelTour";
import { Overview } from "./model/Overview";
import { nodeAppearance, nodeRingColor } from "./model/nodeStyle";
import { RiskBadge } from "../components/RiskBadge";
import { ElementInspector } from "./model/ElementInspector";

interface DfdNode {
  id: string;
  name: string;
  type: string;
  trust_boundary: string | null;
  worst_severity: string | null;
  open_finding_count: number;
  // Derived client-side from the run's open threats (threatSignal.ts).
  open_threat_count?: number;
  worst_threat_risk?: string | null;
  is_manual: boolean;
  // True when trust_boundary comes from a user override rather than being
  // auto-derived -- undo needs the distinction to restore "no override".
  boundary_overridden: boolean;
  position_x: number | null;
  position_y: number | null;
  // Owner-stated properties (unset keys are unknown); see ElementPropertiesForm.
  properties?: ElementProperties;
}

interface DfdBoundaryLayout {
  name: string;
  position_x: number;
  position_y: number;
}

interface DfdEdge {
  id: string;
  source: string;
  target: string;
  label: string | null;
  is_manual: boolean;
  properties?: ElementProperties;
}

interface DfdOut {
  nodes: DfdNode[];
  edges: DfdEdge[];
  boundaries: DfdBoundaryLayout[];
}

// A named, independently-arranged view of this Application's DFD. All diagrams share the same
// threats/findings/run; a diagram only changes what the canvas shows and
// where things sit on it.
interface DiagramOut {
  id: string;
  name: string;
}

interface RunOut {
  id: string;
  status: string;
  error_message: string | null;
  // Empty for a blank model the user builds by hand.
  data_source_config_ids: string[];
  // Absent on older runs.
  source_results?: SourceResult[];
}

interface StalenessOut {
  stale: boolean;
  new_data_source_ids: string[];
  changed_data_source_ids: string[];
  removed_data_source_ids: string[];
}

interface FindingOut {
  id: string;
  domain: string;
  title: string;
  status: string;
  asset_id: string;
  // Only ever set for a Grype-sourced vulnerability finding; blank for
  // every other domain and when Grype itself didn't know a fix.
  evidence?: {
    fixed_versions?: string[];
  };
}

// Loose types matching the CycloneDX fields we actually render -- the API
// passes the (now application-dependency-filtered, see api_applications.py)
// component/vulnerability dicts through mostly as-is, so these objects
// carry more fields than declared here.
interface SbomComponent {
  "bom-ref"?: string;
  name: string;
  version?: string | null;
  type?: string;
}

interface SbomVulnerability {
  id: string;
  affects?: { ref: string }[];
}

interface SbomOut {
  format: string;
  component_count: number;
  vulnerability_count: number;
  components: SbomComponent[];
  vulnerabilities: SbomVulnerability[];
  // True when only bare dependency manifests (no lockfile) were found --
  // Grype can't resolve exact installed versions without one, so a zero
  // component/vulnerability count here means "nothing could be resolved,"
  // not "genuinely zero dependencies." See
  // github_repository_ingestor.py's lockfile check.
  no_lockfile_detected: boolean;
  manifest_files_found: string[];
}

const ASSET_TYPES = ["process", "data_store", "external_entity"] as const;
type AssetTypeValue = (typeof ASSET_TYPES)[number];

const ASSET_TYPE_LABELS: Record<AssetTypeValue, string> = {
  process: "Process",
  data_store: "Data Store",
  external_entity: "External Entity",
};

// Drag payload MIME type for placing a new component by dragging a palette
// button onto the canvas -- a private, namespaced type (not the generic
// "text/plain") so this drop target never accidentally reacts to some
// unrelated browser drag (an image, a link, a file).
const PLACEMENT_DRAG_TYPE = "application/x-kresheen-asset-type";

// Trust-boundary grouping: nodes sharing a non-null `trust_boundary` value
// render inside one shared "boundary" container node (React Flow's
// parent/child mechanism -- @xyflow/react 12's Node type uses `parentId`,
// not the older `reactflow` package's `parentNode`, confirmed against the
// installed package's own type declarations before writing this). This is
// purely a rendering grouping, computed fresh from whatever `trust_boundary`
// values the current DFD response carries (auto-derived or overridden via
// the trust-boundary API) -- nothing about membership is itself persisted
// as a shape; the boundary *label* per component is the only persisted
// thing (see models/trust_boundary.py).
function TrustBoundaryGroupNode({ data }: NodeProps) {
  const label = (data as { label: string }).label;
  return (
    <div
      style={{
        width: "100%",
        height: "100%",
        border: "2px dashed #6610f2",
        borderRadius: 10,
        background: "rgba(102,16,242,0.06)",
        position: "relative",
      }}
    >
      <div
        style={{
          position: "absolute",
          top: -11,
          left: 10,
          background: "var(--bs-body-bg)",
          padding: "0 8px",
          fontSize: 12,
          fontWeight: 600,
          color: "var(--bs-primary-text-emphasis, #6610f2)",
        }}
      >
        {label}
      </div>
    </div>
  );
}

// Custom node component with left/right handles for components (process, data store, external entity)
function DfdComponentNode({ data }: NodeProps) {
  const label = data.label as ReactNode;
  return (
    <div style={{ width: "100%", height: "100%" }}>
      <Handle type="target" position={Position.Left} />
      {label}
      <Handle type="source" position={Position.Right} />
    </div>
  );
}

// Must be a stable module-level reference -- passing a new object literal
// as `nodeTypes` on every render defeats React Flow's memoization and logs
// a warning.
const NODE_TYPES = { boundary: TrustBoundaryGroupNode, default: DfdComponentNode };

// MiniMap node colouring: use the ring colour (severity for HIGH/CRITICAL, neutral border for others)
function miniMapNodeColor(node: Node): string {
  if (node.type === "boundary") return "transparent";
  const data = node.data as { worst_threat_risk?: string | null; worst_severity?: string | null };
  const worst = worseOf(data.worst_severity, data.worst_threat_risk);
  return nodeRingColor(worst);
}

// One framing for the canvas, used on mount and whenever the Diagram tab re-activates. A bare fitView() ignores the
// zoom cap and zooms a small diagram to ~2x, so which of the two ran last decided how big everything was.
const FIT_VIEW_OPTIONS = { padding: 0.12, minZoom: 0.55, maxZoom: 1.1 };
const GROUP_PADDING = 40;
const GROUP_HEADER = 30;
const NODE_WIDTH = 200;
const NODE_HEIGHT = 96;
const GROUP_COLUMNS = 3;
const UNGROUPED_COLUMNS = 4;

function isOutOfScope(properties: ElementProperties | undefined): boolean {
  return properties?.out_of_scope === true;
}

function nodeLabel(node: DfdNode): ReactNode {
  const worst = worseOf(node.worst_severity, node.worst_threat_risk);
  const isHighOrCritical = worst === "critical" || worst === "high";

  const counts = [
    node.open_finding_count ? `${node.open_finding_count} finding${node.open_finding_count === 1 ? "" : "s"}` : "",
    !isHighOrCritical && node.open_threat_count
      ? `${node.open_threat_count} threat${node.open_threat_count === 1 ? "" : "s"}`
      : "",
  ].filter(Boolean);

  // "Deployment/quay-app" reads as "quay-app" with the kind underneath; the full name stays in the tooltip.
  const { kind, short } = splitKind(node.name);
  const name = `${short}${node.is_manual ? " ✎" : ""}${isOutOfScope(node.properties) ? " (out of scope)" : ""}`;
  return (
    <span title={node.name}>
      <span style={{ fontWeight: 600, wordBreak: "break-word" }}>{name}</span>
      {kind && <span style={{ display: "block", fontSize: 10, opacity: 0.85 }}>{kind}</span>}
      {isHighOrCritical && node.open_threat_count ? (
        <span style={{ display: "block", marginTop: 4 }}>
          <RiskBadge level={worst} style={{ fontSize: 10, padding: "2px 6px" }}>
            {worst} · {node.open_threat_count} threat{node.open_threat_count === 1 ? "" : "s"}
          </RiskBadge>
        </span>
      ) : counts.length > 0 ? (
        <span style={{ display: "block", fontSize: 10, opacity: 0.55 }}>{counts.join(", ")}</span>
      ) : null}
    </span>
  );
}

function nodeBackground(node: DfdNode): string {
  const worst = worseOf(node.worst_severity, node.worst_threat_risk);
  const appearance = nodeAppearance(worst, node.open_threat_count ?? 0);
  return appearance.fill;
}

// Standard DFD notation: a process is rounded, a data store is open-ended (top and bottom rules only),
// an external entity is a square-cornered box with a double border.
function shapeStyle(type: string): Record<string, string | number> {
  if (type === "process") return { borderRadius: 999, padding: "10px 22px" };
  if (type === "data_store") {
    return {
      borderRadius: 0,
      borderTop: "4px solid rgba(0,0,0,.55)",
      borderBottom: "4px solid rgba(0,0,0,.55)",
      borderLeft: "none",
      borderRight: "none",
    };
  }
  return { borderRadius: 2, border: "5px double rgba(255,255,255,.9)" };
}

function nodeStyle(node: DfdNode) {
  const outOfScope = isOutOfScope(node.properties);
  const worst = worseOf(node.worst_severity, node.worst_threat_risk);
  const appearance = nodeAppearance(worst, node.open_threat_count ?? 0);
  const shapeStyles = shapeStyle(node.type);

  // Update border colours in shape styles to use the ring colour (preserve shape, change colour)
  let updatedShapeStyles: Record<string, string | number> = shapeStyles;
  if (node.type === "data_store") {
    updatedShapeStyles = {
      borderRadius: 0,
      borderTop: `2px solid ${appearance.ring}`,
      borderBottom: `2px solid ${appearance.ring}`,
      borderLeft: "none",
      borderRight: "none",
    };
  } else if (node.type === "external_entity") {
    updatedShapeStyles = {
      borderRadius: 2,
      border: `2px double ${appearance.ring}`,
    };
  } else {
    // process: add border
    updatedShapeStyles = {
      ...shapeStyles,
      border: `2px solid ${appearance.ring}`,
    };
  }

  return {
    background: appearance.fill,
    color: appearance.text,
    boxShadow: appearance.ring !== "var(--pc-border)" ? `0 0 0 3px ${appearance.ring}` : undefined,
    opacity: outOfScope ? 0.45 : 1,
    padding: 10,
    fontSize: 13,
    textAlign: "center" as const,
    width: NODE_WIDTH - 20,
    ...updatedShapeStyles,
    // Out of scope and hand-drawn are shown by outline, on top of the shape.
    ...(outOfScope
      ? { outline: "2px dashed #6c757d", outlineOffset: 2 }
      : node.is_manual
        ? { outline: "2px solid #6c757d", outlineOffset: 2 }
        : {}),
  };
}

const BOUNDARIES_PER_ROW = 3;
const BOUNDARY_GAP = 60;

function layoutNodes(
  nodes: DfdNode[],
  boundaries: DfdBoundaryLayout[],
  boundariesDraggable: boolean,
  edges: { source: string; target: string }[] = [],
): Node[] {
  const savedLayout = new Map(boundaries.map((b) => [b.name, b]));
  const byBoundary = new Map<string, DfdNode[]>();
  const ungrouped: DfdNode[] = [];
  for (const node of nodes) {
    if (node.trust_boundary) {
      const members = byBoundary.get(node.trust_boundary) ?? [];
      members.push(node);
      byBoundary.set(node.trust_boundary, members);
    } else {
      ungrouped.push(node);
    }
  }
  // Outside-in, so the diagram reads left to right (internet, DMZ, application, data).
  const order = orderBoundaries(nodes, edges);
  const groups = new Map<string, DfdNode[]>(order.map((name) => [name, byBoundary.get(name) ?? []]));
  const sizes = order.map((name) => {
    const members = groups.get(name) ?? [];
    const cols = Math.min(GROUP_COLUMNS, Math.max(members.length, 1));
    const rows = Math.ceil(members.length / cols);
    return {
      width: cols * NODE_WIDTH + GROUP_PADDING * 2,
      height: rows * NODE_HEIGHT + GROUP_PADDING * 2 + GROUP_HEADER,
    };
  });
  const slots = placeInRows(sizes, BOUNDARIES_PER_ROW, BOUNDARY_GAP);

  const result: Node[] = [];
  const top = rowsBottom(sizes, BOUNDARIES_PER_ROW, BOUNDARY_GAP);

  order.forEach((boundaryName, boundaryIndex) => {
    const members = groups.get(boundaryName) ?? [];
    const groupId = `boundary:${boundaryName}`;
    const saved = savedLayout.get(boundaryName);
    const cols = Math.min(GROUP_COLUMNS, members.length);
    const { width, height } = sizes[boundaryIndex];
    result.push({
      id: groupId,
      type: "boundary",
      // A dragged boundary's origin is persisted by label in the diagram's layout; every
      // other boundary keeps its computed slot, so moving one does not shift the rest. Members
      // are positioned relative to the group, so they move with it.
      position: saved ? { x: saved.position_x, y: saved.position_y } : slots[boundaryIndex],
      style: { width, height },
      data: { label: boundaryName },
      draggable: boundariesDraggable,
      selectable: false,
    });
    members.forEach((node, index) => {
      result.push({
        id: node.id,
        parentId: groupId,
        extent: "parent",
        position: {
          x: GROUP_PADDING + (index % cols) * NODE_WIDTH,
          y: GROUP_PADDING + GROUP_HEADER + Math.floor(index / cols) * NODE_HEIGHT,
        },
        data: {
          label: nodeLabel(node),
          worst_severity: node.worst_severity,
          worst_threat_risk: node.worst_threat_risk,
        },
        style: nodeStyle(node),
      });
    });
  });

  // Manually-placed components with a saved position (dragged onto the
  // canvas at a specific spot, see handleCanvasDrop) render exactly there
  // instead of the auto-grid -- without this, a dropped node would snap
  // back to a computed grid position the instant the page reloads the DFD,
  // making the drag-and-drop placement purely cosmetic. Auto-generated
  // (non-manual) nodes always use the grid; their ids aren't stable across
  // runs so a saved position couldn't mean anything on the next scan.
  const positioned = ungrouped.filter((n) => n.is_manual && n.position_x != null && n.position_y != null);
  const gridded = ungrouped.filter((n) => !(n.is_manual && n.position_x != null && n.position_y != null));

  positioned.forEach((node) => {
    result.push({
      id: node.id,
      position: { x: node.position_x as number, y: node.position_y as number },
      data: { label: nodeLabel(node), worst_severity: node.worst_severity, worst_threat_risk: node.worst_threat_risk },
      style: nodeStyle(node),
    });
  });

  gridded.forEach((node, index) => {
    result.push({
      id: node.id,
      position: {
        x: (index % UNGROUPED_COLUMNS) * 220,
        y: top + Math.floor(index / UNGROUPED_COLUMNS) * 140,
      },
      data: { label: nodeLabel(node), worst_severity: node.worst_severity, worst_threat_risk: node.worst_threat_risk },
      style: nodeStyle(node),
    });
  });

  return result;
}

// The Diagram tab's canvas height is now calculated dynamically (see canvasHeight state)

interface PendingPlacement {
  type: AssetTypeValue;
  flowX: number;
  flowY: number;
  // Screen-relative (to the DFD container, not the viewport) coordinates,
  // purely for positioning the little floating name prompt where the user
  // actually dropped -- kept separate from flowX/flowY (the React Flow
  // canvas coordinates that actually get saved), since the two spaces
  // aren't the same once you account for pan/zoom.
  screenX: number;
  screenY: number;
}

interface DfdPaneProps {
  nodes: Node[];
  edges: Edge[];
  editMode: boolean;
  boundaryToolActive: boolean;
  showMinimap: boolean;
  onNodesChange: ReturnType<typeof useNodesState<Node>>[2];
  onEdgesChange: ReturnType<typeof useEdgesState<Edge>>[2];
  onNodeClick: (event: unknown, node: Node) => void;
  onEdgeClick: (event: unknown, edge: Edge) => void;
  onConnect: (connection: Connection) => void;
  onInit: (instance: ReactFlowInstance) => void;
  onSelectionChange: OnSelectionChangeFunc;
  onNodeDragStart: (event: unknown, node: Node) => void;
  onNodeDragStop: (event: unknown, node: Node) => void;
  // Clicking empty canvas closes the element inspector.
  onPaneClick: () => void;
}

function DfdPane({
  nodes,
  edges,
  editMode,
  boundaryToolActive,
  showMinimap,
  onNodesChange,
  onEdgesChange,
  onNodeClick,
  onEdgeClick,
  onConnect,
  onInit,
  onSelectionChange,
  onNodeDragStart,
  onNodeDragStop,
  onPaneClick,
}: DfdPaneProps) {
  if (nodes.length === 0 && !editMode) {
    return <p className="text-muted p-3 mb-0">No components yet. Turn on Edit mode to add some by hand.</p>;
  }
  return (
    <div
      style={{ height: "100%", overscrollBehavior: "contain" }}
      // Middle-button drag pans the canvas; without this the browser also starts its own
      // middle-click autoscroll and drags the whole page up and down with it.
      onMouseDown={(event) => {
        if (event.button === 1) event.preventDefault();
      }}
    >
      <ReactFlow
        colorMode={document.documentElement.getAttribute("data-bs-theme") === "dark" ? "dark" : "light"}
        nodes={nodes}
        edges={edges}
        nodeTypes={NODE_TYPES}
        defaultEdgeOptions={{ type: "smoothstep" }}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onNodeClick={onNodeClick}
        onEdgeClick={onEdgeClick}
        onConnect={editMode ? onConnect : undefined}
        nodesConnectable={editMode}
        onInit={onInit}
        onSelectionChange={onSelectionChange}
        onNodeDragStart={onNodeDragStart}
        onNodeDragStop={onNodeDragStop}
        onPaneClick={onPaneClick}
        // Trust-boundary tool: drag-select instead of drag-to-pan, so
        // dragging across empty canvas draws a selection box around
        // whatever it touches (SelectionMode.Partial -- a node only
        // partially inside the box still counts, matching "drag a box
        // around parts of the DFD"). Panning moves to the middle/right
        // mouse button only while this tool is armed; with no tool armed,
        // left-drag pans exactly like before this feature existed.
        selectionOnDrag={boundaryToolActive}
        selectionMode={SelectionMode.Partial}
        panOnDrag={boundaryToolActive ? [1, 2] : true}
        fitView
        fitViewOptions={FIT_VIEW_OPTIONS}
        minZoom={0.2}
        style={{ background: "var(--bs-body-bg)" }}
      >
        <Background color="var(--pc-grid)" />
        <Controls />
        {showMinimap && (
          <MiniMap
            position="top-right"
            style={{ width: 140, height: 90 }}
            maskColor="rgba(0,0,0,0.1)"
            nodeColor={miniMapNodeColor}
          />
        )}
      </ReactFlow>
    </div>
  );
}

// Past this many diagrams the tab row gets unwieldy, so it becomes a dropdown.
const MAX_DIAGRAM_TABS = 5;

const BOUNDARY_SUGGESTIONS = ["internal", "internet-facing", "third-party"];

export function ApplicationDetailPage() {
  const { applicationId, runId, tab } = useParams<{ applicationId: string; runId: string; tab?: string }>();
  const navigate = useNavigate();
  // URL-addressed tabs: an unknown or missing slug is Overview.
  const extensionTab = extensions.runTabs.find((t) => t.key === tab);
  const activeTab: string = extensionTab ? extensionTab.key : isModelTabKey(tab) ? tab : "overview";
  const [run, setRun] = useState<RunOut | null>(null);
  const [runs, setRuns] = useState<RunHistoryEntry[] | null>(null);
  const [staleness, setStaleness] = useState<StalenessOut | null>(null);
  const [reRunning, setReRunning] = useState(false);
  const [reRunError, setReRunError] = useState<string | null>(null);
  const [diff, setDiff] = useState<RunDiffOut | null>(null);
  const [attackPaths, setAttackPaths] = useState<AttackPathOut[] | null>(null);
  const [findings, setFindings] = useState<FindingOut[]>([]);
  const [sbom, setSbom] = useState<SbomOut | null>(null);
  const [threatsData, setThreatsData] = useState<ThreatsOut | null>(null);
  const [openActionCount, setOpenActionCount] = useState<number | null>(null);
  const [completeness, setCompleteness] = useState<CompletenessOut | null>(null);
  const dfdSnapshotRef = useRef<{ nodes: DfdNode[]; dfd: DfdOut } | null>(null);
  // The user's explicit choice about configuration objects; null = decide automatically.
  const [showConfigObjects, setShowConfigObjects] = useState<boolean | null>(null);
  const showConfigRef = useRef<boolean | null>(null);
  showConfigRef.current = showConfigObjects;
  const [configObjects, setConfigObjects] = useState({ count: 0, shown: true });
  // Add-threat dialog: `open` plus which element to preselect (null = first).
  const [editingThreat, setEditingThreat] = useState<ThreatOut | null>(null);
  const [addThreat, setAddThreat] = useState<{ open: boolean; elementId: string | null }>({
    open: false,
    elementId: null,
  });
  const [edgesForThreats, setEdgesForThreats] = useState<DfdEdge[]>([]);
  const [loadError, setLoadError] = useState<string | null>(null);
  // The API answers 404 for a model that does not exist and for one the user may not see; both get the same page.
  const [notFound, setNotFound] = useState(false);
  const [nodesById, setNodesById] = useState<Record<string, DfdNode>>({});
  const nodesByIdRef = useRef<Record<string, DfdNode>>({});
  nodesByIdRef.current = nodesById;
  const [nodes, setNodes, onNodesChange] = useNodesState<Node>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([]);
  const [selectedNode, setSelectedNode] = useState<DfdNode | null>(null);
  const [reactFlowInstance, setReactFlowInstance] = useState<ReactFlowInstance | null>(null);
  const dfdContainerRef = useRef<HTMLDivElement | null>(null);
  // Below 1100px the docked inspector has nowhere to go, so it falls back
  // to the Offcanvas. matchMedia over a resize listener since it
  // only fires on the breakpoint crossing, not every pixel of a drag-resize.
  const [isNarrowViewport, setIsNarrowViewport] = useState(
    () => typeof window !== "undefined" && window.matchMedia("(max-width: 1099px)").matches,
  );
  useEffect(() => {
    const mql = window.matchMedia("(max-width: 1099px)");
    const onChange = (event: MediaQueryListEvent) => setIsNarrowViewport(event.matches);
    mql.addEventListener("change", onChange);
    return () => mql.removeEventListener("change", onChange);
  }, []);

  // Canvas height on the Diagram tab: fill the viewport below wherever the
  // canvas row starts. Measured through a callback ref because the row only
  // mounts once the run has loaded and the Diagram tab is active (an effect
  // keyed on the tab ran before that and never measured).
  const [canvasHeight, setCanvasHeight] = useState<number>(480);
  const diagramRowObserver = useRef<(() => void) | null>(null);
  const diagramPaneRef = useCallback((element: HTMLDivElement | null) => {
    diagramRowObserver.current?.();
    diagramRowObserver.current = null;
    if (!element) return;
    const update = () => {
      // Distance from the top of the page's scroll container, so a scrolled
      // page does not shrink the canvas.
      const scroller = element.closest(".pc-main-scroll") ?? document.scrollingElement;
      const scrollTop = scroller instanceof HTMLElement ? scroller.scrollTop : 0;
      const top = element.getBoundingClientRect().top + scrollTop;
      setCanvasHeight(Math.max(320, Math.floor(window.innerHeight - top - 16)));
    };
    update();
    window.addEventListener("resize", update);
    diagramRowObserver.current = () => window.removeEventListener("resize", update);
  }, []);

  const [editMode, setEditMode] = useState(false);
  const [editError, setEditError] = useState<string | null>(null);
  const [boundaryDraft, setBoundaryDraft] = useState("");
  const [showMinimap, setShowMinimap] = useState(() => {
    try {
      return localStorage.getItem("kresheen-minimap") === "true";
    } catch {
      return false;
    }
  });
  const notAnalysed = unanalysedSources(run?.source_results);
  const partlyAnalysed = partlyAnalysedSources(run?.source_results);
  const isBlankModel = run !== null && (run.data_source_config_ids ?? []).length === 0;
  const [propertySpecs, setPropertySpecs] = useState<Record<string, PropertySpec[]>>({});
  const [nameDraft, setNameDraft] = useState("");
  const [edgeLabelDraft, setEdgeLabelDraft] = useState("");
  const [edgeToDelete, setEdgeToDelete] = useState<DfdEdge | null>(null);
  const [componentToDelete, setComponentToDelete] = useState<DfdNode | null>(null);

  // Diagrams: every Application always has at least one (the server
  // auto-creates "Main" on first request). `activeDiagramId` starts null
  // until loadDiagrams() resolves it to the first diagram, so the very
  // first DFD fetch below omits diagram_id and lets the server pick the
  // default -- both resolve to the same diagram, so there's no mismatch.
  const [diagrams, setDiagrams] = useState<DiagramOut[]>([]);
  const [activeDiagramId, setActiveDiagramId] = useState<string | null>(null);
  const [diagramNameDraft, setDiagramNameDraft] = useState("");
  const [renamingDiagram, setRenamingDiagram] = useState(false);
  const [addingDiagram, setAddingDiagram] = useState(false);
  const [hiddenLayout, setHiddenLayout] = useState<DiagramElementLayoutOut[]>([]);
  const [showHiddenPanel, setShowHiddenPanel] = useState(false);
  // The element hidden most recently, so an accidental click is one click to reverse without leaving the view.
  const [threatPreset, setThreatPreset] = useState<{ name: string; nonce: number } | null>(null);
  const [actionPlan, setActionPlan] = useState<ActionPlanOut | null>(null);
  const [justHidden, setJustHidden] = useState<{ key: string; label: string } | null>(null);

  // Drag-and-drop placement (Process/Data Store/External Entity): dragging
  // one of the toolbar buttons onto the canvas is the whole interaction --
  // no separate "arm the tool" click needed, since the drag itself already
  // says which type is being placed.
  const [pendingPlacement, setPendingPlacement] = useState<PendingPlacement | null>(null);
  const [pendingPlacementName, setPendingPlacementName] = useState("");
  const submittedPlacementRef = useRef<PendingPlacement | null>(null);

  // Trust boundary tool: click to arm (toggle), then drag a selection box
  // around existing nodes; a name prompt appears reactively as soon as
  // something is selected while the tool is armed, rather than trying to
  // hook a precise "drag finished" event.
  const [boundaryToolActive, setBoundaryToolActive] = useState(false);
  const [selectedBoundaryNodeIds, setSelectedBoundaryNodeIds] = useState<string[]>([]);
  const [boundaryNameDraft, setBoundaryNameDraft] = useState("");

  // Undo/redo (Ctrl-Z / Ctrl-Shift-Z / Ctrl-Y in edit mode). See
  // useEditHistory.ts: history holds inverse API calls, in memory only, and
  // resets on page load or when switching Application.
  // The hide banner belongs to one diagram.
  useEffect(() => setJustHidden(null), [activeDiagramId]);
  const api = dfdEditApi(applicationId ?? "", activeDiagramId ?? "");
  const history = useEditHistory({
    onError: setEditError,
    onSettled: () => Promise.all([loadRun(), loadHiddenLayout()]),
  });
  // Pre-drag canvas positions and the saved boundary origins as of the last
  // load/drag, so a drag can be recorded as a reversible move.
  const dragStartRef = useRef<Record<string, { x: number; y: number }>>({});
  const boundaryLayoutsRef = useRef<Record<string, { x: number; y: number }>>({});
  const editModeRef = useRef(false);
  editModeRef.current = editMode;

  // Lays out and draws the last loaded DFD. `show` is the user's choice about configuration objects
  // (ConfigMap, Secret, PersistentVolumeClaim); null = automatic: fold them away on a busy diagram, since
  // they bury the workloads. They stay in the model, the threats and the reports either way.
  function renderDfd(show: boolean | null) {
    const snapshot = dfdSnapshotRef.current;
    if (!snapshot) return;
    const configCount = snapshot.nodes.filter(isConfigObject).length;
    const showConfig = show ?? !(configCount > 0 && snapshot.nodes.length >= 10);
    const visible = showConfig ? snapshot.nodes : snapshot.nodes.filter((node) => !isConfigObject(node));
    const visibleIds = new Set(visible.map((node) => node.id));
    const boundedIds = new Set(visible.filter((node) => node.trust_boundary).map((node) => node.id));
    setConfigObjects({ count: configCount, shown: showConfig });
    setNodes(layoutNodes(visible, snapshot.dfd.boundaries ?? [], editModeRef.current, snapshot.dfd.edges));
    setEdges(
      snapshot.dfd.edges
        .filter((edge) => visibleIds.has(edge.source) && visibleIds.has(edge.target))
        .map((edge) => ({
          id: edge.id,
          source: edge.source,
          target: edge.target,
          label: edge.label ?? undefined,
          data: { isManual: edge.is_manual, properties: edge.properties ?? {} },
          type: "smoothstep",
          // A flow between two components inside boundaries is drawn above the boundary boxes already; one
          // with an end outside every boundary was drawn underneath them and could not be seen.
          zIndex: boundedIds.has(edge.source) && boundedIds.has(edge.target) ? undefined : 1,
          style: {
            stroke: edge.is_manual ? "#6c757d" : "var(--pc-muted)",
            strokeDasharray: edge.is_manual ? "4 3" : undefined,
            opacity: isOutOfScope(edge.properties) ? 0.4 : 1,
          },
          labelBgPadding: [4, 2],
          labelBgBorderRadius: 4,
          labelBgStyle: { fill: "var(--pc-panel)" },
          labelStyle: { fill: "var(--bs-body-color)", fontSize: 11 },
        })),
    );
  }

  function loadRun() {
    if (!applicationId || !runId) return;
    const dfdUrl = activeDiagramId
      ? `/api/applications/${applicationId}/runs/${runId}/dfd?diagram_id=${encodeURIComponent(activeDiagramId)}`
      : `/api/applications/${applicationId}/runs/${runId}/dfd`;
    return Promise.all([
      apiFetch<RunOut>(`/api/applications/${applicationId}/runs/${runId}`),
      apiFetch<DfdOut>(dfdUrl),
      apiFetch<FindingOut[]>(`/api/applications/${applicationId}/runs/${runId}/findings`),
      apiFetch<SbomOut | null>(`/api/applications/${applicationId}/runs/${runId}/sbom`),
      apiFetch<ThreatsOut>(`/api/applications/${applicationId}/runs/${runId}/threats`),
    ])
      .then(([runData, dfd, findingsData, sbomData, threats]) => {
        setRun(runData);
        boundaryLayoutsRef.current = Object.fromEntries(
          (dfd.boundaries ?? []).map((b) => [b.name, { x: b.position_x, y: b.position_y }]),
        );
        const dfdNodes = dfd.nodes.map((node) => ({ ...node, ...openThreatSignal(node.id, threats.threats) }));
        dfdSnapshotRef.current = { nodes: dfdNodes, dfd };
        renderDfd(showConfigRef.current);
        setNodesById(Object.fromEntries(dfdNodes.map((node) => [node.id, node])));
        setEdgesForThreats(dfd.edges);
        setFindings(findingsData);
        setSbom(sbomData);
        setThreatsData(threats);
      })
      .catch((error: unknown) => {
        if (error instanceof ApiError && error.status === 404) setNotFound(true);
        else setLoadError("Failed to load this threat model run.");
      });
  }

  // Application-scoped (not run-scoped): the run-history dropdown and the
  // staleness banner both need to reflect a re-run or a data-source change
  // immediately, so this is re-fetched whenever runId changes too, not just
  // applicationId.
  function loadRunsAndStaleness() {
    if (!applicationId) return;
    return Promise.all([
      apiFetch<RunHistoryEntry[]>(`/api/applications/${applicationId}/runs`),
      apiFetch<StalenessOut>(`/api/applications/${applicationId}/staleness`),
    ])
      .then(([runsData, stalenessData]) => {
        setRuns(runsData);
        setStaleness(stalenessData);
      })
      .catch(() => {
        // Best-effort: a failure here shouldn't block the rest of the page.
      });
  }

  // Every Application always has at least one diagram (the server
  // auto-creates "Main" on first request, see engine/dfd/diagrams.py).
  // Keeps the currently-active selection if it's still in the list
  // (e.g. after a rename); otherwise defaults to the first diagram.
  function loadDiagrams() {
    if (!applicationId) return;
    return apiFetch<DiagramOut[]>(`/api/applications/${applicationId}/diagrams`).then((list) => {
      setDiagrams(list);
      setActiveDiagramId((current) =>
        current && list.some((d) => d.id === current) ? current : (list[0]?.id ?? null),
      );
    });
  }

  // Every saved layout row on the active diagram that's currently hidden --
  // unlike the DFD itself, this doesn't get filtered out, so a hidden
  // component/flow/boundary can still be found and shown again.
  function loadHiddenLayout() {
    if (!applicationId || !activeDiagramId) {
      setHiddenLayout([]);
      return;
    }
    return apiFetch<DiagramElementLayoutOut[]>(`/api/applications/${applicationId}/diagrams/${activeDiagramId}/layout`)
      .then((rows) => setHiddenLayout(rows.filter((row) => row.hidden)))
      .catch(() => setHiddenLayout([]));
  }

  function loadDiff() {
    if (!applicationId || !runId) return;
    return apiFetch<RunDiffOut>(`/api/applications/${applicationId}/runs/${runId}/diff`)
      .then(setDiff)
      .catch(() => setDiff(null));
  }

  function loadAttackPaths() {
    if (!applicationId || !runId) return;
    return apiFetch<{ paths: AttackPathOut[] }>(`/api/applications/${applicationId}/runs/${runId}/attack-paths`)
      .then((out) => setAttackPaths(out.paths))
      .catch(() => setAttackPaths(null));
  }

  async function handleReRun() {
    if (!applicationId) return;
    setReRunning(true);
    setReRunError(null);
    try {
      const newRun = await apiFetch<RunOut>(`/api/applications/${applicationId}/runs`, { method: "POST" });
      navigate(`/applications/${applicationId}/runs/${newRun.id}`);
    } catch (err) {
      setReRunError(err instanceof ApiError ? err.message : "Failed to re-run the threat model.");
    } finally {
      setReRunning(false);
    }
  }

  useEffect(() => {
    renderDfd(showConfigObjects);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [showConfigObjects]);

  // Persist minimap preference to localStorage
  useEffect(() => {
    try {
      localStorage.setItem("kresheen-minimap", showMinimap ? "true" : "false");
    } catch {
      // localStorage may be unavailable; ignore
    }
  }, [showMinimap]);

  // A status change (mitigated/accepted) reloads only the threat list, so
  // refresh each node's threat count and colour from it.
  useEffect(() => {
    if (!threatsData) return;
    setNodesById((prev) =>
      Object.fromEntries(
        Object.entries(prev).map(([id, node]) => [id, { ...node, ...openThreatSignal(id, threatsData.threats) }]),
      ),
    );
    setNodes((prev) =>
      prev.map((flowNode) => {
        const signal = openThreatSignal(flowNode.id, threatsData.threats);
        const known = nodesByIdRef.current[flowNode.id];
        if (!known) return flowNode;
        const updated = { ...known, ...signal };
        return {
          ...flowNode,
          data: { ...flowNode.data, label: nodeLabel(updated) },
          style: { ...flowNode.style, background: nodeBackground(updated) },
        };
      }),
    );
  }, [threatsData, setNodes]);

  // Threats are derived from the DFD, so they need refetching after any edit
  // that changes it (loadRun) as well as after a status change (this).
  function reloadThreats() {
    if (!applicationId || !runId) return;
    return apiFetch<ThreatsOut>(`/api/applications/${applicationId}/runs/${runId}/threats`)
      .then(setThreatsData)
      .catch(() => setEditError("Failed to refresh threats."));
  }

  // Everything a threat can be attached to: components, then data flows
  // labeled "source -> target" (the same form the generated threats use).
  function threatElementChoices(): ElementChoice[] {
    const components: ElementChoice[] = Object.values(nodesById).map((node) => ({
      kind: "component",
      id: node.id,
      label: node.name,
    }));
    const flows: ElementChoice[] = edgesForThreats
      .filter((edge) => edge.label !== "discovered_in" && nodesById[edge.source] && nodesById[edge.target])
      .map((edge) => ({
        kind: "flow",
        id: edge.id,
        label: `${nodesById[edge.source].name} -> ${nodesById[edge.target].name}`,
      }));
    return [...components, ...flows];
  }

  useEffect(() => {
    apiFetch<Record<string, PropertySpec[]>>("/api/threat-kb/property-specs")
      .then(setPropertySpecs)
      .catch(() => setPropertySpecs({}));
  }, []);

  useEffect(() => {
    void loadRun();
    void loadDiff();
    void loadAttackPaths();
    void loadRunsAndStaleness();
    void loadDiagrams();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [applicationId, runId]);

  // Re-fetches the DFD (and its hidden-element list) for whichever diagram
  // is now active -- fires once more on the very first load too, once
  // loadDiagrams() resolves activeDiagramId from null to the default
  // diagram's id, which is harmless (same diagram the initial diagram_id-
  // less fetch above already resolved server-side).
  useEffect(() => {
    void loadRun();
    void loadHiddenLayout();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeDiagramId]);

  useEffect(() => {
    history.clear();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [applicationId]);

  // Boundary boxes are only draggable in edit mode: a drag persists, and
  // every other persisted edit is likewise gated behind edit mode.
  useEffect(() => {
    setNodes((current) => current.map((n) => (n.type === "boundary" ? { ...n, draggable: editMode } : n)));
  }, [editMode, setNodes]);

  const dialogOpen =
    selectedNode !== null ||
    componentToDelete !== null ||
    edgeToDelete !== null ||
    pendingPlacement !== null ||
    addThreat.open;
  const { undo, redo } = history;
  useEffect(() => {
    if (!editMode) return;
    function onKeyDown(event: KeyboardEvent) {
      // Native text-field undo wins inside inputs; dialogs own the keyboard.
      if (isTextEntryTarget(event.target) || dialogOpen) return;
      if (!(event.ctrlKey || event.metaKey)) return;
      const key = event.key.toLowerCase();
      if (key === "z" && !event.shiftKey) {
        event.preventDefault();
        void undo();
      } else if ((key === "z" && event.shiftKey) || key === "y") {
        event.preventDefault();
        void redo();
      }
    }
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [editMode, dialogOpen, undo, redo]);

  function handleNodeClick(_event: unknown, node: Node) {
    setEditError(null);
    const found = nodesById[node.id] ?? null;
    setSelectedNode(found);
    setBoundaryDraft(found?.trust_boundary ?? "");
    setNameDraft(found?.name ?? "");
    // Highlight the clicked node via React Flow's own selection;
    // see the ".react-flow__node.selected" rule in theme.css.
    setNodes((current) => current.map((n) => ({ ...n, selected: n.id === node.id })));
  }

  // Closes the element inspector and clears the canvas highlight -- used by
  // the inspector's close button/Escape, a click on empty canvas, and the
  // "View all threats for this element" button.
  function closeInspector() {
    setSelectedNode(null);
    setNodes((current) => current.map((n) => (n.selected ? { ...n, selected: false } : n)));
  }

  function handleEdgeClick(_event: unknown, edge: Edge) {
    if (!editMode) return;
    const dfdEdge = edges.find((e) => e.id === edge.id);
    const data = dfdEdge?.data as { isManual?: boolean; properties?: ElementProperties } | undefined;
    setEdgeLabelDraft(typeof edge.label === "string" ? edge.label : "");
    setEdgeToDelete({
      id: edge.id,
      source: edge.source,
      target: edge.target,
      label: typeof edge.label === "string" ? edge.label : null,
      is_manual: data?.isManual === true,
      properties: data?.properties ?? {},
    });
  }

  async function handleSaveProperties(kind: "component" | "flow", elementId: string, properties: ElementProperties) {
    if (!applicationId || !runId) return;
    setEditError(null);
    try {
      await apiFetch(`/api/applications/${applicationId}/runs/${runId}/element-properties`, {
        method: "PUT",
        body: JSON.stringify({ element_kind: kind, element_id: elementId, properties }),
      });
      setSelectedNode(null);
      setEdgeToDelete(null);
      await loadRun();
    } catch (err) {
      setEditError(err instanceof ApiError ? err.message : "Failed to save the properties.");
    }
  }

  // Applies a boundary label (or clears it, next=null) to one or more
  // components as a single undoable step -- a drag-select over N components
  // is N PUTs but one Ctrl-Z. `prev` is the user override before the edit,
  // or null if the label was auto-derived / absent, so undo restores exactly
  // that state rather than freezing a derived label into an override.
  async function applyBoundaryChanges(
    changes: { name: string; prev: string | null; next: string | null }[],
    label: string,
  ) {
    await Promise.all(changes.map((c) => api.restoreBoundary(c.name, c.next)));
    history.record({
      label,
      undo: async () => {
        await Promise.all(changes.map((c) => api.restoreBoundary(c.name, c.prev)));
      },
      redo: async () => {
        await Promise.all(changes.map((c) => api.restoreBoundary(c.name, c.next)));
      },
    });
  }

  function boundaryChangeFor(node: DfdNode, next: string | null) {
    return { name: node.name, prev: node.boundary_overridden ? node.trust_boundary : null, next };
  }

  async function handleSaveBoundary() {
    if (!applicationId || !selectedNode) return;
    setEditError(null);
    const next = boundaryDraft.trim() || null;
    try {
      // Clearing a label that was never overridden is a no-op, not history.
      if (next !== null || selectedNode.boundary_overridden) {
        await applyBoundaryChanges(
          [boundaryChangeFor(selectedNode, next)],
          next ? `Set trust boundary on ${selectedNode.name}` : `Clear trust boundary on ${selectedNode.name}`,
        );
      }
      setSelectedNode(null);
      await loadRun();
    } catch (err) {
      setEditError(err instanceof ApiError ? err.message : "Failed to save the trust boundary.");
    }
  }

  async function handleConfirmDeleteComponent() {
    if (!applicationId || !componentToDelete) return;
    setEditError(null);
    const snapshot = componentToDelete;
    try {
      await api.deleteManualAsset(snapshot.id);
      // Undo re-creates the row under its ORIGINAL id: manual flows reference
      // it as "asset:<id>" and boundary assignments are keyed by name, and
      // neither is deleted with the asset, so restoring the id alone
      // re-attaches both.
      history.record({
        label: `Delete ${snapshot.name}`,
        undo: async () => {
          await api.createManualAsset({
            id: snapshot.id,
            name: snapshot.name,
            type: snapshot.type,
            // A component from the guided intake carries its boundary on the row itself; an owner
            // override is a separate name-keyed record that survives the delete.
            trust_boundary: snapshot.boundary_overridden ? null : snapshot.trust_boundary,
            position_x: snapshot.position_x,
            position_y: snapshot.position_y,
          });
        },
        redo: () => api.deleteManualAsset(snapshot.id),
      });
      setComponentToDelete(null);
      setSelectedNode(null);
      await loadRun();
    } catch (err) {
      setEditError(err instanceof ApiError ? err.message : "Failed to delete this component.");
      setComponentToDelete(null);
    }
  }

  // -- Diagram visibility (hide/show a component, connection or boundary on
  // just this diagram) --

  function isHiddenHere(key: string) {
    return hiddenLayout.some((row) => row.element_key === key && row.hidden);
  }

  async function handleHideElement(elementKey: string, label: string) {
    setEditError(null);
    try {
      await api.setHidden(elementKey, true);
      history.record({
        label: `Hide ${label} on this diagram`,
        undo: () => api.setHidden(elementKey, false),
        redo: () => api.setHidden(elementKey, true),
      });
      setJustHidden({ key: elementKey, label });
      await Promise.all([loadRun(), loadHiddenLayout()]);
    } catch (err) {
      setEditError(err instanceof ApiError ? err.message : "Failed to hide this element.");
    }
  }

  async function handleShowElement(elementKey: string, label: string) {
    setEditError(null);
    setJustHidden((prev) => (prev?.key === elementKey ? null : prev));
    try {
      await api.setHidden(elementKey, false);
      history.record({
        label: `Show ${label} on this diagram`,
        undo: () => api.setHidden(elementKey, true),
        redo: () => api.setHidden(elementKey, false),
      });
      await Promise.all([loadRun(), loadHiddenLayout()]);
    } catch (err) {
      setEditError(err instanceof ApiError ? err.message : "Failed to show this element.");
    }
  }

  // -- Diagrams (switch, create, rename, delete) ----------------------------

  async function handleCreateDiagram() {
    if (!applicationId || !diagramNameDraft.trim()) return;
    setEditError(null);
    try {
      const created = await apiFetch<DiagramOut>(`/api/applications/${applicationId}/diagrams`, {
        method: "POST",
        body: JSON.stringify({ name: diagramNameDraft.trim() }),
      });
      setDiagramNameDraft("");
      setAddingDiagram(false);
      await loadDiagrams();
      setActiveDiagramId(created.id);
    } catch (err) {
      setEditError(err instanceof ApiError ? err.message : "Failed to create that diagram.");
    }
  }

  async function handleRenameDiagram() {
    if (!applicationId || !activeDiagramId || !diagramNameDraft.trim()) return;
    setEditError(null);
    try {
      await apiFetch(`/api/applications/${applicationId}/diagrams/${activeDiagramId}`, {
        method: "PATCH",
        body: JSON.stringify({ name: diagramNameDraft.trim() }),
      });
      setRenamingDiagram(false);
      await loadDiagrams();
    } catch (err) {
      setEditError(err instanceof ApiError ? err.message : "Failed to rename that diagram.");
    }
  }

  async function handleDeleteDiagram(diagramId: string) {
    if (!applicationId) return;
    setEditError(null);
    try {
      await apiFetch(`/api/applications/${applicationId}/diagrams/${diagramId}`, { method: "DELETE" });
      setActiveDiagramId(null);
      await loadDiagrams();
    } catch (err) {
      setEditError(err instanceof ApiError ? err.message : "Can't delete that diagram.");
    }
  }

  // -- Drag-and-drop component placement -----------------------------------

  function handlePaletteDragStart(event: React.DragEvent, type: AssetTypeValue) {
    event.dataTransfer.setData(PLACEMENT_DRAG_TYPE, type);
    event.dataTransfer.effectAllowed = "copy";
  }

  function handleCanvasDragOver(event: React.DragEvent) {
    if (event.dataTransfer.types.includes(PLACEMENT_DRAG_TYPE)) {
      event.preventDefault();
      event.dataTransfer.dropEffect = "copy";
    }
  }

  function handleCanvasDrop(event: React.DragEvent) {
    const type = event.dataTransfer.getData(PLACEMENT_DRAG_TYPE) as AssetTypeValue | "";
    if (!type || !reactFlowInstance || !dfdContainerRef.current) return;
    event.preventDefault();

    const flowPosition = reactFlowInstance.screenToFlowPosition({ x: event.clientX, y: event.clientY });
    const containerRect = dfdContainerRef.current.getBoundingClientRect();

    setEditError(null);
    setPendingPlacement({
      type,
      flowX: flowPosition.x,
      flowY: flowPosition.y,
      screenX: event.clientX - containerRect.left,
      screenY: event.clientY - containerRect.top,
    });
    setPendingPlacementName("");
  }

  async function handleConfirmPlacement() {
    if (!applicationId || !pendingPlacement || !pendingPlacementName.trim()) {
      setPendingPlacement(null);
      return;
    }
    // Enter, the Add button and the input's delayed blur handler (a stale
    // closure over this same placement) can all fire for one placement while
    // the create is still in flight; only the first may create the component.
    if (submittedPlacementRef.current === pendingPlacement) return;
    submittedPlacementRef.current = pendingPlacement;
    setEditError(null);
    const spec = {
      name: pendingPlacementName.trim(),
      type: pendingPlacement.type,
      position_x: pendingPlacement.flowX,
      position_y: pendingPlacement.flowY,
    };
    try {
      const created = await api.createManualAsset(spec);
      history.record({
        label: `Add ${spec.name}`,
        undo: () => api.deleteManualAsset(created.id),
        redo: async () => {
          await api.createManualAsset({ ...spec, id: created.id });
        },
      });
      setPendingPlacement(null);
      setPendingPlacementName("");
      await loadRun();
    } catch (err) {
      setEditError(err instanceof ApiError ? err.message : "Failed to add the component.");
      setPendingPlacement(null);
    }
  }

  // -- Trust boundary drag-to-select ----------------------------------------

  const handleSelectionChange: OnSelectionChangeFunc = ({ nodes: selected }) => {
    if (!boundaryToolActive) return;
    // Only real components count -- exclude the synthetic boundary group
    // containers themselves (a boundary can't contain another boundary in
    // this v1) and anything not backed by an actual DfdNode.
    const ids = selected.map((n) => n.id).filter((id) => nodesById[id] !== undefined);
    // Keep the same array when nothing changed: React Flow re-fires onSelectionChange whenever this callback's identity
    // changes (every render), so setting a fresh array each time re-rendered forever (React error #185, a blank page,
    // as soon as the Trust Boundary tool was armed).
    setSelectedBoundaryNodeIds((prev) =>
      prev.length === ids.length && prev.every((id, i) => id === ids[i]) ? prev : ids,
    );
  };

  function handleToggleBoundaryTool() {
    setBoundaryToolActive((prev) => !prev);
    setSelectedBoundaryNodeIds([]);
    setBoundaryNameDraft("");
  }

  function clearBoundarySelection() {
    setSelectedBoundaryNodeIds([]);
    setBoundaryNameDraft("");
    setNodes((current) => current.map((n) => (n.selected ? { ...n, selected: false } : n)));
  }

  async function handleApplyBoundaryName() {
    if (!applicationId || !boundaryNameDraft.trim() || selectedBoundaryNodeIds.length === 0) return;
    setEditError(null);
    const label = boundaryNameDraft.trim();
    try {
      // Keyed by name: two nodes can share one, and the override is per name.
      const changes = new Map<string, { name: string; prev: string | null; next: string | null }>();
      for (const id of selectedBoundaryNodeIds) {
        const dfdNode = nodesById[id];
        if (dfdNode && !changes.has(dfdNode.name)) changes.set(dfdNode.name, boundaryChangeFor(dfdNode, label));
      }
      await applyBoundaryChanges([...changes.values()], `Group into "${label}"`);
      clearBoundarySelection();
      await loadRun();
      // Stays armed (sticky) -- the user can draw another box for a
      // different boundary right away without re-clicking the tool.
    } catch (err) {
      setEditError(err instanceof ApiError ? err.message : "Failed to save that trust boundary.");
    }
  }

  // Building the connection's ref strings client-side (rather than the
  // backend inferring them) keeps the tagging convention -- "asset:<id>"
  // for a manual component (stable forever), "name:<component name>" for
  // an auto-generated one (resolved fresh against whichever run is being
  // viewed, since its id isn't stable across runs) -- in exactly one place
  // per side of the connection, driven by data this component already has
  // (`nodesById[...].is_manual`). See models/manual_flow.py's docstring.
  function toRef(id: string): string {
    const node = nodesById[id];
    return node?.is_manual ? `asset:${id}` : `name:${node?.name ?? id}`;
  }

  async function handleConnect(connection: Connection) {
    if (!applicationId || !connection.source || !connection.target) return;
    setEditError(null);
    const spec = { source_ref: toRef(connection.source), target_ref: toRef(connection.target) };
    try {
      const created = await api.createManualFlow(spec);
      history.record({
        label: "Add connection",
        undo: () => api.deleteManualFlow(created.id),
        redo: async () => {
          await api.createManualFlow({ ...spec, id: created.id });
        },
      });
      await loadRun();
    } catch (err) {
      setEditError(err instanceof ApiError ? err.message : "Failed to create that connection.");
    }
  }

  // Rename and label edits are their own inverse, so each is one undo step.
  async function handleRenameComponent() {
    if (!applicationId || !selectedNode) return;
    const from = selectedNode.name;
    const to = nameDraft.trim();
    if (!to || to === from) return;
    setEditError(null);
    const id = selectedNode.id;
    try {
      await api.renameManualAsset(id, to);
      history.record({
        label: `Rename ${from}`,
        undo: () => api.renameManualAsset(id, from),
        redo: () => api.renameManualAsset(id, to),
      });
      setSelectedNode(null);
      await loadRun();
    } catch (err) {
      setEditError(err instanceof ApiError ? err.message : "Failed to rename this component.");
    }
  }

  async function handleSaveEdgeLabel() {
    if (!applicationId || !edgeToDelete) return;
    const flow = edgeToDelete;
    const from = flow.label ?? "";
    const to = edgeLabelDraft.trim();
    if (to === from) {
      setEdgeToDelete(null);
      return;
    }
    setEditError(null);
    try {
      await api.updateManualFlowLabel(flow.id, to);
      history.record({
        label: "Edit connection label",
        undo: () => api.updateManualFlowLabel(flow.id, from),
        redo: () => api.updateManualFlowLabel(flow.id, to),
      });
      setEdgeToDelete(null);
      await loadRun();
    } catch (err) {
      setEditError(err instanceof ApiError ? err.message : "Failed to edit that connection.");
      setEdgeToDelete(null);
    }
  }

  async function handleConfirmDeleteEdge() {
    if (!applicationId || !edgeToDelete) return;
    const flow = edgeToDelete;
    const spec = { id: flow.id, source_ref: toRef(flow.source), target_ref: toRef(flow.target), label: flow.label };
    try {
      await api.deleteManualFlow(flow.id);
      history.record({
        label: "Remove connection",
        undo: async () => {
          await api.createManualFlow(spec);
        },
        redo: () => api.deleteManualFlow(flow.id),
      });
      setEdgeToDelete(null);
      await loadRun();
    } catch (err) {
      setEditError(err instanceof ApiError ? err.message : "Failed to delete that connection.");
      setEdgeToDelete(null);
    }
  }

  // -- Dragging: trust-boundary boxes and manually-placed components --------

  function handleNodeDragStart(_event: unknown, node: Node) {
    dragStartRef.current[node.id] = { x: node.position.x, y: node.position.y };
  }

  // Only edit mode persists a move. Auto-generated components stay
  // local-only (their ids change every run, so a saved position would be
  // orphaned); children of a boundary are laid out relative to the group.
  async function handleNodeDragStop(_event: unknown, node: Node) {
    const start = dragStartRef.current[node.id];
    delete dragStartRef.current[node.id];
    if (!editMode || !applicationId || !start) return;
    const end = { x: node.position.x, y: node.position.y };
    if (start.x === end.x && start.y === end.y) return;

    try {
      if (node.type === "boundary") {
        const name = (node.data as { label: string }).label;
        const key = `boundary:${name}`;
        // null = never moved on this diagram, so undo clears the override
        // and falls back to the auto-stacked spot.
        const prev = boundaryLayoutsRef.current[name] ?? null;
        await api.moveElement(key, end.x, end.y);
        boundaryLayoutsRef.current[name] = end;
        history.record({
          label: `Move boundary ${name}`,
          undo: () => api.restoreElementPosition(key, prev),
          redo: () => api.moveElement(key, end.x, end.y),
        });
        return;
      }
      const dfdNode = nodesById[node.id];
      if (!dfdNode?.is_manual || node.parentId) return;
      const key = `${dfdNode.type}:${dfdNode.name}`;
      await api.moveElement(key, end.x, end.y);
      // Keep the snapshot delete-undo re-creates from in step with the move.
      setNodesById((prev) => ({ ...prev, [node.id]: { ...prev[node.id], position_x: end.x, position_y: end.y } }));
      history.record({
        label: `Move ${dfdNode.name}`,
        undo: () => api.moveElement(key, start.x, start.y),
        redo: () => api.moveElement(key, end.x, end.y),
      });
    } catch (err) {
      setEditError(err instanceof ApiError ? err.message : "Failed to save that move.");
      await loadRun();
    }
  }

  // Every tab's content stays mounted (visibility toggles with CSS, see the
  // render below) so the panels that feed the stat strip and Overview keep
  // their data current no matter which tab is active -- the same thing the
  // old accordion gave for free (react-bootstrap keeps every Accordion.Body
  // mounted regardless of which one is expanded). The one exception React
  // Flow itself still needs: its own resize detection isn't reliable for a
  // container that starts hidden and later becomes visible again, so
  // re-calling fitView() when the Diagram tab (re-)activates is what
  // actually keeps the diagram framed correctly -- CSS/layout alone doesn't
  // guarantee it.
  useEffect(() => {
    if (activeTab === "diagram" && reactFlowInstance) {
      requestAnimationFrame(() => reactFlowInstance.fitView(FIT_VIEW_OPTIONS));
    }
  }, [activeTab, reactFlowInstance]);

  function switchTab(next: string) {
    if (!applicationId || !runId) return;
    navigate(`/applications/${applicationId}/runs/${runId}/${next}`, { replace: true });
  }

  if (notFound) {
    return (
      <div className="pc-page-narrow" data-testid="model-not-found">
        <p>This threat model does not exist or you do not have access to it.</p>
        <Link to="/applications">Back to Threat models</Link>
      </div>
    );
  }
  if (loadError) return <div className="pc-page-narrow">{loadError}</div>;
  if (!run) return <div className="pc-page-narrow">Loading...</div>;

  if (run.status !== "completed") {
    const failed = run.status === "failed";
    const lastCompleted = [...(runs ?? [])].reverse().find((entry) => entry.status === "completed");
    return (
      <div className="pc-page-narrow" data-testid={failed ? "failed-run" : "unfinished-run"}>
        <p className="mb-2">
          <Link to="/applications">Back to Threat models</Link>
        </p>
        <h1 className="h4 mb-3">Threat model run</h1>
        {failed ? (
          <>
            <Alert variant="danger" role="alert">
              <p className="fw-semibold mb-1">This run could not finish.</p>
              {run.error_message && <p className="mb-0">{run.error_message}</p>}
            </Alert>
            <p>Fix or remove the data source below, then run again.</p>
            <div className="d-flex flex-wrap align-items-center gap-3 mb-3">
              <Button variant="primary" disabled={reRunning} onClick={() => void handleReRun()}>
                {reRunning ? "Running..." : "Run again"}
              </Button>
              {lastCompleted && (
                <Link to={`/applications/${applicationId}/runs/${lastCompleted.id}`}>
                  Back to the last completed run
                </Link>
              )}
            </div>
            {reRunError && <Alert variant="danger">{reRunError}</Alert>}
            {applicationId && (
              <DataSourcesPanel
                applicationId={applicationId}
                onChanged={loadRunsAndStaleness}
                sourceResults={run.source_results}
              />
            )}
          </>
        ) : (
          <Alert variant="info">
            This run is {run.status === "queued" ? "waiting to start" : "in progress"}. Reload the page to check again.
          </Alert>
        )}
      </div>
    );
  }

  const componentCount = Object.keys(nodesById).length;
  const totalThreats = threatsData?.summary.total ?? 0;
  const openThreatsCount = threatsData?.summary.by_status.open ?? 0;
  const openByRisk = threatsData?.summary.open_by_risk ?? {};
  const highCriticalOpen = (openByRisk.critical ?? 0) + (openByRisk.high ?? 0);
  const addressedCount = totalThreats - openThreatsCount;
  const addressedPct = totalThreats ? Math.round((100 * addressedCount) / totalThreats) : 0;
  const openActions = openActionCount ?? 0;

  function toneForPct(pct: number): string {
    if (pct >= 75) return "good";
    if (pct >= 40) return "warn";
    return "critical";
  }

  // The stat strip: 6 compact tiles, each naming its unit, each a
  // shortcut to the tab that explains the number.
  const statItems: StatStripItem[] = [
    {
      key: "open-threats",
      label: "Open threats",
      value: String(openThreatsCount),
      tone: openThreatsCount ? "accent2" : "good",
      onClick: () => switchTab("threats"),
    },
    {
      key: "high-critical",
      label: "High + critical open",
      value: String(highCriticalOpen),
      tone: highCriticalOpen ? "critical" : "good",
      onClick: () => switchTab("threats"),
    },
    {
      key: "addressed",
      label: "Addressed",
      value: totalThreats ? `${addressedPct}%` : "—",
      tone: totalThreats ? toneForPct(addressedPct) : "accent",
      onClick: () => switchTab("threats"),
    },
    {
      key: "completeness",
      label: "Completeness",
      value: completeness?.score != null ? `${completeness.score}%` : "—",
      tone: completeness?.score == null ? "accent" : toneForPct(completeness.score),
      onClick: () => switchTab("overview"),
    },
    {
      key: "actions-todo",
      label: "Actions to do",
      value: String(openActions),
      tone: openActions ? "warn" : "good",
      onClick: () => switchTab("actions"),
    },
    {
      key: "findings",
      label: "Findings",
      value: String(findings.length),
      tone: findings.length ? "accent2" : "good",
      onClick: () => switchTab("findings"),
    },
  ];

  const headerActions = applicationId && runId && (
    <div className="d-flex align-items-center gap-2">
      {runs && runs.length > 0 && <RunHistory applicationId={applicationId} currentRunId={runId} runs={runs} />}
      <Button size="sm" variant="outline-primary" disabled={reRunning} onClick={() => void handleReRun()}>
        {reRunning ? "Re-running..." : "Re-run"}
      </Button>
      <ReviewStamp applicationId={applicationId} />
      <ExportMenu applicationId={applicationId} runId={runId} diagramRef={dfdContainerRef} />
      {extensions.runHeaderActions.map((action) => (
        <span key={action.id}>{action.render({ applicationId, runId })}</span>
      ))}
    </div>
  );

  return (
    <div className="pc-page">
      {applicationId && (
        <ModelHeader applicationId={applicationId} actions={headerActions} compact={activeTab === "diagram"} />
      )}
      {reRunError && (
        <Alert variant="danger" className="mb-2" onClose={() => setReRunError(null)} dismissible>
          {reRunError}
        </Alert>
      )}
      {notAnalysed.length > 0 && (
        <Alert variant="warning" className="mb-2" data-testid="not-analysed-banner">
          <strong>
            {notAnalysed.length} of {run?.source_results?.length ?? 0} input
            {(run?.source_results?.length ?? 0) === 1 ? "" : "s"} {notAnalysed.length === 1 ? "was" : "were"} stored but
            not analysed.
          </strong>{" "}
          Threats below come only from what was analysed or drawn by hand, so a low count is not a clean result.
          <ul className="mb-0 mt-1">
            {notAnalysed.map((result) => (
              <li key={result.data_source_id}>
                <strong>{SOURCE_TYPE_LABELS[result.type] ?? result.type}:</strong> {result.message}
              </li>
            ))}
          </ul>
        </Alert>
      )}
      {partlyAnalysed.length > 0 && (
        <Alert variant="warning" className="mb-2" data-testid="partly-analysed-banner">
          <strong>Part of an input was not analysed, so this result is incomplete.</strong> A short list below, or "no
          vulnerabilities", does not mean nothing is there.
          <ul className="mb-0 mt-1">
            {partlyAnalysed.flatMap((result) =>
              (result.warnings ?? []).map((warning) => (
                <li key={`${result.data_source_id}-${warning}`}>
                  <strong>{SOURCE_TYPE_LABELS[result.type] ?? result.type}:</strong> {warning}
                </li>
              )),
            )}
          </ul>
        </Alert>
      )}
      {staleness?.stale && (
        <Alert variant="info" className="mb-2 d-flex justify-content-between align-items-center">
          <span>Data sources have changed since this run -- re-run to pick up the updates.</span>
          <Button size="sm" variant="outline-primary" disabled={reRunning} onClick={() => void handleReRun()}>
            {reRunning ? "Re-running..." : "Re-run now"}
          </Button>
        </Alert>
      )}
      <StatStrip items={statItems} compact={activeTab === "diagram"} />
      <ModelTabs
        active={activeTab}
        onSelect={switchTab}
        counts={{ threats: totalThreats, actions: openActions, findings: findings.length }}
      />
      <ModelTour onGoToTab={switchTab} />
      {extensionTab && applicationId && runId && extensionTab.render({ applicationId, runId, refreshKey: threatsData })}

      <div style={{ display: activeTab === "overview" ? undefined : "none" }}>
        {applicationId && runId && (
          <Overview
            applicationId={applicationId}
            runId={runId}
            componentCount={componentCount}
            completeness={completeness}
            actionPlan={actionPlan}
            threatsSummary={threatsData?.summary}
            attackPaths={attackPaths}
            diff={diff}
            refreshKey={threatsData}
            onAnswered={() => loadRun()}
            onGoToTab={switchTab}
            onCompletenessLoaded={setCompleteness}
          />
        )}
      </div>

      {activeTab === "diagram" && (
        <div className="pc-panel">
          {diagrams.length > 0 && (
            <div className="d-flex align-items-center flex-wrap gap-1 p-2 border-bottom bg-light-subtle">
              {diagrams.length > MAX_DIAGRAM_TABS ? (
                <Form.Select
                  size="sm"
                  style={{ width: "auto", minWidth: 220 }}
                  aria-label="Diagram"
                  value={activeDiagramId ?? ""}
                  onChange={(event) => setActiveDiagramId(event.target.value)}
                >
                  {diagrams.map((diagram) => (
                    <option key={diagram.id} value={diagram.id}>
                      {diagram.name}
                    </option>
                  ))}
                </Form.Select>
              ) : (
                diagrams.map((diagram) => (
                  <Button
                    key={diagram.id}
                    size="sm"
                    variant={diagram.id === activeDiagramId ? "primary" : "outline-secondary"}
                    onClick={() => setActiveDiagramId(diagram.id)}
                  >
                    {diagram.name}
                  </Button>
                ))
              )}
              {editMode && !addingDiagram && (
                <Button
                  size="sm"
                  variant="outline-secondary"
                  onClick={() => {
                    setAddingDiagram(true);
                    setDiagramNameDraft("");
                  }}
                  title="Add another diagram -- a separate, independently-arranged view of this same model"
                >
                  + Diagram
                </Button>
              )}
              {editMode && addingDiagram && (
                <InputGroup size="sm" style={{ maxWidth: 220 }}>
                  <Form.Control
                    autoFocus
                    placeholder="Diagram name"
                    value={diagramNameDraft}
                    onChange={(event) => setDiagramNameDraft(event.target.value)}
                    onKeyDown={(event) => {
                      if (event.key === "Enter") void handleCreateDiagram();
                      if (event.key === "Escape") setAddingDiagram(false);
                    }}
                  />
                  <Button
                    variant="outline-primary"
                    disabled={!diagramNameDraft.trim()}
                    onClick={() => void handleCreateDiagram()}
                  >
                    Add
                  </Button>
                </InputGroup>
              )}
              {editMode && activeDiagramId && !renamingDiagram && !addingDiagram && (
                <Button
                  size="sm"
                  variant="link"
                  className="text-muted"
                  onClick={() => {
                    setRenamingDiagram(true);
                    setDiagramNameDraft(diagrams.find((d) => d.id === activeDiagramId)?.name ?? "");
                  }}
                >
                  Rename
                </Button>
              )}
              {editMode && renamingDiagram && (
                <InputGroup size="sm" style={{ maxWidth: 220 }}>
                  <Form.Control
                    autoFocus
                    value={diagramNameDraft}
                    onChange={(event) => setDiagramNameDraft(event.target.value)}
                    onKeyDown={(event) => {
                      if (event.key === "Enter") void handleRenameDiagram();
                      if (event.key === "Escape") setRenamingDiagram(false);
                    }}
                  />
                  <Button
                    variant="outline-primary"
                    disabled={!diagramNameDraft.trim()}
                    onClick={() => void handleRenameDiagram()}
                  >
                    Save
                  </Button>
                </InputGroup>
              )}
              {editMode && activeDiagramId && diagrams.length > 1 && !renamingDiagram && !addingDiagram && (
                <Button
                  size="sm"
                  variant="link"
                  className="text-danger"
                  onClick={() => void handleDeleteDiagram(activeDiagramId)}
                >
                  Delete diagram
                </Button>
              )}
              {editMode && hiddenLayout.length > 0 && (
                <Button
                  size="sm"
                  variant="link"
                  className="ms-auto"
                  onClick={() => setShowHiddenPanel((prev) => !prev)}
                >
                  {hiddenLayout.length} hidden on this diagram {showHiddenPanel ? "▲" : "▼"}
                </Button>
              )}
            </div>
          )}
          {justHidden && (
            <Alert
              variant="info"
              className="mb-0 rounded-0 py-2 d-flex align-items-center gap-2"
              dismissible
              onClose={() => setJustHidden(null)}
            >
              <span>
                Hid <strong>{justHidden.label}</strong> on this diagram only.
              </span>
              <Button
                size="sm"
                variant="outline-primary"
                onClick={() => void handleShowElement(justHidden.key, justHidden.label)}
              >
                Show it again
              </Button>
            </Alert>
          )}
          {editMode && showHiddenPanel && hiddenLayout.length > 0 && (
            <div className="p-2 border-bottom bg-light-subtle d-flex flex-wrap gap-2">
              {hiddenLayout.map((row) => (
                <Badge key={row.id} bg="secondary" className="d-flex align-items-center gap-2">
                  {row.element_key
                    .replace(/^(process|data_store|external_entity):/, "")
                    .replace(/^(flow|boundary):/, "$1 ")}
                  <Button
                    size="sm"
                    variant="link"
                    className="text-white p-0"
                    onClick={() => void handleShowElement(row.element_key, row.element_key)}
                  >
                    Show
                  </Button>
                </Badge>
              ))}
            </div>
          )}
          <div className="d-flex justify-content-between align-items-center p-2 border-bottom bg-body-tertiary flex-wrap gap-2">
            <Form.Check
              type="switch"
              id="dfd-edit-mode"
              label="Edit mode"
              checked={editMode}
              onChange={(event) => {
                setEditMode(event.target.checked);
                if (!event.target.checked) {
                  setBoundaryToolActive(false);
                  clearBoundarySelection();
                  setPendingPlacement(null);
                }
              }}
            />
            <Form.Check
              type="switch"
              id="dfd-minimap"
              label="Mini map"
              checked={showMinimap}
              onChange={(event) => setShowMinimap(event.target.checked)}
            />
            {configObjects.count > 0 && (
              <Form.Check
                type="switch"
                id="dfd-show-config"
                label={`Show configuration objects (${configObjects.count})`}
                title="ConfigMaps, Secrets and volume claims. Hidden by default on a busy diagram; their threats and findings are unaffected."
                checked={configObjects.shown}
                onChange={() => setShowConfigObjects(!configObjects.shown)}
              />
            )}
            <span className="small text-muted" aria-label="Diagram legend">
              Rounded: process · Open-ended: data store · Double border: external entity · Ring: open high or critical
              risk
            </span>
            {editMode && (
              <div className="d-flex gap-2">
                <Button
                  size="sm"
                  variant="outline-secondary"
                  onClick={() => void history.undo()}
                  disabled={!history.canUndo}
                  title={history.undoLabel ? `Undo: ${history.undoLabel} (Ctrl+Z)` : "Nothing to undo"}
                >
                  ↶ Undo
                </Button>
                <Button
                  size="sm"
                  variant="outline-secondary"
                  onClick={() => void history.redo()}
                  disabled={!history.canRedo}
                  title={history.redoLabel ? `Redo: ${history.redoLabel} (Ctrl+Shift+Z)` : "Nothing to redo"}
                >
                  ↷ Redo
                </Button>
                <Button
                  size="sm"
                  variant={boundaryToolActive ? "primary" : "outline-primary"}
                  onClick={handleToggleBoundaryTool}
                  title="Click, then drag a box around components to group them into a trust boundary"
                >
                  ⬚ Trust Boundary
                </Button>
                {ASSET_TYPES.map((type) => (
                  <Button
                    key={type}
                    size="sm"
                    variant="outline-secondary"
                    draggable
                    onDragStart={(event) => handlePaletteDragStart(event, type)}
                    style={{ cursor: "grab" }}
                    title={`Drag onto the diagram to place a new ${ASSET_TYPE_LABELS[type]}`}
                  >
                    {ASSET_TYPE_LABELS[type]}
                  </Button>
                ))}
              </div>
            )}
          </div>
          {editError && (
            <Alert variant="danger" className="m-2 mb-0" onClose={() => setEditError(null)} dismissible>
              {editError}
            </Alert>
          )}
          {editMode && nodes.length === 0 && isBlankModel && (
            <Alert variant="info" className="m-2 mb-0">
              This is a blank model. Drag a Process, Data Store or External Entity onto the canvas, then connect them.
              Threats are generated for every element you draw.
            </Alert>
          )}
          {editMode && !boundaryToolActive && selectedBoundaryNodeIds.length === 0 && (
            <p className="text-muted small px-2 pt-2 mb-0">
              Drag a component button onto the diagram to place it. Drag between two components to connect them. Click a
              dashed (manually-added) connection to remove it. Drag a trust boundary box to reposition it. Ctrl+Z /
              Ctrl+Shift+Z undoes and redoes edits.
            </p>
          )}
          {boundaryToolActive && selectedBoundaryNodeIds.length === 0 && (
            <p className="text-muted small px-2 pt-2 mb-0">
              Drag a box around the components that belong in this boundary.
            </p>
          )}
          {boundaryToolActive && selectedBoundaryNodeIds.length > 0 && (
            <div className="p-2 border-bottom bg-light-subtle d-flex align-items-center gap-2">
              <span className="small text-muted">
                {selectedBoundaryNodeIds.length} component{selectedBoundaryNodeIds.length === 1 ? "" : "s"} selected --
              </span>
              <Form.Control
                size="sm"
                style={{ maxWidth: 220 }}
                list="trust-boundary-suggestions"
                autoFocus
                placeholder="Boundary name"
                value={boundaryNameDraft}
                onChange={(event) => setBoundaryNameDraft(event.target.value)}
                onKeyDown={(event) => {
                  if (event.key === "Enter") void handleApplyBoundaryName();
                  if (event.key === "Escape") clearBoundarySelection();
                }}
              />
              <Button size="sm" onClick={() => void handleApplyBoundaryName()} disabled={!boundaryNameDraft.trim()}>
                Apply
              </Button>
              <Button size="sm" variant="outline-secondary" onClick={clearBoundarySelection}>
                Cancel
              </Button>
            </div>
          )}
          <div className="pc-diagram-row" ref={diagramPaneRef} style={{ height: canvasHeight }}>
            <div
              ref={dfdContainerRef}
              className="pc-diagram-canvas"
              style={{ position: "relative" }}
              onDragOver={handleCanvasDragOver}
              onDrop={handleCanvasDrop}
            >
              <ReactFlowProvider>
                <DfdPane
                  nodes={nodes}
                  edges={edges}
                  editMode={editMode}
                  boundaryToolActive={boundaryToolActive}
                  showMinimap={showMinimap}
                  onNodesChange={onNodesChange}
                  onEdgesChange={onEdgesChange}
                  onNodeClick={handleNodeClick}
                  onEdgeClick={handleEdgeClick}
                  onConnect={handleConnect}
                  onInit={setReactFlowInstance}
                  onSelectionChange={handleSelectionChange}
                  onNodeDragStart={handleNodeDragStart}
                  onNodeDragStop={(event, node) => void handleNodeDragStop(event, node)}
                  onPaneClick={closeInspector}
                />
              </ReactFlowProvider>
              {pendingPlacement && (
                <div
                  style={{
                    position: "absolute",
                    left: pendingPlacement.screenX,
                    top: pendingPlacement.screenY,
                    zIndex: 10,
                    background: "var(--bs-body-bg)",
                    border: "1px solid var(--bs-border-color)",
                    borderRadius: 6,
                    boxShadow: "0 2px 8px rgba(0,0,0,0.15)",
                    padding: 6,
                  }}
                >
                  <InputGroup size="sm">
                    <Form.Control
                      autoFocus
                      placeholder={`Name this ${ASSET_TYPE_LABELS[pendingPlacement.type]}`}
                      style={{ width: 200 }}
                      value={pendingPlacementName}
                      onChange={(event) => setPendingPlacementName(event.target.value)}
                      onBlur={() => {
                        // A short delay so a click on the Add button isn't
                        // lost to the input's blur firing first.
                        window.setTimeout(() => {
                          if (pendingPlacementName.trim()) void handleConfirmPlacement();
                          else setPendingPlacement(null);
                        }, 150);
                      }}
                      onKeyDown={(event) => {
                        if (event.key === "Enter") void handleConfirmPlacement();
                        if (event.key === "Escape") setPendingPlacement(null);
                      }}
                    />
                    <Button variant="primary" onClick={() => void handleConfirmPlacement()}>
                      Add
                    </Button>
                  </InputGroup>
                </div>
              )}
            </div>
            {/* Non-modal inspector docked next to the canvas: no
                  backdrop, so the diagram stays visible and clickable. Below
                  1100px there's no room for a dock, so it falls back to the
                  Offcanvas rendered near the other dialogs below. */}
            {!isNarrowViewport && selectedNode && applicationId && runId && (
              <div className="pc-inspector-dock" data-testid="inspector-dock">
                <ElementInspector
                  element={selectedNode}
                  editMode={editMode}
                  onClose={closeInspector}
                  nameDraft={nameDraft}
                  onNameDraftChange={setNameDraft}
                  onRename={() => void handleRenameComponent()}
                  boundaryDraft={boundaryDraft}
                  onBoundaryDraftChange={setBoundaryDraft}
                  onSaveBoundary={() => void handleSaveBoundary()}
                  boundarySuggestionsListId="trust-boundary-suggestions"
                  hiddenHere={isHiddenHere(`${selectedNode.type}:${selectedNode.name}`)}
                  onToggleHidden={() => {
                    const key = `${selectedNode.type}:${selectedNode.name}`;
                    void (isHiddenHere(key)
                      ? handleShowElement(key, selectedNode.name)
                      : handleHideElement(key, selectedNode.name));
                  }}
                  onDeleteRequest={() => setComponentToDelete(selectedNode)}
                  propertySpecs={propertySpecs[selectedNode.type] ?? []}
                  onSaveProperties={(next) => handleSaveProperties("component", selectedNode.id, next)}
                  findings={findings
                    .filter((finding) => finding.asset_id === selectedNode.id)
                    .map((finding) => ({ id: finding.id, title: finding.title }))}
                  applicationId={applicationId}
                  runId={runId}
                  threats={threatsData?.threats ?? []}
                  onThreatsChanged={reloadThreats}
                  onAddThreat={() => setAddThreat({ open: true, elementId: selectedNode.id })}
                  onEditThreat={setEditingThreat}
                  blankModel={isBlankModel}
                  onViewAllThreats={() => {
                    setThreatPreset({ name: selectedNode.name, nonce: Date.now() });
                    switchTab("threats");
                    closeInspector();
                  }}
                />
              </div>
            )}
          </div>
        </div>
      )}

      <div className="pc-panel pc-panel-body" style={{ display: activeTab === "threats" ? undefined : "none" }}>
        {threatsData && applicationId && runId ? (
          <ThreatsPanel
            applicationId={applicationId}
            runId={runId}
            threats={threatsData.threats}
            onChanged={reloadThreats}
            onAddThreat={() => setAddThreat({ open: true, elementId: null })}
            onEditThreat={setEditingThreat}
            blankModel={isBlankModel}
            coverageGaps={threatsData.coverage_gaps}
            docConflicts={threatsData.doc_conflicts}
            unavailableMethodologies={threatsData.unavailable_methodologies}
            presetElement={threatPreset}
          />
        ) : (
          <p className="text-muted mb-0">Threats are unavailable.</p>
        )}
      </div>

      <div className="pc-panel pc-panel-body" style={{ display: activeTab === "actions" ? undefined : "none" }}>
        {applicationId && runId ? (
          <ActionPlanPanel
            applicationId={applicationId}
            runId={runId}
            refreshKey={threatsData}
            onLoaded={(plan) => {
              setActionPlan(plan);
              setOpenActionCount(plan.actions.filter((a) => a.status === "todo" || a.status === "in_progress").length);
            }}
          />
        ) : (
          <p className="text-muted mb-0">The action plan is unavailable.</p>
        )}
      </div>

      <div style={{ display: activeTab === "findings" ? undefined : "none" }}>
        <section className="pc-panel mb-3" aria-label="Findings">
          <div className="pc-panel-head">
            <span>Findings ({findings.length})</span>
          </div>
          <div className="pc-panel-body">
            {findings.length === 0 ? (
              <p className="text-muted mb-0">No findings for this run.</p>
            ) : (
              <div className="pc-sticky-thead" style={{ maxHeight: "70vh", overflow: "auto" }}>
                <Table size="sm" striped responsive className="mb-0">
                  <thead>
                    <tr>
                      <th>Title</th>
                      <th>Domain</th>
                      <th>Fixed version</th>
                      <th>Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {findings.map((finding) => (
                      <tr key={finding.id}>
                        <td>{finding.title}</td>
                        <td>{finding.domain}</td>
                        <td>{(finding.evidence?.fixed_versions ?? []).join(", ")}</td>
                        <td>
                          <Badge bg={finding.status === "open" ? "danger" : "secondary"}>{finding.status}</Badge>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </Table>
              </div>
            )}
          </div>
        </section>

        {sbom && (
          <section className="pc-panel mb-3" aria-label="Software Bill of Materials">
            <div className="pc-panel-head">
              <span>
                Software Bill of Materials ({sbom.component_count} component{sbom.component_count === 1 ? "" : "s"},{" "}
                {sbom.vulnerability_count} known vulnerabilit{sbom.vulnerability_count === 1 ? "y" : "ies"})
              </span>
            </div>
            <div className="pc-panel-body">
              {sbom.no_lockfile_detected ? (
                <Alert variant="info" className="mb-0">
                  No lockfile found in this repository -- dependency versions can&apos;t be resolved for vulnerability
                  matching.{" "}
                  {sbom.manifest_files_found.length > 0 && `Found manifests: ${sbom.manifest_files_found.join(", ")}.`}
                </Alert>
              ) : sbom.component_count === 0 ? (
                <p className="text-muted mb-0">No application dependencies were found for this run.</p>
              ) : (
                <div className="pc-sticky-thead" style={{ maxHeight: "70vh", overflow: "auto" }}>
                  <Table size="sm" striped responsive className="mb-0">
                    <thead>
                      <tr>
                        <th>Name</th>
                        <th>Version</th>
                        <th>Type</th>
                        <th>Vulnerabilities</th>
                      </tr>
                    </thead>
                    <tbody>
                      {sbom.components.map((component, index) => {
                        const ref = component["bom-ref"];
                        const vulnCount = ref
                          ? sbom.vulnerabilities.filter((v) => v.affects?.some((a) => a.ref === ref)).length
                          : 0;
                        return (
                          <tr key={ref ?? `${component.name}-${index}`}>
                            <td>{component.name}</td>
                            <td>{component.version ?? "—"}</td>
                            <td>{component.type ?? "—"}</td>
                            <td>
                              {vulnCount > 0 ? (
                                <Badge bg="danger">{vulnCount}</Badge>
                              ) : (
                                <span className="text-muted">0</span>
                              )}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </Table>
                </div>
              )}
            </div>
          </section>
        )}
      </div>

      <div style={{ display: activeTab === "settings" ? undefined : "none" }}>
        {applicationId && (
          <section className="pc-panel mb-3" aria-label="Data sources">
            <div className="pc-panel-head">
              <span>Data sources</span>
            </div>
            <DataSourcesPanel
              applicationId={applicationId}
              onChanged={loadRunsAndStaleness}
              sourceResults={run?.source_results}
            />
          </section>
        )}
        {applicationId && (
          <section className="pc-panel mb-3" aria-label="Model info">
            <div className="pc-panel-head">
              <span>Model info</span>
            </div>
            <ModelInfoPanel applicationId={applicationId} />
          </section>
        )}
      </div>

      <datalist id="trust-boundary-suggestions">
        {BOUNDARY_SUGGESTIONS.map((suggestion) => (
          <option key={suggestion} value={suggestion} />
        ))}
      </datalist>

      {applicationId && runId && (
        <AddThreatModal
          show={addThreat.open}
          onHide={() => setAddThreat({ open: false, elementId: null })}
          applicationId={applicationId}
          runId={runId}
          elements={threatElementChoices()}
          initialElementId={addThreat.elementId ?? undefined}
          onCreated={reloadThreats}
        />
      )}
      {applicationId && runId && (
        <AddThreatModal
          show={editingThreat !== null}
          onHide={() => setEditingThreat(null)}
          applicationId={applicationId}
          runId={runId}
          elements={[]}
          editing={editingThreat}
          onCreated={reloadThreats}
        />
      )}

      {/* Below 1100px there's no room for the docked inspector (see the
          "pc-diagram-row" / "pc-inspector-dock" above), so the same
          ElementInspector falls back to a non-modal Offcanvas: no backdrop,
          so the diagram behind it is still visible, and `scroll` so the
          page underneath can still be scrolled with the panel open. */}
      {isNarrowViewport && (
        <Offcanvas show={selectedNode !== null} onHide={closeInspector} placement="end" backdrop={false} scroll>
          <Offcanvas.Body>
            {selectedNode && applicationId && runId && (
              <ElementInspector
                element={selectedNode}
                editMode={editMode}
                onClose={closeInspector}
                nameDraft={nameDraft}
                onNameDraftChange={setNameDraft}
                onRename={() => void handleRenameComponent()}
                boundaryDraft={boundaryDraft}
                onBoundaryDraftChange={setBoundaryDraft}
                onSaveBoundary={() => void handleSaveBoundary()}
                boundarySuggestionsListId="trust-boundary-suggestions"
                hiddenHere={isHiddenHere(`${selectedNode.type}:${selectedNode.name}`)}
                onToggleHidden={() => {
                  const key = `${selectedNode.type}:${selectedNode.name}`;
                  void (isHiddenHere(key)
                    ? handleShowElement(key, selectedNode.name)
                    : handleHideElement(key, selectedNode.name));
                }}
                onDeleteRequest={() => setComponentToDelete(selectedNode)}
                propertySpecs={propertySpecs[selectedNode.type] ?? []}
                onSaveProperties={(next) => handleSaveProperties("component", selectedNode.id, next)}
                findings={findings
                  .filter((finding) => finding.asset_id === selectedNode.id)
                  .map((finding) => ({ id: finding.id, title: finding.title }))}
                applicationId={applicationId}
                runId={runId}
                threats={threatsData?.threats ?? []}
                onThreatsChanged={reloadThreats}
                onAddThreat={() => setAddThreat({ open: true, elementId: selectedNode.id })}
                onEditThreat={setEditingThreat}
                blankModel={isBlankModel}
                onViewAllThreats={() => {
                  setThreatPreset({ name: selectedNode.name, nonce: Date.now() });
                  switchTab("threats");
                  closeInspector();
                }}
              />
            )}
          </Offcanvas.Body>
        </Offcanvas>
      )}

      <Modal show={edgeToDelete !== null} onHide={() => setEdgeToDelete(null)}>
        <Modal.Header closeButton>
          <Modal.Title>Edit connection</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          {edgeToDelete?.is_manual ? (
            <Form.Group controlId="edge-label-draft" className="mb-3">
              <Form.Label>Label</Form.Label>
              <Form.Control
                value={edgeLabelDraft}
                maxLength={200}
                placeholder="e.g. HTTPS, SQL, webhook"
                onChange={(event) => setEdgeLabelDraft(event.target.value)}
              />
            </Form.Group>
          ) : (
            <p className="text-muted small">
              This connection comes from the scanned sources, so its label can&apos;t be edited. You can still state
              facts about it below.
            </p>
          )}
          {edgeToDelete && (
            <ElementPropertiesForm
              specs={propertySpecs.data_flow ?? []}
              value={edgeToDelete.properties ?? {}}
              onSave={(next) => handleSaveProperties("flow", edgeToDelete.id, next)}
            />
          )}
        </Modal.Body>
        <Modal.Footer>
          {editMode && edgeToDelete && nodesById[edgeToDelete.source] && nodesById[edgeToDelete.target] && (
            <Button
              className="me-auto"
              variant={
                isHiddenHere(`flow:${nodesById[edgeToDelete.source].name}->${nodesById[edgeToDelete.target].name}`)
                  ? "outline-secondary"
                  : "primary"
              }
              onClick={() => {
                const sourceName = nodesById[edgeToDelete.source].name;
                const targetName = nodesById[edgeToDelete.target].name;
                const key = `flow:${sourceName}->${targetName}`;
                const label = `${sourceName} -> ${targetName}`;
                if (isHiddenHere(key)) void handleShowElement(key, label);
                else {
                  void handleHideElement(key, label);
                  setEdgeToDelete(null);
                }
              }}
              title="Lit = shown on this diagram. Click to hide it here."
            >
              Show on this diagram
            </Button>
          )}
          {edgeToDelete?.is_manual && (
            <Button variant="outline-danger" onClick={() => void handleConfirmDeleteEdge()}>
              Remove connection
            </Button>
          )}
          <Button variant="secondary" onClick={() => setEdgeToDelete(null)}>
            {edgeToDelete?.is_manual ? "Cancel" : "Close"}
          </Button>
          {edgeToDelete?.is_manual && <Button onClick={() => void handleSaveEdgeLabel()}>Save</Button>}
        </Modal.Footer>
      </Modal>

      <Modal show={componentToDelete !== null} onHide={() => setComponentToDelete(null)}>
        <Modal.Header closeButton>
          <Modal.Title>Delete component</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          Delete the manually-added component <strong>{componentToDelete?.name}</strong>? You can undo this with Ctrl+Z.
        </Modal.Body>
        <Modal.Footer>
          <Button variant="secondary" onClick={() => setComponentToDelete(null)}>
            Cancel
          </Button>
          <Button variant="danger" onClick={() => void handleConfirmDeleteComponent()}>
            Delete
          </Button>
        </Modal.Footer>
      </Modal>
    </div>
  );
}
