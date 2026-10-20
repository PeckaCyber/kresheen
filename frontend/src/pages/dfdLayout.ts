// Pure helpers for laying out and naming the data flow diagram.
// Kept out of ApplicationDetail.tsx so they can be tested without React Flow.

export interface LayoutNode {
  id: string;
  name: string;
  type: string;
  trust_boundary: string | null;
}

export interface LayoutEdge {
  source: string;
  target: string;
}

// "Deployment/quay-app" -> { kind: "Deployment", short: "quay-app" }. Names that are not
// Kind/name (anything a person typed) come back unchanged with no kind.
export function splitKind(name: string): { kind: string | null; short: string } {
  const match = /^([A-Z][A-Za-z]+)\/(.+)$/.exec(name);
  return match ? { kind: match[1], short: match[2] } : { kind: null, short: name };
}

// Kubernetes objects that hold configuration rather than run anything. They are real data stores
// with real threats, but on a diagram they bury the workloads, so they can be folded away.
const CONFIG_KINDS = new Set(["ConfigMap", "Secret", "PersistentVolumeClaim"]);

export function isConfigObject(node: Pick<LayoutNode, "name" | "type">): boolean {
  const { kind } = splitKind(node.name);
  return node.type === "data_store" && kind !== null && CONFIG_KINDS.has(kind);
}

// Boundaries in the order data reaches them: breadth-first from the initiating external entities, so the
// diagram reads outside-in (internet, then DMZ, then application, then data). A boundary is as deep
// as its shallowest member. Anything unreachable goes last; ties are alphabetical, so it is stable.
export function orderBoundaries(nodes: LayoutNode[], edges: LayoutEdge[]): string[] {
  const depth = new Map<string, number>();
  const outgoing = new Map<string, string[]>();
  for (const edge of edges) outgoing.set(edge.source, [...(outgoing.get(edge.source) ?? []), edge.target]);
  const queue: string[] = [];
  // Start from the external entities that initiate flows (users, callers), not ones that only
  // receive them (a payment provider), or a third party would be drawn beside the internet at the
  // far left instead of at the end of the chain. If every external entity receives something, fall
  // back to all of them.
  const receivers = new Set(edges.map((edge) => edge.target));
  const externals = nodes.filter((node) => node.type === "external_entity");
  const initiators = externals.filter((node) => !receivers.has(node.id));
  for (const node of initiators.length > 0 ? initiators : externals) {
    depth.set(node.id, 0);
    queue.push(node.id);
  }
  for (let head = 0; head < queue.length; head++) {
    const current = queue[head];
    for (const next of outgoing.get(current) ?? []) {
      if (!depth.has(next)) {
        depth.set(next, (depth.get(current) ?? 0) + 1);
        queue.push(next);
      }
    }
  }
  const boundaryDepth = new Map<string, number>();
  for (const node of nodes) {
    if (!node.trust_boundary) continue;
    const d = depth.get(node.id) ?? Number.MAX_SAFE_INTEGER;
    boundaryDepth.set(node.trust_boundary, Math.min(boundaryDepth.get(node.trust_boundary) ?? d, d));
  }
  return [...boundaryDepth.entries()]
    .sort((a, b) => a[1] - b[1] || a[0].localeCompare(b[0]))
    .map(([name]) => name);
}

export interface Box {
  width: number;
  height: number;
}

// Places boxes left to right, wrapping after `perRow`, so a chain of boundaries reads like a page
// instead of one tall column that shrinks to unreadable when fitted to the screen.
export function placeInRows(boxes: Box[], perRow: number, gap: number): { x: number; y: number }[] {
  const positions: { x: number; y: number }[] = [];
  let x = 0;
  let y = 0;
  let rowHeight = 0;
  boxes.forEach((box, index) => {
    if (index > 0 && index % perRow === 0) {
      x = 0;
      y += rowHeight + gap;
      rowHeight = 0;
    }
    positions.push({ x, y });
    x += box.width + gap;
    rowHeight = Math.max(rowHeight, box.height);
  });
  return positions;
}

// The y at which whatever comes after the boxes (the ungrouped grid) should start.
export function rowsBottom(boxes: Box[], perRow: number, gap: number): number {
  if (boxes.length === 0) return 0;
  const positions = placeInRows(boxes, perRow, gap);
  return Math.max(...boxes.map((box, i) => positions[i].y + box.height)) + gap;
}
