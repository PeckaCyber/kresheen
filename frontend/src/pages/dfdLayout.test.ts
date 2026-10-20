import { describe, expect, it } from "vitest";
import { isConfigObject, orderBoundaries, placeInRows, rowsBottom, splitKind, type LayoutNode } from "./dfdLayout";

const node = (id: string, name: string, type: string, trust_boundary: string | null): LayoutNode => ({ id, name, type, trust_boundary });

describe("splitKind", () => {
  it("separates a Kubernetes kind from the object name", () => {
    expect(splitKind("Deployment/quay-app")).toEqual({ kind: "Deployment", short: "quay-app" });
    expect(splitKind("PersistentVolumeClaim/postgres-pvc")).toEqual({ kind: "PersistentVolumeClaim", short: "postgres-pvc" });
  });

  it("leaves names a person typed alone, including ones with a slash", () => {
    expect(splitKind("Web Portal")).toEqual({ kind: null, short: "Web Portal" });
    expect(splitKind("orders/api")).toEqual({ kind: null, short: "orders/api" }); // lower-case: not a kind
    expect(splitKind("Auth/Login service")).toEqual({ kind: "Auth", short: "Login service" }); // ambiguous, harmless
  });
});

describe("isConfigObject", () => {
  it("flags configuration data stores only", () => {
    expect(isConfigObject({ name: "ConfigMap/app-config", type: "data_store" })).toBe(true);
    expect(isConfigObject({ name: "Secret/db", type: "data_store" })).toBe(true);
    expect(isConfigObject({ name: "PersistentVolumeClaim/data", type: "data_store" })).toBe(true);
    expect(isConfigObject({ name: "Deployment/app", type: "process" })).toBe(false);
    expect(isConfigObject({ name: "Secret/x", type: "process" })).toBe(false);
    expect(isConfigObject({ name: "Orders DB", type: "data_store" })).toBe(false);
  });
});

describe("orderBoundaries", () => {
  const nodes = [
    node("db", "DB", "data_store", "Data"),
    node("api", "API", "process", "Application"),
    node("web", "Web", "process", "DMZ"),
    node("user", "User", "external_entity", "Internet"),
    node("stray", "Stray", "process", "Aside"),
  ];
  const edges = [
    { source: "user", target: "web" },
    { source: "web", target: "api" },
    { source: "api", target: "db" },
  ];

  it("orders boundaries outside-in by how far data travels to reach them", () => {
    expect(orderBoundaries(nodes, edges)).toEqual(["Internet", "DMZ", "Application", "Data", "Aside"]);
  });

  it("puts unreachable boundaries last and is stable", () => {
    expect(orderBoundaries([...nodes].reverse(), [...edges].reverse())).toEqual(["Internet", "DMZ", "Application", "Data", "Aside"]);
  });

  it("uses a boundary's shallowest member, and ignores nodes with no boundary", () => {
    const mixed = [
      node("user", "User", "external_entity", "Internet"),
      node("a", "A", "process", "Zone"),
      node("b", "B", "process", "Zone"),
      node("free", "Free", "process", null),
    ];
    expect(orderBoundaries(mixed, [{ source: "user", target: "b" }, { source: "b", target: "a" }])).toEqual(["Internet", "Zone"]);
  });

  it("draws a third party that only receives data at the end, not beside the users", () => {
    const shop = [
      node("shopper", "Shopper", "external_entity", "Internet"),
      node("web", "Web", "process", "DMZ"),
      node("api", "API", "process", "Application"),
      node("db", "DB", "data_store", "Data"),
      node("pay", "Payments", "external_entity", "Third party"),
    ];
    const flows = [
      { source: "shopper", target: "web" },
      { source: "web", target: "api" },
      { source: "api", target: "db" },
      { source: "api", target: "pay" },
    ];
    expect(orderBoundaries(shop, flows)).toEqual(["Internet", "DMZ", "Application", "Data", "Third party"]);
  });

  it("falls back to every external entity when all of them receive something", () => {
    const loop = [node("a", "A", "external_entity", "Out"), node("p", "P", "process", "In")];
    expect(orderBoundaries(loop, [{ source: "a", target: "p" }, { source: "p", target: "a" }])).toEqual(["Out", "In"]);
  });

  it("copes with cycles and an empty model", () => {
    const cyc = [node("u", "U", "external_entity", "Out"), node("a", "A", "process", "In"), node("b", "B", "process", "In")];
    expect(orderBoundaries(cyc, [{ source: "u", target: "a" }, { source: "a", target: "b" }, { source: "b", target: "a" }])).toEqual(["Out", "In"]);
    expect(orderBoundaries([], [])).toEqual([]);
  });
});

describe("placeInRows", () => {
  const boxes = Array.from({ length: 5 }, () => ({ width: 100, height: 50 }));

  it("lays boxes left to right and wraps after perRow", () => {
    expect(placeInRows(boxes, 3, 10)).toEqual([
      { x: 0, y: 0 }, { x: 110, y: 0 }, { x: 220, y: 0 },
      { x: 0, y: 60 }, { x: 110, y: 60 },
    ]);
  });

  it("starts the next row below the tallest box in the previous one", () => {
    const uneven = [{ width: 10, height: 30 }, { width: 10, height: 90 }, { width: 10, height: 20 }];
    expect(placeInRows(uneven, 2, 5)[2]).toEqual({ x: 0, y: 95 });
  });

  it("reports where the next thing should start", () => {
    expect(rowsBottom(boxes, 3, 10)).toBe(120);
    expect(rowsBottom([], 3, 10)).toBe(0);
  });
});
