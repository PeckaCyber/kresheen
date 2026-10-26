import { Fragment, useEffect, useMemo, useState, type FormEvent } from "react";
import { Alert, Badge, Button, Form, Modal, Table } from "react-bootstrap";
import { apiFetch } from "../api/client";
import { PageHeader } from "../components/PageHeader";
import {
  CUSTOM_METHODOLOGY,
  threatMethodologies,
  methodologyCategories,
  categoryLabel,
  type Methodology,
} from "../methodology";

interface ThreatKBEntryOut {
  id: string;
  source: string;
  external_id: string | null;
  name: string;
  description: string;
  tags: string[];
  url: string | null;
  methodology: Methodology;
  category: string | null;
  severity: string;
  mitigations: string[];
  applies_to: string | null;
  boundary_hint: string | null;
}

interface PredefinedRuleOut {
  id: string;
  element_type: string;
  methodology: Methodology;
  category: string | null;
  title: string;
  description: string;
  severity: string;
  mitigations: string[];
  cwe_refs: string[];
  attack_refs: string[];
  applies_when: string;
  taxonomy_id: string | null;
}

const SOURCE_LABEL: Record<string, string> = {
  mitre_attack: "MITRE ATT&CK",
  cwe: "CWE",
  custom: "Custom",
};

const ENTITY_LABEL: Record<string, string> = {
  process: "Process",
  data_store: "Data store",
  external_entity: "External entity",
  data_flow: "Data flow",
  trust_boundary: "Trust boundary",
};

// Threat feeds are their own framework; they carry no per-entry category yet.
const FEED_FRAMEWORK: Record<string, string> = {
  mitre_attack: "MITRE ATT&CK",
  cwe: "CWE",
};

// Framework on top, the category within it underneath (e.g. STRIDE / Spoofing).
function CategoryCell({ framework, category }: { framework: string | null; category?: string | null }) {
  if (!framework) return <td>—</td>;
  return (
    <td>
      <div>{framework}</div>
      {category && <div className="small text-muted">{category}</div>}
    </td>
  );
}

export function ThreatKnowledgeBasePage() {
  const [entries, setEntries] = useState<ThreatKBEntryOut[] | null>(null);
  const [rules, setRules] = useState<PredefinedRuleOut[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [tags, setTags] = useState("");
  const [sourceFilter, setSourceFilter] = useState("all");
  const [expandedRuleId, setExpandedRuleId] = useState<string | null>(null);
  const [appliesTo, setAppliesTo] = useState("");
  const [boundaryHint, setBoundaryHint] = useState("");
  const [methodology, setMethodology] = useState<Methodology>("STRIDE");
  const [category, setCategory] = useState("");
  const [severity, setSeverity] = useState("medium");
  const [mitigations, setMitigations] = useState("");
  const [searchTerm, setSearchTerm] = useState("");
  const [methodologyFilter, setMethodologyFilter] = useState("all");
  const [entityFilter, setEntityFilter] = useState("all");

  function load() {
    return Promise.all([
      apiFetch<ThreatKBEntryOut[]>("/api/threat-kb").then(setEntries),
      apiFetch<PredefinedRuleOut[]>("/api/threat-kb/rules").then(setRules),
    ]).catch(() => setError("Failed to load the threat knowledge base."));
  }

  // Compute all available methodologies and entities from current data
  // Must be before early returns to follow Rules of Hooks
  const allDistinctMethodologies = useMemo(() => {
    if (!rules || !entries) return [];
    const methods = new Set<string>();
    rules.forEach((r) => methods.add(r.methodology));
    entries.forEach((e) => methods.add(e.methodology));
    return Array.from(methods).sort();
  }, [rules, entries]);

  const allDistinctEntities = useMemo(() => {
    if (!rules || !entries) return [];
    const entities = new Set<string>();
    rules.forEach((r) => entities.add(r.element_type));
    entries.forEach((e) => {
      if (e.applies_to) entities.add(e.applies_to);
    });
    return Array.from(entities).sort();
  }, [rules, entries]);

  // Get items by source filter
  const itemsBySource = useMemo(() => {
    if (!rules || !entries) return [];
    if (sourceFilter === "all") {
      return [
        ...rules.map((r) => ({ ...r, type: "rule" as const })),
        ...entries.map((e) => ({ ...e, type: "entry" as const })),
      ];
    } else if (sourceFilter === "predefined") {
      return rules.map((r) => ({ ...r, type: "rule" as const }));
    } else if (sourceFilter === "custom") {
      return entries.filter((e) => e.source === "custom").map((e) => ({ ...e, type: "entry" as const }));
    } else {
      return entries.filter((e) => e.source === sourceFilter).map((e) => ({ ...e, type: "entry" as const }));
    }
  }, [sourceFilter, rules, entries]);

  // Apply all additional filters
  const filteredItems = useMemo(() => {
    return itemsBySource.filter((item) => {
      // Search filter
      if (searchTerm.trim()) {
        const search = searchTerm.trim().toLowerCase();
        const id = item.type === "rule" ? item.id : (item.external_id ?? "");
        const name = item.type === "rule" ? item.title : item.name;
        const desc = item.description;
        const matches =
          id.toLowerCase().includes(search) ||
          name.toLowerCase().includes(search) ||
          desc.toLowerCase().includes(search);
        if (!matches) return false;
      }

      // Methodology filter
      if (methodologyFilter !== "all" && item.methodology !== methodologyFilter) {
        return false;
      }

      // Entity filter
      if (entityFilter !== "all") {
        if (item.type === "rule") {
          if (item.element_type !== entityFilter) return false;
        } else {
          if (item.applies_to !== entityFilter) return false;
        }
      }

      return true;
    });
  }, [itemsBySource, searchTerm, methodologyFilter, entityFilter]);

  useEffect(() => {
    void load();
  }, []);

  async function handleCreate(event: FormEvent) {
    event.preventDefault();
    try {
      await apiFetch("/api/threat-kb", {
        method: "POST",
        body: JSON.stringify({
          name,
          description,
          tags: tags
            .split(",")
            .map((t) => t.trim())
            .filter(Boolean),
          applies_to: appliesTo || null,
          boundary_hint: appliesTo && boundaryHint.trim() ? boundaryHint.trim() : null,
          methodology,
          category: category || null,
          severity,
          mitigations: mitigations
            .split("\n")
            .map((m) => m.trim())
            .filter(Boolean),
        }),
      });
      setShowCreate(false);
      setName("");
      setDescription("");
      setTags("");
      setAppliesTo("");
      setBoundaryHint("");
      setMethodology("STRIDE");
      setCategory("");
      setSeverity("medium");
      setMitigations("");
      await load();
    } catch {
      setError("Failed to add that custom threat.");
    }
  }

  if (error && (!entries || !rules)) return <div className="pc-page">{error}</div>;
  if (!entries || !rules) return <div className="pc-page">Loading...</div>;

  const customCount = entries.filter((e) => e.source === "custom").length;
  const mitreCount = entries.filter((e) => e.source === "mitre_attack").length;
  const cweCount = entries.filter((e) => e.source === "cwe").length;

  const isExpanded = (id: string) => expandedRuleId === id;

  return (
    <div className="pc-page">
      <PageHeader
        title="Threat library"
        actions={<Button onClick={() => setShowCreate(true)}>Add custom threat</Button>}
      />

      <Alert variant="info" className="small">
        Pre-defined rules generate threats automatically on every matching element of a run's data flow diagram. A
        custom threat does the same when you choose what it applies to; otherwise it is reference only, and you can
        attach it to a specific component or flow from a run's Threats section. Threat feed entries are reference only
        for now.
      </Alert>

      <div className="d-flex flex-wrap gap-2 mb-2">
        <Form.Control
          type="search"
          placeholder="Search threats"
          aria-label="Search threats"
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          style={{ minWidth: "200px", maxWidth: "300px" }}
        />

        <Form.Select
          aria-label="Filter by source"
          style={{ width: "auto", minWidth: "180px" }}
          value={sourceFilter}
          onChange={(e) => setSourceFilter(e.target.value)}
        >
          <option value="all">All</option>
          <option value="predefined">Pre-defined ({rules.length})</option>
          <option value="custom">Custom ({customCount})</option>
          <optgroup label="Threat feeds">
            <option value="mitre_attack">MITRE ATT&CK ({mitreCount})</option>
            <option value="cwe">CWE ({cweCount})</option>
          </optgroup>
        </Form.Select>

        <Form.Select
          aria-label="Methodology"
          style={{ width: "auto", minWidth: "150px" }}
          value={methodologyFilter}
          onChange={(e) => setMethodologyFilter(e.target.value)}
        >
          <option value="all">All methodologies</option>
          {allDistinctMethodologies.map((m) => (
            <option key={m} value={m}>
              {m}
            </option>
          ))}
        </Form.Select>

        <Form.Select
          aria-label="Entity"
          style={{ width: "auto", minWidth: "150px" }}
          value={entityFilter}
          onChange={(e) => setEntityFilter(e.target.value)}
        >
          <option value="all">All entities</option>
          {allDistinctEntities.map((e) => (
            <option key={e} value={e}>
              {ENTITY_LABEL[e] ?? e}
            </option>
          ))}
        </Form.Select>
      </div>

      <div className="text-muted small mb-3">
        Showing {filteredItems.length} of {itemsBySource.length}
      </div>

      {error && <Alert variant="danger">{error}</Alert>}

      {filteredItems.length === 0 && itemsBySource.length > 0 ? (
        <Table striped size="sm">
          <thead>
            <tr>
              <th>Source</th>
              <th>ID</th>
              <th>Name</th>
              <th>Entity</th>
              <th>Category</th>
              <th>Severity</th>
              <th>Description</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td colSpan={7}>
                <div className="text-muted p-2">
                  No threats match these filters.{" "}
                  <Button
                    variant="link"
                    size="sm"
                    className="p-0"
                    onClick={() => {
                      setSearchTerm("");
                      setMethodologyFilter("all");
                      setEntityFilter("all");
                    }}
                  >
                    Clear filters
                  </Button>
                </div>
              </td>
            </tr>
          </tbody>
        </Table>
      ) : (
        <Table striped size="sm">
          <thead>
            <tr>
              <th>Source</th>
              <th>ID</th>
              <th>Name</th>
              <th>Entity</th>
              <th>Category</th>
              <th>Severity</th>
              <th>Description</th>
            </tr>
          </thead>
          <tbody>
            {filteredItems.map((item) => {
              if (item.type === "rule") {
                const isExpandedRow = isExpanded(item.id);
                return (
                  <Fragment key={item.id}>
                    <tr
                      onClick={() => setExpandedRuleId(isExpandedRow ? null : item.id)}
                      style={{ cursor: "pointer" }}
                      aria-expanded={isExpandedRow}
                    >
                      <td>
                        <Badge bg="primary">Pre-defined</Badge>
                      </td>
                      <td>{item.id}</td>
                      <td>{item.title}</td>
                      <td>
                        {ENTITY_LABEL[item.element_type] ?? item.element_type}
                        <div className="small text-muted">{item.applies_when}</div>
                      </td>
                      <CategoryCell
                        framework={item.methodology}
                        category={categoryLabel(item.methodology, item.category)}
                      />
                      <td>{item.severity}</td>
                      <td className="small">{item.description}</td>
                    </tr>
                    {isExpandedRow && (
                      <tr>
                        <td colSpan={7}>
                          <div className="p-2">
                            <strong>Suggested mitigations</strong>
                            <ul className="small">
                              {item.mitigations.map((m, i) => (
                                <li key={i}>{m}</li>
                              ))}
                            </ul>
                            <p className="small text-muted">
                              {item.cwe_refs.join(" · ")} {item.attack_refs.join(" · ")}
                              {item.taxonomy_id && ` · Research taxonomy ${item.taxonomy_id}`}
                            </p>
                          </div>
                        </td>
                      </tr>
                    )}
                  </Fragment>
                );
              } else {
                return (
                  <tr key={item.id}>
                    <td>
                      <Badge bg={item.source === "custom" ? "info" : "secondary"}>
                        {SOURCE_LABEL[item.source] ?? item.source}
                      </Badge>
                    </td>
                    <td>{item.external_id ?? "—"}</td>
                    <td>{item.name}</td>
                    <td>
                      {item.applies_to ? (ENTITY_LABEL[item.applies_to] ?? item.applies_to) : "—"}
                      {!item.applies_to && <div className="small text-muted">Reference only</div>}
                      {item.applies_to && item.boundary_hint && (
                        <div className="small text-muted">boundary contains "{item.boundary_hint}"</div>
                      )}
                    </td>
                    <CategoryCell
                      framework={item.category ? item.methodology : (FEED_FRAMEWORK[item.source] ?? null)}
                      category={item.category ? categoryLabel(item.methodology, item.category) : null}
                    />
                    <td>{item.applies_to ? item.severity : "—"}</td>
                    <td className="small">{item.description}</td>
                  </tr>
                );
              }
            })}
          </tbody>
        </Table>
      )}

      {filteredItems.length === 0 && itemsBySource.length === 0 && (
        <p className="text-muted">
          {sourceFilter === "custom"
            ? "No custom threats yet. Use Add custom threat to create one."
            : sourceFilter !== "all" && sourceFilter !== "predefined"
              ? "No entries loaded for this feed yet."
              : null}
        </p>
      )}

      <Modal show={showCreate} onHide={() => setShowCreate(false)}>
        <Form onSubmit={handleCreate}>
          <Modal.Header closeButton>
            <Modal.Title>Add custom threat</Modal.Title>
          </Modal.Header>
          <Modal.Body>
            <Form.Group className="mb-3" controlId="kb-name">
              <Form.Label>Name</Form.Label>
              <Form.Control value={name} onChange={(event) => setName(event.target.value)} required autoFocus />
            </Form.Group>
            <Form.Group className="mb-3" controlId="kb-description">
              <Form.Label>Description</Form.Label>
              <Form.Control
                as="textarea"
                rows={3}
                value={description}
                onChange={(event) => setDescription(event.target.value)}
                required
              />
            </Form.Group>
            <Form.Group controlId="kb-tags">
              <Form.Label>Tags (comma-separated)</Form.Label>
              <Form.Control value={tags} onChange={(event) => setTags(event.target.value)} />
            </Form.Group>
            <Form.Group className="mb-3" controlId="kb-applies-to">
              <Form.Label>Generate this threat automatically on</Form.Label>
              <Form.Select value={appliesTo} onChange={(e) => setAppliesTo(e.target.value)}>
                <option value="">Nothing (reference only)</option>
                <option value="process">Every process</option>
                <option value="data_store">Every data store</option>
                <option value="external_entity">Every external entity</option>
                <option value="data_flow">Every data flow</option>
              </Form.Select>
              {!appliesTo && (
                <Form.Text className="text-muted">
                  Leave as reference only to attach this threat to specific components by hand from a run's Threats
                  section.
                </Form.Text>
              )}
            </Form.Group>
            {appliesTo && (
              <Form.Group className="mb-3" controlId="kb-boundary-hint">
                <Form.Label>Only where the trust boundary contains (optional)</Form.Label>
                <Form.Control
                  value={boundaryHint}
                  onChange={(e) => setBoundaryHint(e.target.value)}
                  placeholder="e.g. pci"
                  maxLength={100}
                />
              </Form.Group>
            )}
            <Form.Group className="mb-3" controlId="kb-severity">
              <Form.Label>Severity</Form.Label>
              <Form.Select value={severity} onChange={(e) => setSeverity(e.target.value)}>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </Form.Select>
            </Form.Group>
            <Form.Group className="mb-3" controlId="kb-methodology">
              <Form.Label>Methodology</Form.Label>
              <Form.Select
                value={methodology}
                onChange={(e) => {
                  setMethodology(e.target.value);
                  setCategory("");
                }}
              >
                {threatMethodologies().map((m) => (
                  <option key={m} value={m}>
                    {m}
                  </option>
                ))}
              </Form.Select>
            </Form.Group>
            <Form.Group className="mb-3" controlId="kb-category">
              <Form.Label>
                {methodology === CUSTOM_METHODOLOGY ? "Custom category (optional)" : "Category (optional)"}
              </Form.Label>
              {methodology === CUSTOM_METHODOLOGY ? (
                <Form.Control
                  value={category}
                  onChange={(e) => setCategory(e.target.value)}
                  placeholder="Your own category, e.g. Insider fraud"
                />
              ) : (
                <Form.Select value={category} onChange={(e) => setCategory(e.target.value)}>
                  <option value="">None</option>
                  {methodologyCategories(methodology).map((c) => (
                    <option key={c} value={c}>
                      {categoryLabel(methodology, c)}
                    </option>
                  ))}
                </Form.Select>
              )}
            </Form.Group>
            <Form.Group className="mb-3" controlId="kb-mitigations">
              <Form.Label>Suggested mitigations (one per line)</Form.Label>
              <Form.Control
                as="textarea"
                rows={3}
                value={mitigations}
                onChange={(e) => setMitigations(e.target.value)}
              />
            </Form.Group>
          </Modal.Body>
          <Modal.Footer>
            <Button variant="secondary" type="button" onClick={() => setShowCreate(false)}>
              Cancel
            </Button>
            <Button type="submit">Save</Button>
          </Modal.Footer>
        </Form>
      </Modal>
    </div>
  );
}
