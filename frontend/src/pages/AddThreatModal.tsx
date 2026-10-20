import { useEffect, useState, type ChangeEvent, type FormEvent } from "react";
import { Alert, Button, Form, Modal } from "react-bootstrap";
import { apiFetch, ApiError } from "../api/client";
import { CUSTOM_METHODOLOGY, threatMethodologiesWith, methodologyCategories, categoryLabel, type Methodology } from "../methodology";

interface KbEntry {
  id: string;
  source: string;
  name: string;
  description: string;
  severity: string;
  methodology: Methodology;
  category: string | null;
  mitigations: string[];
}

export interface ElementChoice {
  kind: "component" | "flow";
  id: string;
  label: string;
}

const EMPTY_FORM = {
  elementId: "",
  kbEntryId: "",
  title: "",
  description: "",
  severity: "medium",
  methodology: "STRIDE" as Methodology,
  category: "",
  mitigations: "",
};

export interface EditableThreat {
  manual_threat_id: string | null;
  element_name: string;
  title: string;
  description: string;
  severity: string;
  methodology: Methodology;
  category: string | null;
  mitigations: string[];
}

// The methodology's categories, plus the threat's own when it is no longer in the list (an edited threat whose
// methodology this installation stopped offering keeps its category visible).
function categoriesWith(methodology: Methodology, category: string): string[] {
  const categories = methodologyCategories(methodology);
  return category && !categories.includes(category) ? [...categories, category] : categories;
}

export function AddThreatModal(props: {
  show: boolean;
  onHide: () => void;
  applicationId: string;
  runId: string;
  elements: ElementChoice[];
  initialElementId?: string;
  // When set, the dialog edits this manual threat instead of adding one (the
  // element and knowledge-base start are fixed, so they are hidden).
  editing?: EditableThreat | null;
  onCreated: () => void | Promise<void>;
}) {
  const [kbEntries, setKbEntries] = useState<KbEntry[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [formData, setFormData] = useState(EMPTY_FORM);

  useEffect(() => {
    if (props.show && props.editing) {
      setFormData({
        ...EMPTY_FORM,
        title: props.editing.title,
        description: props.editing.description,
        severity: props.editing.severity,
        methodology: props.editing.methodology,
        category: props.editing.category ?? "",
        mitigations: props.editing.mitigations.join("\n"),
      });
      setError(null);
    } else if (props.show) {
      apiFetch<KbEntry[]>("/api/threat-kb")
        .then((entries) => setKbEntries(entries))
        .catch(() => setKbEntries([]));

      const initialElementId = props.initialElementId;
      let selectedElementId = "";
      if (initialElementId && props.elements.some(e => e.id === initialElementId)) {
        selectedElementId = initialElementId;
      } else if (props.elements.length > 0) {
        selectedElementId = props.elements[0].id;
      }
      setFormData({ ...EMPTY_FORM, elementId: selectedElementId });
      setError(null);
    }
  }, [props.show, props.elements, props.initialElementId, props.editing]);

  const handleElementChange = (e: ChangeEvent<HTMLSelectElement>) => {
    setFormData({ ...formData, elementId: e.target.value });
  };

  const handleKbEntryChange = (e: ChangeEvent<HTMLSelectElement>) => {
    const kbId = e.target.value;
    setFormData(prev => ({ ...prev, kbEntryId: kbId }));

    if (kbId) {
      const entry = kbEntries.find(e => e.id === kbId);
      if (entry) {
        const element = props.elements.find(e => e.id === formData.elementId);
        const title = entry.name.replace(/\{name\}/g, element?.label || "");
        setFormData(prev => ({
          ...prev,
          title,
          description: entry.description,
          severity: entry.severity,
          methodology: entry.methodology,
          category: entry.category ?? "",
          mitigations: entry.mitigations.join("\n"),
        }));
      }
    } else {
      setFormData(prev => ({ ...prev, kbEntryId: "" }));
    }
  };

  const handleInputChange = (e: ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>) => {
    const { name, value } = e.target;
    setFormData(prev => ({ ...prev, [name]: value }));
  };

  const handleMethodologyChange = (e: ChangeEvent<HTMLSelectElement>) => {
    setFormData(prev => ({ ...prev, methodology: e.target.value as Methodology, category: "" }));
  };

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (isSubmitting) return;
    if (!props.editing && props.elements.length === 0) return;

    setIsSubmitting(true);
    setError(null);

    try {
      if (props.editing?.manual_threat_id) {
        await apiFetch<void>(
          `/api/applications/${props.applicationId}/runs/${props.runId}/manual-threats/${props.editing.manual_threat_id}`,
          {
            method: "PATCH",
            body: JSON.stringify({
              title: formData.title,
              description: formData.description,
              severity: formData.severity,
              methodology: formData.methodology,
              category: formData.category || null,
              mitigations: formData.mitigations
                .split("\n")
                .map((line) => line.trim())
                .filter((line) => line.length > 0),
            }),
          },
        );
        await props.onCreated();
        props.onHide();
        return;
      }

      const element = props.elements.find(e => e.id === formData.elementId);
      if (!element) throw new Error("Invalid element selected");

      const body = {
        element_kind: element.kind,
        element_id: element.id,
        kb_entry_id: formData.kbEntryId || null,
        title: formData.title,
        description: formData.description,
        severity: formData.severity,
        methodology: formData.methodology,
        category: formData.category || null,
        mitigations: formData.mitigations
          .split("\n")
          .map(line => line.trim())
          .filter(line => line.length > 0),
      };

      await apiFetch<void>(`/api/applications/${props.applicationId}/runs/${props.runId}/manual-threats`, {
        method: "POST",
        body: JSON.stringify(body),
      });

      await props.onCreated();
      props.onHide();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Failed to add the threat.");
    } finally {
      setIsSubmitting(false);
    }
  };

  const kbEntryOptions = kbEntries.map(entry => (
    <option key={entry.id} value={entry.id}>
      {entry.name}
    </option>
  ));

  const componentElements = props.elements.filter(e => e.kind === "component");
  const flowElements = props.elements.filter(e => e.kind === "flow");

  return (
    <Modal show={props.show} onHide={props.onHide} size="lg">
      <Modal.Header closeButton>
        <Modal.Title>{props.editing ? "Edit threat" : "Add threat"}</Modal.Title>
      </Modal.Header>
      <Form onSubmit={handleSubmit}>
        <Modal.Body>
          {error && <Alert variant="danger">{error}</Alert>}
          {props.editing && (
            <p className="text-muted small">
              On <strong>{props.editing.element_name}</strong>. To move a threat to another element, delete it and
              add it again.
            </p>
          )}
          {!props.editing && (
          <Form.Group className="mb-3" controlId="element">
            <Form.Label>Element</Form.Label>
            <Form.Select
              value={formData.elementId}
              onChange={handleElementChange}
              required
            >
              <optgroup label="Components">
                {componentElements.map(e => (
                  <option key={e.id} value={e.id}>
                    {e.label}
                  </option>
                ))}
              </optgroup>
              <optgroup label="Data flows">
                {flowElements.map(e => (
                  <option key={e.id} value={e.id}>
                    {e.label}
                  </option>
                ))}
              </optgroup>
            </Form.Select>
          </Form.Group>
          )}

          {!props.editing && (
          <Form.Group className="mb-3" controlId="kbEntry">
            <Form.Label>Start from a knowledge base entry (optional)</Form.Label>
            <Form.Select
              value={formData.kbEntryId}
              onChange={handleKbEntryChange}
            >
              <option value="">None, write my own</option>
              {kbEntryOptions}
            </Form.Select>
          </Form.Group>
          )}

          <Form.Group className="mb-3" controlId="title">
            <Form.Label>Title</Form.Label>
            <Form.Control
              type="text"
              name="title"
              value={formData.title}
              onChange={handleInputChange}
              required
              maxLength={200}
            />
          </Form.Group>

          <Form.Group className="mb-3" controlId="description">
            <Form.Label>Description</Form.Label>
            <Form.Control
              as="textarea"
              rows={3}
              name="description"
              value={formData.description}
              onChange={handleInputChange}
              maxLength={2000}
            />
          </Form.Group>

          <Form.Group className="mb-3" controlId="severity">
            <Form.Label>Severity</Form.Label>
            <Form.Select
              name="severity"
              value={formData.severity}
              onChange={handleInputChange}
            >
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </Form.Select>
          </Form.Group>

          <Form.Group className="mb-3" controlId="methodology">
            <Form.Label>Methodology</Form.Label>
            <Form.Select
              name="methodology"
              value={formData.methodology}
              onChange={handleMethodologyChange}
            >
              {threatMethodologiesWith([formData.methodology]).map((methodology) => (
                <option key={methodology} value={methodology}>
                  {methodology}
                </option>
              ))}
            </Form.Select>
          </Form.Group>

          <Form.Group className="mb-3" controlId="category">
            <Form.Label>{formData.methodology === CUSTOM_METHODOLOGY ? "Custom category (optional)" : "Category (optional)"}</Form.Label>
            {formData.methodology === CUSTOM_METHODOLOGY ? (
              <Form.Control
                name="category"
                value={formData.category}
                onChange={handleInputChange}
                placeholder="Your own category, e.g. Insider fraud"
              />
            ) : (
            <Form.Select
              name="category"
              value={formData.category}
              onChange={handleInputChange}
            >
              <option value="">None</option>
              {categoriesWith(formData.methodology, formData.category).map((category) => (
                <option key={category} value={category}>
                  {categoryLabel(formData.methodology, category)}
                </option>
              ))}
            </Form.Select>
            )}
          </Form.Group>

          <Form.Group className="mb-3" controlId="mitigations">
            <Form.Label>Mitigations (one per line)</Form.Label>
            <Form.Control
              as="textarea"
              rows={4}
              name="mitigations"
              value={formData.mitigations}
              onChange={handleInputChange}
            />
          </Form.Group>
        </Modal.Body>
        <Modal.Footer>
          <Button variant="secondary" type="button" onClick={props.onHide}>
            Cancel
          </Button>
          <Button
            type="submit"
            disabled={isSubmitting || (!props.editing && props.elements.length === 0)}
          >
            {isSubmitting ? (props.editing ? "Saving..." : "Adding...") : props.editing ? "Save changes" : "Add threat"}
          </Button>
        </Modal.Footer>
      </Form>
    </Modal>
  );
}
