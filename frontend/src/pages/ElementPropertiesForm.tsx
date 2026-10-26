import { useEffect, useState } from "react";
import { Button, Form } from "react-bootstrap";

export type PropertyValue = boolean | string;
export type ElementProperties = Record<string, PropertyValue>;

export interface PropertySpec {
  key: string;
  label: string;
  kind: "bool" | "text";
  help: string;
}

// Owner-stated facts about one element. Unknown is the absence of a key, and
// the server only lets an explicit value change the generated threats, so
// "Unknown" is always a safe choice. The form is built from the server's spec
// list (GET /api/threat-kb/property-specs), so the key list lives in one place.
export function ElementPropertiesForm({
  specs,
  value,
  readOnly,
  onSave,
}: {
  specs: PropertySpec[];
  value: ElementProperties;
  readOnly?: boolean;
  onSave: (next: ElementProperties) => void | Promise<void>;
}) {
  const [draft, setDraft] = useState<ElementProperties>(value);
  const [saving, setSaving] = useState(false);
  const valueKey = JSON.stringify(value);

  useEffect(() => {
    setDraft(value);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [valueKey]);

  if (specs.length === 0) return null;

  if (readOnly) {
    const stated = specs.filter((spec) => value[spec.key] !== undefined);
    if (stated.length === 0) return null;
    return (
      <ul className="small text-muted ps-3">
        {stated.map((spec) => (
          <li key={spec.key}>
            {spec.label}:{" "}
            {typeof value[spec.key] === "boolean" ? (value[spec.key] ? "Yes" : "No") : String(value[spec.key])}
          </li>
        ))}
      </ul>
    );
  }

  function setBool(key: string, raw: string) {
    setDraft((prev) => {
      const { [key]: _removed, ...rest } = prev;
      return raw === "" ? rest : { ...rest, [key]: raw === "yes" };
    });
  }

  function setText(key: string, raw: string) {
    setDraft((prev) => {
      const { [key]: _removed, ...rest } = prev;
      return raw === "" ? rest : { ...rest, [key]: raw };
    });
  }

  async function save() {
    setSaving(true);
    try {
      await onSave(draft);
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="mb-3">
      <div className="small fw-semibold mb-2">Properties</div>
      {specs.map((spec) => (
        <Form.Group key={spec.key} className="mb-2" controlId={`prop-${spec.key}`}>
          <Form.Label className="small mb-1">{spec.label}</Form.Label>
          {spec.kind === "bool" ? (
            <Form.Select
              size="sm"
              value={draft[spec.key] === undefined ? "" : draft[spec.key] ? "yes" : "no"}
              onChange={(event) => setBool(spec.key, event.target.value)}
            >
              <option value="">Unknown</option>
              <option value="yes">Yes</option>
              <option value="no">No</option>
            </Form.Select>
          ) : (
            <Form.Control
              size="sm"
              maxLength={500}
              value={typeof draft[spec.key] === "string" ? (draft[spec.key] as string) : ""}
              onChange={(event) => setText(spec.key, event.target.value)}
            />
          )}
          {spec.help && <Form.Text muted>{spec.help}</Form.Text>}
        </Form.Group>
      ))}
      <Button size="sm" variant="outline-primary" disabled={saving} onClick={() => void save()}>
        Save properties
      </Button>
    </div>
  );
}
