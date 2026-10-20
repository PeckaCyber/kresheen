import { type ReactNode, useId, useState } from "react";
import { Card, Collapse } from "react-bootstrap";

// A card whose body is hidden until its header is clicked. Used for Settings,
// where every section starting expanded made the page a long scroll.
export function CollapsibleCard({
  title,
  children,
  defaultOpen = false,
  id,
}: {
  title: string;
  children: ReactNode;
  defaultOpen?: boolean;
  /** Anchor id for `Settings`'s "jump to section" links (e.g. `/settings#account`). */
  id?: string;
}) {
  const [open, setOpen] = useState(defaultOpen);
  const bodyId = useId();
  return (
    <Card className="mb-3" id={id}>
      <Card.Header className="p-0">
        <h2 className="h6 mb-0">
          <button
            type="button"
            className="btn btn-link text-decoration-none text-body w-100 d-flex justify-content-between align-items-center px-3 py-2"
            aria-expanded={open}
            aria-controls={bodyId}
            onClick={() => setOpen((v) => !v)}
          >
            <span className="fw-semibold">{title}</span>
            <span aria-hidden="true">{open ? "\u25B2" : "\u25BC"}</span>
          </button>
        </h2>
      </Card.Header>
      <Collapse in={open} mountOnEnter>
        <div id={bodyId}>
          <Card.Body>{children}</Card.Body>
        </div>
      </Collapse>
    </Card>
  );
}
