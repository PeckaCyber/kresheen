import { Col, Row } from "react-bootstrap";

export interface StatStripItem {
  key: string;
  label: string;
  value: string;
  tone: string;
  onClick: () => void;
}

// The run page's 6-tile stat strip: compact versions of the dashboard's
// .pc-stat tiles (see pages/dashboard/StatTiles.tsx) -- smaller value type
// (.pc-stat-compact in theme.css) so they don't dominate the page the way the
// full-size dashboard tiles do. Each tile switches the page to the tab that
// explains the number.
export function StatStrip({ items, compact = false }: { items: StatStripItem[]; compact?: boolean }) {
  if (compact) {
    return (
      <div className="pc-stat-strip-compact">
        {items.map((item) => (
          <button
            key={item.key}
            type="button"
            className={`pc-stat-chip pc-tone-${item.tone}`}
            data-testid={`model-stat-${item.key}`}
            onClick={item.onClick}
            title={`${item.label}: ${item.value}`}
          >
            {item.label} <span className="pc-stat-chip-value">{item.value}</span>
          </button>
        ))}
      </div>
    );
  }

  return (
    <Row xs={2} md={3} xl={6} className="g-2 mb-3">
      {items.map((item) => (
        <Col key={item.key}>
          <button
            type="button"
            className={`pc-stat pc-stat-compact pc-tone-${item.tone}`}
            data-testid={`model-stat-${item.key}`}
            onClick={item.onClick}
          >
            <div className="pc-stat-label">{item.label}</div>
            <div className="pc-stat-value">{item.value}</div>
          </button>
        </Col>
      ))}
    </Row>
  );
}
