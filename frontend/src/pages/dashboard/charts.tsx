// Small chart primitives shared across dashboard panels. Kept dependency-free
// (plain SVG) to match the rest of the app.

import { useRef, useState } from "react";
import type { TrendPoint } from "./types";

export function Sparkline({ values, color }: { values: number[]; color: string }) {
  if (values.length < 2) return null;
  const W = 120;
  const H = 34;
  const max = Math.max(1, ...values);
  const min = Math.min(...values);
  const span = Math.max(1, max - min);
  const pts = values.map((v, i) => [(i * W) / (values.length - 1), H - 4 - ((v - min) / span) * (H - 8)] as const);
  const line = pts.map(([x, y], i) => `${i === 0 ? "M" : "L"}${x},${y}`).join(" ");
  return (
    <svg viewBox={`0 0 ${W} ${H}`} width="100%" height={H} aria-hidden="true" preserveAspectRatio="none" style={{ marginTop: 6 }}>
      <path d={`${line} L${W},${H} L0,${H} Z`} fill={color} opacity="0.18" />
      <path d={line} fill="none" stroke={color} strokeWidth="1.8" vectorEffect="non-scaling-stroke" />
    </svg>
  );
}

// The area chart used by the "Threat trend" panel. A trend needs at least two
// points to mean anything, so the caller is expected to show the stat-style
// empty state instead of rendering this for anything shorter -- this
// component assumes `points.length >= 2`.
export function TrendChart({ points }: { points: TrendPoint[] }) {
  const [hover, setHover] = useState<number | null>(null);
  const wrap = useRef<HTMLDivElement | null>(null);
  const W = 720;
  const H = 230;
  const pad = { l: 40, r: 16, t: 14, b: 26 };
  const max = Math.max(1, ...points.map((p) => p.open));
  const top = Math.ceil(max * 1.1);
  const x = (i: number) => pad.l + (i * (W - pad.l - pad.r)) / (points.length - 1);
  const y = (v: number) => pad.t + (1 - v / top) * (H - pad.t - pad.b);
  const line = points.map((p, i) => `${i === 0 ? "M" : "L"}${x(i)},${y(p.open)}`).join(" ");
  const area = `${line} L${x(points.length - 1)},${H - pad.b} L${x(0)},${H - pad.b} Z`;
  const last = points[points.length - 1];
  const first = points[0];
  const shown = hover !== null ? points[hover] : null;

  function onMove(event: React.MouseEvent<SVGSVGElement>) {
    const box = event.currentTarget.getBoundingClientRect();
    const px = ((event.clientX - box.left) / box.width) * W;
    let best = 0;
    for (let i = 1; i < points.length; i++) if (Math.abs(x(i) - px) < Math.abs(x(best) - px)) best = i;
    setHover(best);
  }

  return (
    <div>
      <div ref={wrap} style={{ position: "relative" }}>
        <svg
          viewBox={`0 0 ${W} ${H}`}
          width="100%"
          role="img"
          aria-label={`Open threats over time: ${first.open} on ${first.day}, ${last.open} on ${last.day}`}
          onMouseMove={onMove}
          onMouseLeave={() => setHover(null)}
        >
          <defs>
            <linearGradient id="pc-trend-fill" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="var(--pc-series)" stopOpacity="0.45" />
              <stop offset="100%" stopColor="var(--pc-series)" stopOpacity="0.02" />
            </linearGradient>
          </defs>
          {[0, 0.25, 0.5, 0.75, 1].map((f) => (
            <g key={f}>
              <line x1={pad.l} x2={W - pad.r} y1={y(top * f)} y2={y(top * f)} stroke="var(--pc-grid)" />
              <text x={pad.l - 8} y={y(top * f) + 4} textAnchor="end" fontSize="11" fill="var(--pc-muted)">
                {Math.round(top * f)}
              </text>
            </g>
          ))}
          <path d={area} fill="url(#pc-trend-fill)" />
          <path d={line} fill="none" stroke="var(--pc-series)" strokeWidth="2.5" strokeLinejoin="round" />
          {points.map((p, i) => (
            <circle
              key={p.day}
              cx={x(i)}
              cy={y(p.open)}
              r={hover === i ? 6 : 4}
              fill="var(--pc-series)"
              stroke="var(--pc-panel)"
              strokeWidth="2"
            />
          ))}
          {hover !== null && (
            <line x1={x(hover)} x2={x(hover)} y1={pad.t} y2={H - pad.b} stroke="var(--pc-muted)" strokeDasharray="3 3" />
          )}
          <text x={pad.l} y={H - 6} fontSize="11" fill="var(--pc-muted)">
            {first.day}
          </text>
          <text x={W - pad.r} y={H - 6} fontSize="11" textAnchor="end" fill="var(--pc-muted)">
            {last.day}
          </text>
        </svg>
        {shown && hover !== null && (
          <div
            className="pc-tooltip"
            style={{ left: `${(x(hover) / W) * 100}%`, top: 8, transform: hover > points.length / 2 ? "translateX(-105%)" : "translateX(8px)" }}
          >
            <div className="fw-semibold mb-1">{shown.day}</div>
            <div>
              <span className="pc-legend-swatch" style={{ background: "var(--pc-series)" }} />
              {shown.open} open
            </div>
            <div>
              <span className="pc-legend-swatch" style={{ background: "var(--pc-series-new)" }} />+{shown.new} new
            </div>
            <div>
              <span className="pc-legend-swatch" style={{ background: "var(--pc-series-resolved)" }} />-{shown.resolved} resolved
            </div>
          </div>
        )}
      </div>
      <div className="d-flex flex-wrap gap-3 small mt-2">
        <span>
          <strong>{last.open}</strong> open on {last.day}
        </span>
        <span style={{ color: "var(--pc-series-new)" }}>+{last.new} new since the previous snapshot</span>
        <span style={{ color: "var(--pc-series-resolved)" }}>-{last.resolved} resolved</span>
      </div>
    </div>
  );
}
