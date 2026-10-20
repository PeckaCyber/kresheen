import { RANGE_OPTIONS } from "./types";

export function ExecutiveSummaryPanel({
  days,
  onRangeChange,
}: {
  days: number;
  onRangeChange: (days: number) => void;
}) {
  return (
    <section className="pc-panel mb-3" aria-label="Overview">
      <div className="pc-panel-body d-flex flex-wrap justify-content-between align-items-center gap-3">
        <span className="text-muted">Everything you can see, over the selected time range.</span>
        <div className="pc-segctl" role="group" aria-label="Time range">
          {RANGE_OPTIONS.map((option) => (
            <button
              key={option.label}
              type="button"
              className={`pc-segctl-btn${days === option.days ? " active" : ""}`}
              aria-pressed={days === option.days}
              onClick={() => onRangeChange(option.days)}
            >
              {option.label}
            </button>
          ))}
        </div>
      </div>
    </section>
  );
}
