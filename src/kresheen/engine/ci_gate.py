"""CI/CD gate: decides pass/fail from a run diff and renders the PR comment.

Pure over `RunDiffOut` (the same shape `GET .../runs/{id}/diff` returns), so
the `kresheen ci` command is a thin HTTP client around it and this logic is
testable without a server. Only what a run *newly introduced* can fail the
gate -- pre-existing findings/threats are the baseline, not the PR's fault.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from kresheen.models.run_diff import RunDiffOut

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
COMMENT_MARKER = "<!-- kresheen-ci -->"
_LIST_CAP = 15


@dataclass(frozen=True)
class GateOptions:
    # Fail on a new finding/threat at or above this severity; None disables.
    fail_on: str | None = "critical"
    fail_on_boundary_crossing: bool = True


@dataclass
class GateResult:
    passed: bool
    violations: list[str] = field(default_factory=list)
    markdown: str = ""


def severity_rank(severity: str) -> int:
    try:
        return SEVERITY_ORDER.index(severity.lower())
    except ValueError:
        return -1


def evaluate_gate(diff: RunDiffOut, options: GateOptions, *, run_url: str | None = None) -> GateResult:
    violations: list[str] = []
    if diff.previous_run_id is not None:
        if options.fail_on is not None:
            threshold = severity_rank(options.fail_on)
            for f in diff.new_findings:
                if severity_rank(f.severity) >= threshold:
                    violations.append(f"New {f.severity} finding: {f.title}")
            for t in diff.new_threats:
                if severity_rank(t.severity) >= threshold:
                    violations.append(f"New {t.severity} threat: {t.title}")
        if options.fail_on_boundary_crossing:
            for flow in diff.new_flows:
                if flow.crosses_boundary:
                    violations.append(
                        f"New flow crosses a trust boundary: {flow.source_name} -> {flow.target_name}"
                    )
    if diff.previous_run_id is not None and options.fail_on_boundary_crossing:
        for change in diff.boundary_changes:
            violations.append(
                f"Component moved trust boundary: {change.name} "
                f"({change.from_boundary or 'unassigned'} -> {change.to_boundary or 'unassigned'})"
            )
    result = GateResult(passed=not violations, violations=violations)
    result.markdown = render_markdown(diff, result, options, run_url=run_url)
    return result


def _bullets(lines: list[str]) -> list[str]:
    out = [f"- {line}" for line in lines[:_LIST_CAP]]
    if len(lines) > _LIST_CAP:
        out.append(f"- ...and {len(lines) - _LIST_CAP} more")
    return out


def _md(text: str) -> str:
    """Names/titles come from scanned repos and diagrams: keep them from
    injecting markup or @-mentions into a PR comment."""
    cleaned = "".join(ch for ch in text if ch.isprintable()).replace("`", "'")
    return cleaned.replace("@", "@\u200b").replace("<", "&lt;").replace("[", "\\[")


def render_markdown(diff: RunDiffOut, result: GateResult, options: GateOptions, *, run_url: str | None) -> str:
    lines = [COMMENT_MARKER, f"## Kresheen threat model: {'passed' if result.passed else 'FAILED'}", ""]
    if diff.previous_run_id is None:
        lines += ["No earlier completed run to compare against, so nothing was gated. This run is the baseline.", ""]
    else:
        lines += [
            "| | New | Resolved |",
            "|---|---|---|",
            f"| Findings | {len(diff.new_findings)} | {len(diff.resolved_findings)} |",
            f"| Threats | {len(diff.new_threats)} | {len(diff.resolved_threats)} |",
            f"| Components | {len(diff.new_components)} | {len(diff.removed_components)} |",
            f"| Flows | {len(diff.new_flows)} | {len(diff.removed_flows)} |",
            f"| Boundary moves | {len(diff.boundary_changes)} | |",
            "",
        ]
    if result.violations:
        lines += ["### Gate violations", *_bullets([_md(v) for v in result.violations]), ""]
        rules = []
        if options.fail_on:
            rules.append(f"new finding/threat at or above `{options.fail_on}`")
        if options.fail_on_boundary_crossing:
            rules.append("new trust-boundary-crossing flow or component moving boundary")
        lines += [f"Gate rules: {', '.join(rules)}.", ""]
    crossing = [f for f in diff.new_flows if f.crosses_boundary]
    if crossing and not options.fail_on_boundary_crossing:
        lines += ["### New trust-boundary crossings", *_bullets([_md(f"{f.source_name} -> {f.target_name}") for f in crossing]), ""]
    if diff.new_components:
        lines += ["### New components", *_bullets([_md(f"{c.name} ({c.type})") for c in diff.new_components]), ""]
    if run_url:
        lines += [f"[Open the run in Kresheen]({run_url})"]
    return "\n".join(lines).rstrip() + "\n"
