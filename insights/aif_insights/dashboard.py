"""Phase A2b: one local HTML page with the weekly KPI trends.

    aif-insights dashboard [--out DIR] [--weeks N] [--html PATH]

The page is built from the derived tables and is self-contained (no scripts
or fonts from the network). It holds private data, so it stays on this
machine: it is written under the derived folder, never into the repository.
"""
from __future__ import annotations

import html
from datetime import UTC, datetime
from pathlib import Path

from aif_insights.derive import DEFAULT_OUT, kpis, pr_kpis

#: (column, title, unit note). Order is the page order.
SESSION_KPIS = [
    ("sessions", "Sessions", "count"),
    ("correction_loops", "Correction loops per session", "corrections + interrupts"),
    ("autonomy_span_min", "Autonomy span", "median minutes between human interventions"),
    ("abandoned_rate", "Abandoned-session rate", "share with no commit, push or PR"),
    ("tool_error_rate", "Tool error rate", "failed tool calls / tool calls"),
    ("test_loop_rate", "Test-loop rate", "share of sessions failing one test 3+ times"),
    ("cost_usd", "Cost", "USD, Claude only, token-equivalent"),
]
PR_KPIS = [
    ("merged", "Merged PRs", "count, by week opened"),
    ("cost_per_merged_pr", "Cost per merged PR", "USD, Claude only, token-equivalent"),
    ("first_pass_ci", "First-pass CI rate", "share green on first CI run, docs-only excluded"),
    ("rework_rate", "Rework rate", "share with commits after the first review"),
    ("attention_min_per_merged_pr", "Human attention per merged PR", "estimated minutes"),
    ("lead_time_h", "Lead time", "median hours, opened to merged"),
]
#: Reference categorical palette, fixed order (light, dark).
SERIES = [("#2a78d6", "#3987e5"), ("#eb6834", "#d95926"), ("#1baf7a", "#199e70"),
          ("#eda100", "#c98500"), ("#e87ba4", "#d55181"), ("#008300", "#0ca30c"),
          ("#6250d6", "#9085e9"), ("#e34948", "#e66767")]
W, H, PAD_L, PAD_R, PAD_T, PAD_B = 520, 230, 48, 150, 14, 34
LABEL_GAP = 14


def _series(columns: list[str], rows: list[tuple]) -> tuple[list[str], dict[str, dict[str, dict]]]:
    weeks = sorted({r[0] for r in rows})
    out: dict[str, dict[str, dict]] = {}
    for r in rows:
        rec = dict(zip(columns, r, strict=True))
        out.setdefault(f"{rec['agent']} · {rec['mode']}", {})[rec["week"]] = rec
    return weeks, dict(sorted(out.items()))


def _tick(v: float, top: float) -> str:
    return f"{v:,.0f}" if top >= 10 else f"{v:.2f}".rstrip("0").rstrip(".")


def _fmt(v) -> str:
    if v is None:
        return "–"
    if isinstance(v, float):
        return f"{v:,.3f}".rstrip("0").rstrip(".") if abs(v) < 10 else f"{v:,.1f}"
    return f"{v:,}"


def _chart(key: str, title: str, note: str, weeks: list[str],
           series: dict[str, dict[str, dict]], colors: dict[str, int]) -> str:
    values = [s[w][key] for s in series.values() for w in s if s[w].get(key) is not None]
    if not values:
        return (f'<section class="card"><h3>{html.escape(title)}</h3>'
                f'<p class="note">{html.escape(note)}</p><p class="empty">No data yet.</p></section>')
    top = max(values) or 1
    x0, x1, y0, y1 = PAD_L, W - PAD_R, H - PAD_B, PAD_T

    def x(i: int) -> float:
        return x0 + (x1 - x0) * (i / max(len(weeks) - 1, 1))

    def y(v: float) -> float:
        return y0 - (y0 - y1) * (v / top)

    parts = [f'<line class="axis" x1="{x0}" y1="{y0}" x2="{x1}" y2="{y0}"/>']
    for frac in (0.5, 1.0):
        parts.append(f'<line class="grid" x1="{x0}" y1="{y(top * frac):.1f}" x2="{x1}" '
                     f'y2="{y(top * frac):.1f}"/><text class="tick" x="{x0 - 6}" '
                     f'y="{y(top * frac) + 4:.1f}" text-anchor="end">{_tick(top * frac, top)}</text>')
    parts.append(f'<text class="tick" x="{x0 - 6}" y="{y0 + 4}" text-anchor="end">0</text>')
    for i in sorted({0, len(weeks) - 1, len(weeks) // 2}):
        anchor = "start" if i == 0 else "end" if i == len(weeks) - 1 else "middle"
        parts.append(f'<text class="tick" x="{x(i):.1f}" y="{H - 6}" text-anchor="{anchor}">'
                     f'{weeks[i][5:]}</text>')
    labels = []
    for name, points in series.items():
        slot = colors[name]
        pts = [(i, points[w][key]) for i, w in enumerate(weeks)
               if w in points and points[w].get(key) is not None]
        if not pts:
            continue
        path = " ".join(f"{'M' if j == 0 else 'L'}{x(i):.1f},{y(v):.1f}" for j, (i, v) in enumerate(pts))
        parts.append(f'<path class="line s{slot}" d="{path}"/>')
        for i, v in pts:
            tip = html.escape(f"{name}, week of {weeks[i]}: {_fmt(v)}")
            parts.append(f'<g class="pt"><circle class="dot s{slot}" cx="{x(i):.1f}" cy="{y(v):.1f}" '
                         f'r="4"/><circle class="hit" cx="{x(i):.1f}" cy="{y(v):.1f}" r="12">'
                         f'<title>{tip}</title></circle></g>')
        labels.append((y(pts[-1][1]), name))
    # End labels, nudged apart so they never overlap.
    # End labels: spaced at least LABEL_GAP apart, then lifted together if the
    # lowest would drop below the plot, so they never overlap or hit the axis.
    labels.sort()
    placed: list[float] = []
    for want, _name in labels:
        placed.append(max(want, placed[-1] + LABEL_GAP) if placed else want)
    lift = max(0.0, (placed[-1] if placed else 0) - y0)
    for (_want, name), ly in zip(labels, (p - lift for p in placed), strict=True):
        parts.append(f'<text class="end" x="{x1 + 8}" y="{ly + 4:.1f}">{html.escape(name.split(" · ")[0])}'
                     f' <tspan class="muted">{html.escape(name.split(" · ")[1])}</tspan></text>')
    table = "".join(
        f"<tr><td>{w}</td>" + "".join(f"<td>{_fmt(series[n].get(w, {}).get(key))}</td>" for n in series)
        + "</tr>" for w in weeks)
    head = "".join(f"<th>{html.escape(n)}</th>" for n in series)
    return (f'<section class="card"><h3>{html.escape(title)}</h3><p class="note">{html.escape(note)}</p>'
            f'<svg viewBox="0 0 {W} {H}" role="img" aria-label="{html.escape(title)} by week">'
            f'{"".join(parts)}</svg><details><summary>Table</summary><table><thead><tr><th>Week</th>'
            f'{head}</tr></thead><tbody>{table}</tbody></table></details></section>')


def _legend(colors: dict[str, int]) -> str:
    return '<ul class="legend">' + "".join(
        f'<li><span class="swatch s{slot}"></span>{html.escape(name)}</li>'
        for name, slot in colors.items()) + "</ul>"


def render(out: Path = DEFAULT_OUT, weeks: int = 12) -> str:
    columns, rows = kpis(out, weeks)
    s_weeks, s_series = _series(columns, rows)
    try:
        pcolumns, prows = pr_kpis(out, weeks)
    except FileNotFoundError:
        pcolumns, prows = [], []
    p_weeks, p_series = _series(pcolumns, prows) if prows else ([], {})
    names = sorted(set(s_series) | set(p_series))
    colors = {n: i % len(SERIES) + 1 for i, n in enumerate(names)}  # entity -> fixed slot
    slots = "\n".join(f"  --s{i}: {light};" for i, (light, _) in enumerate(SERIES, 1))
    dark = "\n".join(f"  --s{i}: {d};" for i, (_, d) in enumerate(SERIES, 1))
    rules = "\n".join(f".s{i}{{stroke:var(--s{i});fill:var(--s{i})}} .line.s{i}{{fill:none}} "
                      f".swatch.s{i}{{background:var(--s{i})}}" for i in range(1, len(SERIES) + 1))
    s_cards = "".join(_chart(k, t, n, s_weeks, s_series, colors) for k, t, n in SESSION_KPIS) \
        if s_weeks else '<p class="empty">No sessions in this period.</p>'
    p_cards = "".join(_chart(k, t, n, p_weeks, p_series, colors) for k, t, n in PR_KPIS) \
        if p_weeks else '<p class="empty">No linked PRs yet: run <code>aif-insights github</code>.</p>'
    built = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Factory KPIs</title>
<style>
:root {{
  color-scheme: light;
  --bg: #fcfcfb; --card: #ffffff; --ink: #0b0b0b; --ink-2: #52514e; --rule: #e4e3df;
{slots}
}}
@media (prefers-color-scheme: dark) {{
  :root:not([data-theme="light"]) {{
    color-scheme: dark;
    --bg: #1a1a19; --card: #222221; --ink: #f0efec; --ink-2: #c3c2b7; --rule: #3a3a38;
{dark}
  }}
}}
:root[data-theme="dark"] {{
  color-scheme: dark;
  --bg: #1a1a19; --card: #222221; --ink: #f0efec; --ink-2: #c3c2b7; --rule: #3a3a38;
{dark}
}}
* {{ box-sizing: border-box; }}
body {{ margin: 0; padding: 24px 16px 48px; background: var(--bg); color: var(--ink);
  font: 14px/1.45 system-ui, -apple-system, "Segoe UI", sans-serif; }}
main {{ max-width: 1180px; margin: 0 auto; }}
h1 {{ font-size: 22px; margin: 0 0 4px; }} h2 {{ font-size: 16px; margin: 32px 0 4px; }}
h3 {{ font-size: 14px; margin: 0; }}
.note, .sub {{ color: var(--ink-2); margin: 2px 0 8px; font-size: 12.5px; }}
.grid-cards {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(min(100%, 460px), 1fr)); gap: 16px; }}
.card {{ background: var(--card); border: 1px solid var(--rule); border-radius: 10px; padding: 14px 14px 8px; min-width: 0; }}
svg {{ width: 100%; height: auto; display: block; overflow: visible; }}
.axis {{ stroke: var(--ink-2); stroke-width: 1; }} .grid {{ stroke: var(--rule); stroke-width: 1; }}
.tick {{ fill: var(--ink-2); font-size: 11px; }}
.end {{ fill: var(--ink); font-size: 11.5px; }} .muted {{ fill: var(--ink-2); }}
.line {{ stroke-width: 2; stroke-linejoin: round; stroke-linecap: round; }}
.dot {{ stroke: var(--card); stroke-width: 2; }}
.hit {{ fill: transparent; stroke: none; cursor: crosshair; }}
.pt:hover .dot {{ r: 6; }}
{rules}
.legend {{ list-style: none; display: flex; flex-wrap: wrap; gap: 6px 18px; padding: 0; margin: 12px 0 0; }}
.legend li {{ display: flex; align-items: center; gap: 6px; font-size: 13px; }}
.swatch {{ width: 14px; height: 3px; border-radius: 2px; display: inline-block; }}
details {{ margin-top: 6px; font-size: 12.5px; }} summary {{ cursor: pointer; color: var(--ink-2); }}
table {{ border-collapse: collapse; width: 100%; margin-top: 6px; overflow-x: auto; display: block; }}
th, td {{ text-align: right; padding: 3px 8px; border-bottom: 1px solid var(--rule); white-space: nowrap; }}
th:first-child, td:first-child {{ text-align: left; }}
.empty {{ color: var(--ink-2); }}
code {{ font-size: 12.5px; }}
</style></head>
<body><main>
<h1>Factory KPIs</h1>
<p class="sub">Weekly, last {int(weeks)} weeks, built {built}. Trends, not targets: two developers make small samples.
Hover a point for its value; each chart has a table.</p>
{_legend(colors)}
<h2>Sessions</h2>
<p class="sub">By week the session started. Headless sessions are runs started by a program.</p>
<div class="grid-cards">{s_cards}</div>
<h2>Pull requests</h2>
<p class="sub">PRs linked to at least one session, by week opened. A session linked to several PRs splits its cost and attention evenly.</p>
<div class="grid-cards">{p_cards}</div>
</main></body></html>
"""


def write(out: Path = DEFAULT_OUT, weeks: int = 12, target: Path | None = None) -> Path:
    target = (target or out / "dashboard.html").expanduser()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render(out.expanduser(), weeks), encoding="utf-8")
    return target
