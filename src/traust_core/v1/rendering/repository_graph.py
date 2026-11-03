from __future__ import annotations

import base64
import hashlib
import json
from xml.etree import ElementTree

from traust_core.v1.models.repository_graph import RepositoryGraph
from traust_core.v1.rendering.html import _table, _text
from traust_core.v1.rendering.markdown import Report

_CSS = """
:root {
  color-scheme: light;
  --ink: #151515;
  --muted: #555b61;
  --rule: #c9ced3;
  --paper: #fff;
  --focus: #0759b1;
  --accent: #155a8a;
  --soft: #f4f6f8;
}
* {
  box-sizing: border-box;
}
body {
  font:
    14px/1.5 system-ui,
    sans-serif;
  margin: 0;
  color: var(--ink);
  background: var(--paper);
}
header,
.controls,
.workspace,
.statistics {
  max-width: 100rem;
  margin: 0 auto;
}
header {
  padding: 1.4rem 1.5rem 0.75rem;
}
h1 {
  font-size: 1.75rem;
  line-height: 1.2;
  margin: 0 0 0.4rem;
}
p {
  max-width: 72ch;
  margin: 0.4rem 0;
}
.meta,
.hint {
  color: var(--muted);
}
.controls {
  display: flex;
  align-items: end;
  gap: 0.7rem;
  flex-wrap: wrap;
  padding: 0.75rem 1.5rem 1rem;
}
label {
  display: flex;
  flex-direction: column;
  gap: 0.3rem;
  font-weight: 600;
}
input,
select,
button {
  font: inherit;
  color: inherit;
  background: var(--paper);
  border: 1px solid var(--rule);
  border-radius: 4px;
  padding: 0.55rem 0.7rem;
  min-height: 44px;
}
input {
  width: min(24rem, 75vw);
  caret-color: var(--focus);
}
button {
  cursor: pointer;
}
button:hover {
  background: var(--soft);
  border-color: var(--accent);
}
button:disabled {
  opacity: 0.5;
  cursor: default;
}
:focus-visible {
  outline: 3px solid var(--focus);
  outline-offset: 3px;
}
::selection {
  background: #cce6fa;
  color: #151515;
}
a {
  color: #0759b1;
  text-underline-offset: 0.2em;
}
.workspace {
  display: grid;
  grid-template-columns: minmax(0, 1fr) 19rem;
  border-block: 1px solid var(--rule);
}
.map {
  min-width: 0;
  position: relative;
  background: var(--soft);
}
canvas {
  display: block;
  width: 100%;
  height: 65vh;
  min-height: 360px;
  touch-action: none;
  cursor: grab;
}
canvas.dragging {
  cursor: grabbing;
}
#status {
  position: absolute;
  bottom: 0.6rem;
  left: 0.8rem;
  background: var(--paper);
  padding: 0.3rem 0.5rem;
  font-variant-numeric: tabular-nums;
  pointer-events: none;
}
.legend {
  display: flex;
  gap: 1rem;
  flex-wrap: wrap;
  padding: 0.6rem 0.8rem;
  border-top: 1px solid var(--rule);
  font-size: 0.85rem;
}
.legend span::before {
  content: "";
  display: inline-block;
  width: 0.65rem;
  height: 0.65rem;
  margin-right: 0.35rem;
  background: var(--swatch);
  border: 1px solid #39424a;
  border-radius: 50%;
}
aside {
  padding: 1rem;
  max-height: 75vh;
  overflow: auto;
  border-left: 1px solid var(--rule);
  scrollbar-color: #7a8793 var(--soft);
}
aside h2 {
  font-size: 1rem;
  margin: 0 0 0.5rem;
}
#details {
  overflow-wrap: anywhere;
}
#results {
  list-style: none;
  padding: 0;
  margin: 0.6rem 0;
}
#results li {
  border-bottom: 1px solid var(--rule);
  padding: 0.6rem 0;
}
#results button {
  border: 0;
  padding: 0;
  min-height: 44px;
  text-align: left;
  color: var(--accent);
  background: none;
  overflow-wrap: anywhere;
}
#results small {
  display: block;
  color: var(--muted);
}
.statistics {
  padding: 1.4rem 1.5rem 3rem;
}
summary {
  font-size: 1.1rem;
  font-weight: 600;
  cursor: pointer;
  padding: 0.4rem 0;
}
.statistics h2 {
  font-size: 1.15rem;
  margin: 1.5rem 0 0.6rem;
}
.table-wrap {
  overflow-x: auto;
}
table {
  border-collapse: collapse;
  font-variant-numeric: tabular-nums;
}
th,
td {
  border: 1px solid var(--rule);
  padding: 0.4rem 0.6rem;
  text-align: left;
}
th {
  background: var(--soft);
}
.sr-only {
  position: absolute;
  width: 1px;
  height: 1px;
  padding: 0;
  margin: -1px;
  overflow: hidden;
  clip: rect(0, 0, 0, 0);
  white-space: nowrap;
  border: 0;
}
@media (max-width: 700px) {
  header,
  .controls {
    padding-inline: 1rem;
  }
  .workspace {
    grid-template-columns: 1fr;
  }
  canvas {
    height: 55vh;
    min-height: 320px;
  }
  aside {
    max-height: 25rem;
    border-left: 0;
    border-top: 1px solid var(--rule);
  }
  .controls label:first-child {
    width: 100%;
  }
  input {
    width: 100%;
  }
  .statistics {
    padding-inline: 1rem;
  }
}
@media (prefers-reduced-motion: reduce) {
  * {
    scroll-behavior: auto !important;
  }
}
"""

_SCRIPT = r"""
"use strict";
const data = JSON.parse(document.getElementById("graph-data").textContent);
const canvas = document.getElementById("graph"),
  ctx = canvas.getContext("2d");
const search = document.getElementById("search"),
  segment = document.getElementById("segment");
const status = document.getElementById("status"),
  results = document.getElementById("results");
const details = document.getElementById("details"),
  count = document.getElementById("result-count");
const all = new Map(data.nodes.map((n) => [n.id, n]));
const collapsed = new Set(["product-version", "category", "repo-ref", "findings"]);
const outgoing = new Map();
for (const e of data.edges) {
  if (!outgoing.has(e.from)) outgoing.set(e.from, []);
  outgoing.get(e.from).push(e);
}
const base = data.nodes.filter((n) => !collapsed.has(n.type));
const baseIds = new Set(base.map((n) => n.id)),
  projected = new Map();
for (const n of base) {
  const queue = [...(outgoing.get(n.id) || [])],
    seen = new Set();
  while (queue.length) {
    const e = queue.pop();
    if (seen.has(e.to)) continue;
    seen.add(e.to);
    if (baseIds.has(e.to)) {
      const key = n.id + "\n" + e.to;
      projected.set(key, { from: n.id, to: e.to, rel: e.rel });
    } else for (const next of outgoing.get(e.to) || []) queue.push(next);
  }
}
let shown = [],
  edges = [],
  positions = new Map(),
  zoom = 1,
  pan = { x: 0, y: 0 },
  selected = null,
  drag = null,
  moved = false;
const colors = {
  critical: "#b02027",
  high: "#b24d07",
  medium: "#8a6500",
  low: "#287545",
  informational: "#4b6274",
};
const kindColors = {
  segment: "#1d5b82",
  product: "#557b97",
  release: "#557b97",
  "owner-team": "#6b568a",
};
const column = { segment: 0, product: 1, release: 1, "owner-team": 1, repo: 2 };
function safeUrl(value) {
  try {
    const u = new URL(value);
    return ["https:", "http:"].includes(u.protocol) ? u.href : null;
  } catch {
    return null;
  }
}
function nodeColor(n) {
  return n.type === "repo"
    ? colors[n.attrs.max_severity] || "#707b85"
    : kindColors[n.type] || "#707b85";
}
function update() {
  const text = search.value.trim().toLocaleLowerCase(),
    focus = segment.value;
  let pool = base.filter(
    (n) =>
      !focus || n.attrs.segment === focus || (n.attrs.segments || []).includes(focus),
  );
  let ids = new Set(pool.map((n) => n.id));
  if (focus) {
    for (const e of projected.values())
      if (ids.has(e.to) && all.get(e.from).type === "owner-team") ids.add(e.from);
    pool = base.filter((n) => ids.has(n.id));
  }
  if (text) {
    const matches = new Set(
      pool
        .filter((n) =>
          [n.label, n.attrs.url || "", n.attrs.branch || ""]
            .join(" ")
            .toLocaleLowerCase()
            .includes(text),
        )
        .map((n) => n.id),
    );
    const neighbours = new Set(matches);
    for (const e of projected.values())
      if (matches.has(e.from) || matches.has(e.to)) {
        if (ids.has(e.from)) neighbours.add(e.from);
        if (ids.has(e.to)) neighbours.add(e.to);
      }
    pool = pool.filter((n) => neighbours.has(n.id));
  }
  shown = pool;
  ids = new Set(shown.map((n) => n.id));
  edges = [...projected.values()].filter((e) => ids.has(e.from) && ids.has(e.to));
  if (selected && !ids.has(selected)) selected = null;
  const groups = new Map();
  for (const n of shown) {
    const c = column[n.type] ?? 2;
    if (!groups.has(c)) groups.set(c, []);
    groups.get(c).push(n);
  }
  positions = new Map();
  for (const [c, ns] of groups) {
    ns.sort((a, b) => a.label.localeCompare(b.label));
    ns.forEach((n, i) => positions.set(n.id, { x: 80 + c * 370, y: 50 + i * 36 }));
  }
  renderResults();
  fit();
}
function renderResults() {
  results.replaceChildren();
  const repos = shown.filter((n) => n.type === "repo");
  count.textContent =
    repos.length +
    " repositories in this view" +
    (repos.length > 100 ? " · first 100 listed; refine search" : "");
  for (const n of repos.slice(0, 100)) {
    const li = document.createElement("li"),
      b = document.createElement("button"),
      s = document.createElement("small");
    b.textContent = n.label;
    b.addEventListener("click", () => select(n.id, true));
    s.textContent =
      (n.attrs.max_severity || "Unrated") +
      " · " +
      (n.attrs.findings === "assessed" ? "assessed" : "no assessment");
    li.append(b, s);
    results.append(li);
  }
  if (!shown.length) {
    const li = document.createElement("li");
    li.textContent =
      "No matching repositories or relationships. Clear search or choose another segment.";
    results.append(li);
  }
  describe();
}
function describe() {
  details.replaceChildren();
  if (!selected) {
    details.textContent =
      "Select a node to inspect its relationships. Double-click a repository to open its source.";
    return;
  }
  const n = all.get(selected),
    title = document.createElement("strong"),
    p = document.createElement("p");
  title.textContent = n.label;
  const related = data.edges.filter((e) => e.from === selected || e.to === selected);
  p.textContent = n.type + " · " + related.length + " recorded relationships";
  details.append(title, p);
  if (n.type === "repo") {
    const p = document.createElement("p");
    p.textContent =
      (n.attrs.open_findings ?? "Unmeasured") +
      " open findings · " +
      (n.attrs.resolved_findings ?? "Unmeasured") +
      " resolved";
    details.append(p);
  }
  const url = safeUrl(n.attrs.url);
  if (url) {
    const a = document.createElement("a");
    a.href = url;
    a.target = "_blank";
    a.rel = "noopener noreferrer";
    a.textContent = "Open source repository";
    details.append(a);
  }
  const list = document.createElement("ul");
  for (const e of related.slice(0, 50)) {
    const li = document.createElement("li");
    const other = all.get(e.from === selected ? e.to : e.from);
    li.textContent = e.rel + " · " + (other ? other.label : "Unknown node");
    list.append(li);
  }
  details.append(list);
  if (related.length > 50) {
    const p = document.createElement("p");
    p.textContent =
      "First 50 relationships shown; the JSON export contains all " +
      related.length +
      ".";
    details.append(p);
  }
}
function size() {
  const r = canvas.getBoundingClientRect(),
    d = window.devicePixelRatio || 1;
  canvas.width = Math.round(r.width * d);
  canvas.height = Math.round(r.height * d);
  ctx.setTransform(d, 0, 0, d, 0, 0);
  fit();
}
function fit() {
  const r = canvas.getBoundingClientRect();
  const ps = [...positions.values()];
  if (!ps.length) {
    zoom = 1;
    pan = { x: r.width / 2, y: r.height / 2 };
    draw();
    return;
  }
  const maxX = Math.max(...ps.map((p) => p.x)) + 100,
    maxY = Math.max(...ps.map((p) => p.y)) + 40;
  zoom = Math.min(r.width / maxX, r.height / maxY, 1.3) * 0.9;
  pan = { x: (r.width - maxX * zoom) / 2, y: (r.height - maxY * zoom) / 2 };
  draw();
}
function draw() {
  const r = canvas.getBoundingClientRect();
  ctx.clearRect(0, 0, r.width, r.height);
  ctx.save();
  ctx.translate(pan.x, pan.y);
  ctx.scale(zoom, zoom);
  const neighbours = new Set(selected ? [selected] : []);
  if (selected)
    for (const e of edges) {
      if (e.from === selected) neighbours.add(e.to);
      if (e.to === selected) neighbours.add(e.from);
    }
  ctx.lineWidth = 1 / zoom;
  for (const e of edges) {
    const a = positions.get(e.from),
      b = positions.get(e.to);
    if (!a || !b) continue;
    ctx.strokeStyle =
      selected && !(e.from === selected || e.to === selected) ? "#d7dce1" : "#9ca9b4";
    ctx.beginPath();
    ctx.moveTo(a.x, a.y);
    ctx.lineTo(b.x, b.y);
    ctx.stroke();
  }
  for (const n of shown) {
    const p = positions.get(n.id);
    if (
      p.x * zoom + pan.x < -150 ||
      p.x * zoom + pan.x > r.width + 150 ||
      p.y * zoom + pan.y < -30 ||
      p.y * zoom + pan.y > r.height + 30
    )
      continue;
    ctx.globalAlpha = selected && !neighbours.has(n.id) ? 0.28 : 1;
    ctx.fillStyle = nodeColor(n);
    ctx.beginPath();
    ctx.arc(p.x, p.y, n.id === selected ? 8 : 5, 0, Math.PI * 2);
    ctx.fill();
    if (n.id === selected) {
      ctx.strokeStyle = "#151515";
      ctx.lineWidth = 2 / zoom;
      ctx.stroke();
    }
    if (zoom > 0.55 || shown.length < 45 || n.id === selected) {
      ctx.fillStyle = "#151515";
      ctx.font = 12 / Math.max(zoom, 0.7) + "px system-ui,sans-serif";
      ctx.fillText(
        n.label.length > 46 ? n.label.slice(0, 43) + "…" : n.label,
        p.x + 11,
        p.y + 4,
      );
    }
  }
  ctx.globalAlpha = 1;
  ctx.restore();
  status.textContent =
    shown.length +
    " nodes · " +
    edges.length +
    " relationships · " +
    Math.round(zoom * 100) +
    "%";
}
function hit(event) {
  const r = canvas.getBoundingClientRect(),
    x = (event.clientX - r.left - pan.x) / zoom,
    y = (event.clientY - r.top - pan.y) / zoom;
  let found = null,
    distance = 14 / zoom;
  for (const n of shown) {
    const p = positions.get(n.id),
      d = Math.hypot(p.x - x, p.y - y);
    if (d < distance) {
      found = n;
      distance = d;
    }
  }
  return found;
}
function select(id, center) {
  selected = id;
  describe();
  if (center) {
    const p = positions.get(id),
      r = canvas.getBoundingClientRect();
    zoom = Math.max(zoom, 1);
    pan = { x: r.width / 2 - p.x * zoom, y: r.height / 2 - p.y * zoom };
  }
  draw();
}
function changeZoom(factor, x, y) {
  const before = zoom;
  zoom = Math.min(5, Math.max(0.01, zoom * factor));
  pan = { x: x - ((x - pan.x) * zoom) / before, y: y - ((y - pan.y) * zoom) / before };
  draw();
}
canvas.addEventListener("pointerdown", (e) => {
  drag = { x: e.clientX, y: e.clientY, pan: { ...pan } };
  moved = false;
  canvas.setPointerCapture(e.pointerId);
  canvas.classList.add("dragging");
});
canvas.addEventListener("pointermove", (e) => {
  if (!drag) return;
  const dx = e.clientX - drag.x,
    dy = e.clientY - drag.y;
  if (Math.hypot(dx, dy) > 4) moved = true;
  pan = { x: drag.pan.x + dx, y: drag.pan.y + dy };
  draw();
});
canvas.addEventListener("pointerup", (e) => {
  if (!moved) {
    const n = hit(e);
    selected = n ? n.id : null;
    describe();
    draw();
  }
  drag = null;
  canvas.classList.remove("dragging");
});
canvas.addEventListener("pointercancel", () => {
  drag = null;
  canvas.classList.remove("dragging");
});
canvas.addEventListener("dblclick", (e) => {
  const n = hit(e),
    url = n && safeUrl(n.attrs.url);
  if (url) window.open(url, "_blank", "noopener,noreferrer");
});
canvas.addEventListener(
  "wheel",
  (e) => {
    e.preventDefault();
    const r = canvas.getBoundingClientRect();
    changeZoom(Math.exp(-e.deltaY * 0.001), e.clientX - r.left, e.clientY - r.top);
  },
  { passive: false },
);
canvas.addEventListener("keydown", (e) => {
  const r = canvas.getBoundingClientRect();
  if (
    [
      "+",
      "=",
      "-",
      "Home",
      "ArrowLeft",
      "ArrowRight",
      "ArrowUp",
      "ArrowDown",
      "Escape",
    ].includes(e.key)
  )
    e.preventDefault();
  if (e.key === "+" || e.key === "=") changeZoom(1.25, r.width / 2, r.height / 2);
  else if (e.key === "-") changeZoom(0.8, r.width / 2, r.height / 2);
  else if (e.key === "Home") fit();
  else if (e.key === "Escape") {
    selected = null;
    describe();
    draw();
  } else if (e.key.startsWith("Arrow")) {
    pan.x += e.key === "ArrowLeft" ? 40 : e.key === "ArrowRight" ? -40 : 0;
    pan.y += e.key === "ArrowUp" ? 40 : e.key === "ArrowDown" ? -40 : 0;
    draw();
  }
});
for (const [id, factor] of [
  ["zoom-in", 1.25],
  ["zoom-out", 0.8],
])
  document.getElementById(id).addEventListener("click", () => {
    const r = canvas.getBoundingClientRect();
    changeZoom(factor, r.width / 2, r.height / 2);
  });
document.getElementById("fit").addEventListener("click", fit);
document.getElementById("clear").addEventListener("click", () => {
  search.value = "";
  segment.value = "";
  update();
  search.focus();
});
let timer;
search.addEventListener("input", () => {
  clearTimeout(timer);
  timer = setTimeout(update, 120);
});
segment.addEventListener("change", update);
const segments = new Map();
for (const n of data.nodes) {
  if (n.type === "segment") segments.set(n.attrs.segment, n.label);
  for (const s of n.attrs.segments || []) if (!segments.has(s)) segments.set(s, s);
}
for (const [value, label] of [...segments].sort((a, b) => a[1].localeCompare(b[1]))) {
  const option = document.createElement("option");
  option.value = value;
  option.textContent = label;
  segment.append(option);
}
new ResizeObserver(size).observe(canvas);
update();
size();
"""


class RepositoryGraphRenderer:
    media_type = "text/html"

    def render(self, model: RepositoryGraph, report: Report) -> bytes:
        digest = base64.b64encode(hashlib.sha256(_SCRIPT.encode()).digest()).decode()
        csp = (
            "default-src 'none'; style-src 'unsafe-inline'; "
            f"script-src 'sha256-{digest}'; base-uri 'none'; form-action 'none'"
        )
        payload = (
            model.model_dump_json(by_alias=True)
            .replace("<", "\\u003c")
            .replace(">", "\\u003e")
            .replace("&", "\\u0026")
            .replace("\u2028", "\\u2028")
            .replace("\u2029", "\\u2029")
        )
        sections = []
        for section in report.sections:
            sections.append(f"<h2>{_text(section.heading)}</h2>")
            if section.body:
                sections.append(f"<p>{_text(section.body)}</p>")
            if section.table:
                sections.append(f'<div class="table-wrap">{_table(section.table)}</div>')
        sources = "".join(f"<li>{_text(source)}</li>" for source in report.sources)
        return (
            '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<meta http-equiv="Content-Security-Policy" content="{csp}">'
            f"<title>{_text(report.title)}</title><style>{_CSS}</style></head><body>"
            f'<header><h1>{_text(report.title)}</h1><p class="meta">'
            f"Snapshot {_text(model.as_of.isoformat())}</p>"
            "<p>Explore what ships each repository, its owners, and its assessment coverage. "
            "Version, category, ref and artifact details stay in node relationships "
            "and the full JSON export.</p></header>"
            '<div class="controls"><label>Find a repository or product'
            '<input id="search" type="search" placeholder="Repository, product or team" '
            'autocomplete="off"></label>'
            '<label>Focus segment<select id="segment">'
            '<option value="">All segments</option></select></label>'
            '<button id="zoom-in" type="button" aria-label="Zoom in">Zoom in</button>'
            '<button id="zoom-out" type="button" aria-label="Zoom out">Zoom out</button>'
            '<button id="fit" type="button">Fit graph</button>'
            '<button id="clear" type="button">Clear filters</button></div>'
            '<main><div class="workspace"><section class="map" aria-label="Relationship map">'
            '<canvas id="graph" tabindex="0" role="img" '
            'aria-label="Interactive repository relationships" '
            'aria-describedby="graph-help"></canvas><p id="status" role="status"></p>'
            '<p id="graph-help" class="sr-only">Drag to pan; scroll or use plus and minus to zoom. '
            "Arrow keys pan, Home fits the graph, Escape clears selection. "
            "The repository list provides keyboard access.</p>"
            '<div class="legend" aria-label="Repository severity">'
            '<span style="--swatch:#b02027">Critical</span>'
            '<span style="--swatch:#b24d07">High</span>'
            '<span style="--swatch:#8a6500">Medium</span><span style="--swatch:#287545">Low</span>'
            '<span style="--swatch:#707b85">Unrated / no assessment</span></div></section>'
            '<aside aria-label="Repository details"><h2>Selected relationship</h2>'
            '<div id="details"></div><h2>Repositories</h2>'
            '<p id="result-count" aria-live="polite"></p>'
            '<ul id="results"></ul></aside></div>'
            '<section class="statistics"><details>'
            "<summary>Graph statistics and provenance</summary>"
            f"{''.join(sections)}<h2>Sources</h2><ul>{sources}</ul></details></section></main>"
            "<noscript><p>This interactive map requires JavaScript. "
            "The paired JSON export and Markdown hub report "
            "contain the complete data and remain usable without it.</p></noscript>"
            f'<script id="graph-data" type="application/json">{payload}</script>'
            f"<script>{_SCRIPT}</script></body></html>\n"
        ).encode()

    def graphviz(self, model: RepositoryGraph) -> str:
        quoted = json.dumps
        nodes = (
            f"  {quoted(n.id)} [label={quoted(n.label)},group={quoted(n.type)}];"
            for n in model.nodes
        )
        edges = (
            f"  {quoted(e.source)} -> {quoted(e.target)} [label={quoted(e.rel)}];"
            for e in model.edges
        )
        return "\n".join(("digraph portfolio {", *nodes, *edges, "}", ""))

    def gexf(self, model: RepositoryGraph) -> str:
        root = ElementTree.Element("gexf", xmlns="http://gexf.net/1.3", version="1.3")
        graph = ElementTree.SubElement(root, "graph", defaultedgetype="directed", mode="static")
        definitions = ElementTree.SubElement(graph, "attributes", {"class": "node"})
        ElementTree.SubElement(definitions, "attribute", id="kind", title="type", type="string")
        nodes = ElementTree.SubElement(graph, "nodes")
        for item in model.nodes:
            node = ElementTree.SubElement(nodes, "node", id=item.id, label=item.label)
            values = ElementTree.SubElement(node, "attvalues")
            ElementTree.SubElement(values, "attvalue", {"for": "kind", "value": item.type})
        edges = ElementTree.SubElement(graph, "edges")
        for index, item in enumerate(model.edges):
            ElementTree.SubElement(
                edges, "edge", id=str(index), source=item.source, target=item.target, label=item.rel
            )
        return ElementTree.tostring(root, encoding="unicode", xml_declaration=True) + "\n"
