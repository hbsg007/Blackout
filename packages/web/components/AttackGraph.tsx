"use client";

import { useMemo, useState } from "react";

/**
 * AttackGraph — layered DAG rendering of attack paths.
 *
 * WHY LAYERED AND NOT FORCE-DIRECTED
 * Force-directed layouts (the classic bouncing-node graph) look impressive and
 * are usually the wrong choice here. Attack paths have inherent *direction*:
 * internet → domain → host → service → impact. That's a DAG with natural
 * layers, and a layered left-to-right layout makes the flow readable at a
 * glance — you can trace a route with your eye.
 *
 * A force simulation throws that ordering away, produces a different picture
 * on every render (so nobody can point at "the thing on the left"), and turns
 * into an unreadable hairball past ~50 nodes. Choosing the boring layout
 * because it communicates better is the correct engineering call.
 */

interface GNode { id: string; kind: string; label: string; severity: string; meta?: any; }
interface GEdge { source: string; target: string; technique: string; }
interface GPath { nodes: string[]; severity: string; score: number; narrative: string; }

const LAYER_ORDER = ["internet", "domain", "subdomain", "ip", "service", "vuln", "exposure", "impact"];

const SEV: Record<string, string> = {
  critical: "var(--critical)", high: "var(--high)", medium: "var(--medium)",
  low: "var(--low)", informational: "var(--info)", unknown: "var(--info)",
};

const KIND_LABEL: Record<string, string> = {
  internet: "ENTRY", domain: "DOMAIN", subdomain: "HOST", ip: "ADDRESS",
  service: "SERVICE", vuln: "VULN", exposure: "CREDENTIAL", impact: "IMPACT",
};

export function AttackGraph({
  nodes, edges, paths,
}: { nodes: GNode[]; edges: GEdge[]; paths: GPath[] }) {
  const [hover, setHover] = useState<string | null>(null);
  const [activePath, setActivePath] = useState<number | null>(null);

  const layout = useMemo(() => {
    // Bucket nodes into columns by kind, then stack within the column.
    const cols: Record<string, GNode[]> = {};
    for (const n of nodes) (cols[n.kind] ||= []).push(n);

    const present = LAYER_ORDER.filter((k) => cols[k]?.length);
    const colW = 168;
    const rowH = 46;
    const pad = 28;

    const pos: Record<string, { x: number; y: number }> = {};
    let maxRows = 1;

    present.forEach((kind, ci) => {
      const list = cols[kind].slice(0, 14); // cap per column for legibility
      maxRows = Math.max(maxRows, list.length);
      list.forEach((n, ri) => {
        pos[n.id] = { x: pad + ci * colW, y: pad + ri * rowH };
      });
    });

    return {
      pos,
      width: pad * 2 + Math.max(present.length - 1, 0) * colW + 140,
      height: pad * 2 + maxRows * rowH,
      columns: present,
      colW,
    };
  }, [nodes, edges]);

  const nodeById = useMemo(
    () => Object.fromEntries(nodes.map((n) => [n.id, n])), [nodes]);

  const highlighted = useMemo(() => {
    if (activePath === null || !paths[activePath]) return null;
    return new Set(paths[activePath].nodes);
  }, [activePath, paths]);

  if (!nodes.length) {
    return <div className="empty">No graph data for this scan.</div>;
  }

  return (
    <div>
      {/* path selector — clicking a path highlights it in the graph */}
      {paths.length > 0 && (
        <div style={{ marginBottom: 14 }}>
          <div style={{
            fontFamily: "var(--mono)", fontSize: 10, letterSpacing: "0.14em",
            color: "var(--dim)", marginBottom: 8,
          }}>
            {paths.length} PATH{paths.length === 1 ? "" : "S"} TO IMPACT
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
            {paths.map((p, i) => (
              <button
                key={i}
                onClick={() => setActivePath(activePath === i ? null : i)}
                style={{
                  textAlign: "left", background: activePath === i
                    ? "var(--panel-hi)" : "transparent",
                  border: "1px solid var(--line)",
                  borderLeft: `2px solid ${SEV[p.severity] || SEV.unknown}`,
                  borderRadius: "0 3px 3px 0", padding: "7px 11px",
                  cursor: "pointer", color: "var(--text)",
                  fontFamily: "var(--mono)", fontSize: 11,
                }}
              >
                <span style={{ color: SEV[p.severity] || SEV.unknown }}>
                  {p.severity.toUpperCase()}
                </span>
                <span style={{ color: "var(--dim)" }}> · </span>
                <span style={{ color: "var(--text)" }}>
                  {p.nodes.map((n) => nodeById[n]?.label || n).join("  →  ")}
                </span>
              </button>
            ))}
          </div>
        </div>
      )}

      <div style={{ overflowX: "auto", paddingBottom: 8 }}>
        <svg width={layout.width} height={layout.height + 26}
             style={{ display: "block", minWidth: "100%" }}>
          {/* column headers */}
          {layout.columns.map((kind, ci) => (
            <text key={kind} x={28 + ci * layout.colW} y={12}
                  fontFamily="var(--mono)" fontSize={9} letterSpacing="0.14em"
                  fill="var(--dimmer)">
              {KIND_LABEL[kind] || kind.toUpperCase()}
            </text>
          ))}

          <g transform="translate(0, 20)">
            {/* edges first so nodes draw on top */}
            {edges.map((e, i) => {
              const a = layout.pos[e.source];
              const b = layout.pos[e.target];
              if (!a || !b) return null;
              const on = highlighted
                ? highlighted.has(e.source) && highlighted.has(e.target)
                : hover
                  ? e.source === hover || e.target === hover
                  : false;
              const x1 = a.x + 126, y1 = a.y + 14;
              const x2 = b.x, y2 = b.y + 14;
              const mid = (x1 + x2) / 2;
              return (
                <path
                  key={i}
                  d={`M ${x1} ${y1} C ${mid} ${y1}, ${mid} ${y2}, ${x2} ${y2}`}
                  fill="none"
                  stroke={on ? "var(--accent)" : "var(--line-hi)"}
                  strokeWidth={on ? 1.6 : 1}
                  opacity={highlighted && !on ? 0.15 : 1}
                />
              );
            })}

            {/* nodes */}
            {nodes.map((n) => {
              const p = layout.pos[n.id];
              if (!p) return null;
              const dim = highlighted && !highlighted.has(n.id);
              const color = SEV[n.severity] || SEV.unknown;
              return (
                <g
                  key={n.id}
                  transform={`translate(${p.x}, ${p.y})`}
                  opacity={dim ? 0.22 : 1}
                  onMouseEnter={() => setHover(n.id)}
                  onMouseLeave={() => setHover(null)}
                  style={{ cursor: "default" }}
                >
                  <rect
                    width={126} height={28} rx={3}
                    fill="var(--panel-hi)"
                    stroke={n.severity === "informational" ? "var(--line-hi)" : color}
                    strokeWidth={1}
                  />
                  {/* severity spine */}
                  <rect width={2} height={28} rx={1} fill={color} />
                  <text x={9} y={18} fontFamily="var(--mono)" fontSize={10.5}
                        fill="var(--text)">
                    {n.label.length > 17 ? n.label.slice(0, 16) + "…" : n.label}
                  </text>
                  <title>{`${n.kind}: ${n.label}`}</title>
                </g>
              );
            })}
          </g>
        </svg>
      </div>

      <p style={{ fontSize: 11, color: "var(--dimmer)", marginTop: 10, maxWidth: 620 }}>
        Hypothesized routes based on external observation only. This model has no
        visibility into internal segmentation, WAFs, or other controls, so paths
        indicate possible reachability — not proven exploitability.
      </p>
    </div>
  );
}
