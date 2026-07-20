"use client";

/**
 * RiskGauge — the signature element.
 *
 * Most risk gauges are a single arc filled to N%. That's decoration: the arc
 * carries no information the number doesn't already give you.
 *
 * This one is SEGMENTED BY FINDING. Each arc segment's length is that
 * finding's actual weight contribution to the score, colored by its severity.
 * So the ring shows you not just "75/100" but *what the 75 is made of* — one
 * fat red segment means a single dominant problem; forty thin amber ones mean
 * diffuse debt. Those demand completely different responses.
 *
 * Structure encoding real information rather than decorating it — that's the
 * principle worth taking from this component.
 */

interface Finding {
  severity: string;
  title: string;
  weight: number;
}

const SEV: Record<string, string> = {
  critical: "var(--critical)",
  high: "var(--high)",
  medium: "var(--medium)",
  low: "var(--low)",
  informational: "var(--info)",
  unknown: "var(--info)",
};

export function RiskGauge({
  score,
  severity,
  findings,
  size = 190,
}: {
  score: number;
  severity: string;
  findings: Finding[];
  size?: number;
}) {
  const stroke = 12;
  const r = (size - stroke) / 2 - 8;
  const cx = size / 2;
  const cy = size / 2;
  const circumference = 2 * Math.PI * r;

  // The ring represents the full 0-100 scale. Segments occupy their share.
  const scored = findings.filter((f) => f.weight > 0);
  const totalWeight = scored.reduce((s, f) => s + f.weight, 0) || 1;
  // Scale so segments sum to the clamped score, not the raw weight total —
  // otherwise a capped score (e.g. CVE contribution caps at 45) would draw a
  // ring longer than the number it represents. The picture must not lie.
  const scale = score / totalWeight;

  let offset = 0;
  const segments = scored.map((f, i) => {
    const frac = (f.weight * scale) / 100;
    const len = frac * circumference;
    const seg = {
      key: i,
      color: SEV[f.severity] || SEV.unknown,
      dash: `${Math.max(len - 2, 0)} ${circumference}`,
      rotation: (offset / 100) * 360 - 90,
      title: `${f.title} (+${f.weight})`,
    };
    offset += frac * 100;
    return seg;
  });

  return (
    <div style={{ display: "flex", alignItems: "center", gap: 24, flexWrap: "wrap" }}>
      <svg width={size} height={size} role="img"
           aria-label={`Risk score ${score} of 100, severity ${severity}`}>
        {/* track */}
        <circle cx={cx} cy={cy} r={r} fill="none"
                stroke="var(--line)" strokeWidth={stroke} />

        {/* one arc per finding */}
        {segments.map((s) => (
          <circle
            key={s.key}
            cx={cx} cy={cy} r={r}
            fill="none"
            stroke={s.color}
            strokeWidth={stroke}
            strokeDasharray={s.dash}
            strokeLinecap="butt"
            transform={`rotate(${s.rotation} ${cx} ${cy})`}
          >
            <title>{s.title}</title>
          </circle>
        ))}

        {/* tick marks every 10 points — makes the ring readable as a scale */}
        {Array.from({ length: 10 }).map((_, i) => {
          const a = (i / 10) * 2 * Math.PI - Math.PI / 2;
          const r1 = r + stroke / 2 + 3;
          const r2 = r1 + 4;
          return (
            <line
              key={i}
              x1={cx + Math.cos(a) * r1} y1={cy + Math.sin(a) * r1}
              x2={cx + Math.cos(a) * r2} y2={cy + Math.sin(a) * r2}
              stroke="var(--line-hi)" strokeWidth={1}
            />
          );
        })}

        <text x={cx} y={cy - 2} textAnchor="middle"
              fontFamily="var(--mono)" fontSize={40} fontWeight={700}
              fill="var(--text-hi)">
          {score}
        </text>
        <text x={cx} y={cy + 18} textAnchor="middle"
              fontFamily="var(--mono)" fontSize={10}
              letterSpacing="0.16em"
              fill={SEV[severity] || SEV.unknown}>
          {severity.toUpperCase()}
        </text>
      </svg>

      {/* legend — severity counts, so the ring is decodable */}
      <div style={{ minWidth: 170 }}>
        {["critical", "high", "medium", "low", "informational"].map((sev) => {
          const items = scored.filter((f) => f.severity === sev);
          if (!items.length) return null;
          const pts = items.reduce((s, f) => s + f.weight, 0);
          return (
            <div key={sev} style={{
              display: "flex", alignItems: "center", gap: 8,
              padding: "5px 0", fontSize: 12, fontFamily: "var(--mono)",
            }}>
              <span style={{
                width: 8, height: 8, background: SEV[sev], borderRadius: 1,
                flexShrink: 0,
              }} />
              <span style={{ color: "var(--text)" }}>{items.length}</span>
              <span style={{ color: "var(--dim)" }}>{sev}</span>
              <span style={{ marginLeft: "auto", color: "var(--dim)" }}>
                +{pts}
              </span>
            </div>
          );
        })}
        {!scored.length && (
          <div style={{ color: "var(--dim)", fontSize: 12 }}>
            No scored findings.
          </div>
        )}
      </div>
    </div>
  );
}
