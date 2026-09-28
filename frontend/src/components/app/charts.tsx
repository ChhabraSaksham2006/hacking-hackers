import { useMemo } from "react";
import {
  attackStages,
  riskFromProbability,
  stateColorVar,
  threshold,
  windowLabel,
  type RiskState,
} from "@/lib/telemetry";
import { cn } from "@/lib/utils";

function path(series: number[], w: number, h: number, pad = 0) {
  if (!series || series.length === 0) return `M${pad},${h - pad}`;
  const stepX = (w - pad * 2) / Math.max(1, series.length - 1);
  return series
    .map((v, i) => {
      const x = pad + i * stepX;
      const y = h - pad - v * (h - pad * 2);
      return `${i === 0 ? "M" : "L"}${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(" ");
}

/** Signature moment: the probability trajectory traces itself in once on load. */
export function ProbabilityTimeline({
  series,
  height = 260,
  animate = true,
}: {
  series: number[];
  height?: number;
  animate?: boolean;
}) {
  const w = 900;
  const h = height;
  const pad = 18;
  const d = useMemo(() => path(series, w, h, pad), [series, h]);
  const stepX = (w - pad * 2) / (series.length - 1);
  const y = (v: number) => h - pad - v * (h - pad * 2);

  return (
    <div className="w-full">
      <svg
        viewBox={`0 0 ${w} ${h}`}
        className="h-auto w-full"
        role="img"
        aria-label="Infiltration probability over time"
      >
        {[0.25, 0.5, 0.75, 1].map((g) => (
          <line
            key={g}
            x1={pad}
            x2={w - pad}
            y1={y(g)}
            y2={y(g)}
            stroke="var(--glass-border)"
            strokeWidth="1"
          />
        ))}
        <line
          x1={pad}
          x2={w - pad}
          y1={y(threshold)}
          y2={y(threshold)}
          stroke="var(--watch-amber)"
          strokeWidth="1"
          strokeDasharray="6 6"
          opacity="0.8"
        />
        <text
          x={w - pad}
          y={y(threshold) - 6}
          textAnchor="end"
          className="font-mono"
          fontSize="11"
          fill="var(--watch-amber)"
        >
          threshold 0.65
        </text>
        <path
          d={`${d} L${w - pad},${h - pad} L${pad},${h - pad} Z`}
          fill="color-mix(in oklab, var(--signal-teal) 12%, transparent)"
        />
        <path
          d={d}
          fill="none"
          stroke="var(--signal-teal)"
          strokeWidth="2"
          strokeLinejoin="round"
          className={animate ? "trace-line" : undefined}
          style={{ ["--trace-len" as string]: "2400" }}
        />
        {series.map((v, i) =>
          v > threshold ? (
            <circle
              key={i}
              cx={pad + i * stepX}
              cy={y(v)}
              r="3.5"
              fill={stateColorVar[riskFromProbability(v)]}
            />
          ) : null,
        )}
        {[0, Math.floor(series.length / 2), series.length - 1].map((i) => (
          <text
            key={i}
            x={pad + i * stepX}
            y={h - 4}
            textAnchor={i === 0 ? "start" : i === series.length - 1 ? "end" : "middle"}
            className="font-mono"
            fontSize="11"
            fill="var(--fog-400)"
          >
            {windowLabel(i, series.length)}
          </text>
        ))}
      </svg>
    </div>
  );
}

export function DualTrajectory({
  predicted,
  actual,
}: {
  predicted: number[];
  actual: number[];
}) {
  const w = 720;
  const h = 240;
  return (
    <svg viewBox={`0 0 ${w} ${h}`} className="h-auto w-full" role="img" aria-label="Forecast versus observed trajectory">
      {[0.25, 0.5, 0.75, 1].map((g) => (
        <line
          key={g}
          x1={16}
          x2={w - 16}
          y1={h - 16 - g * (h - 32)}
          y2={h - 16 - g * (h - 32)}
          stroke="var(--glass-border)"
        />
      ))}
      <path d={path(predicted, w, h, 16)} fill="none" stroke="var(--signal-teal)" strokeWidth="2" strokeDasharray="7 5" />
      <path d={path(actual, w, h, 16)} fill="none" stroke="var(--paper-100)" strokeWidth="2" opacity="0.85" />
    </svg>
  );
}

export function Sparkline({
  series,
  className,
  color = "var(--signal-teal)",
}: {
  series: number[];
  className?: string;
  color?: string;
}) {
  return (
    <svg viewBox="0 0 120 32" className={cn("h-8 w-[120px]", className)} aria-hidden="true">
      <path d={path(series, 120, 32, 2)} fill="none" stroke={color} strokeWidth="1.5" />
    </svg>
  );
}

export function StageStrip({ current }: { current: number }) {
  return (
    <div className="relative pt-2">
      <div className="absolute top-[18px] right-3 left-3 h-px bg-[var(--glass-border)]" />
      <ol className="relative flex justify-between">
        {attackStages.map((stage, i) => {
          const active = i === current;
          const passed = i < current;
          return (
            <li key={stage} className="flex w-[19%] flex-col items-start gap-2 sm:gap-3">
              <span
                className={cn(
                  "size-[12px] sm:size-[13px] rounded-full border shrink-0",
                  active && "border-transparent",
                )}
                style={{
                  background: active
                    ? "var(--watch-amber)"
                    : passed
                      ? "color-mix(in oklab, var(--signal-teal) 60%, transparent)"
                      : "transparent",
                  borderColor: passed ? "var(--signal-teal)" : "var(--fog-600)",
                  boxShadow: active
                    ? "0 0 14px 2px color-mix(in oklab, var(--watch-amber) 55%, transparent)"
                    : undefined,
                }}
              />
              <span
                className={cn(
                  "text-[10px] sm:text-[12px] leading-tight break-words hyphens-auto",
                  active ? "text-paper font-medium" : "text-fog",
                )}
              >
                {stage}
              </span>
            </li>
          );
        })}
      </ol>
    </div>
  );
}

type Node = { id: string; x: number; y: number; size: number; state: RiskState };

export const graphNodes: Node[] = [
  { id: "edge-gw-01", x: 120, y: 90, size: 13, state: "critical" },
  { id: "corp-sw-01", x: 300, y: 70, size: 10, state: "watch" },
  { id: "fin-db-02", x: 470, y: 130, size: 15, state: "critical" },
  { id: "ops-jump-05", x: 300, y: 210, size: 9, state: "watch" },
  { id: "hr-file-11", x: 520, y: 260, size: 8, state: "watch" },
  { id: "dev-ci-03", x: 660, y: 90, size: 11, state: "watch" },
  { id: "print-svc-02", x: 180, y: 280, size: 6, state: "normal" },
  { id: "ot-plc-04", x: 700, y: 250, size: 7, state: "normal" },
  { id: "guest-ap-02", x: 60, y: 200, size: 5, state: "normal" },
];

const graphEdges: [number, number, number][] = [
  [0, 1, 3], [1, 2, 4], [1, 3, 2], [3, 2, 3], [2, 4, 2],
  [1, 5, 2], [5, 7, 1], [6, 3, 1], [8, 0, 1], [4, 2, 1],
];

export type GraphNode = {
  id: string;
  x: number;
  y: number;
  size: number;
  state: RiskState;
  hostname?: string;
  role?: string;
  segment?: string;
  flows?: number;
  bytes?: number;
};

export type GraphEdge = {
  source: string;
  target: string;
  bytes?: number;
  score?: number;
  weight?: number;
};

export function NetworkGraph({
  nodes = graphNodes,
  edges,
  onSelect,
  selected,
  scrub = 100,
}: {
  nodes?: GraphNode[];
  edges?: GraphEdge[];
  onSelect?: ((id: string) => void) | undefined;
  selected?: string | undefined;
  scrub?: number;
}) {
  const intensity = 0.4 + (scrub / 100) * 0.6;
  const nodeMap = new Map<string, GraphNode>();
  nodes.forEach((n) => nodeMap.set(n.id, n));

  return (
    <svg viewBox="0 0 780 340" className="h-auto w-full" role="img" aria-label="Network state graph">
      {edges && edges.length > 0
        ? edges.map((e, i) => {
            const n1 = nodeMap.get(e.source);
            const n2 = nodeMap.get(e.target);
            if (!n1 || !n2) return null;
            const wgt = e.weight ?? (e.score && e.score > 0.6 ? 3 : 1.5);
            return (
              <g key={`edge-${i}`}>
                <line
                  x1={n1.x}
                  y1={n1.y}
                  x2={n2.x}
                  y2={n2.y}
                  stroke="var(--glass-border)"
                  strokeWidth={wgt}
                />
                <line
                  x1={n1.x}
                  y1={n1.y}
                  x2={n2.x}
                  y2={n2.y}
                  stroke={e.score && e.score > 0.7 ? "var(--critical-crimson)" : "var(--signal-teal)"}
                  strokeWidth={Math.max(1, wgt - 0.5)}
                  opacity={0.45 * intensity}
                  className="particle-flow"
                />
              </g>
            );
          })
        : graphEdges.map(([a, b, wgt], i) => {
            const n1 = nodes[a];
            const n2 = nodes[b];
            if (!n1 || !n2) return null;
            return (
              <g key={i}>
                <line
                  x1={n1.x}
                  y1={n1.y}
                  x2={n2.x}
                  y2={n2.y}
                  stroke="var(--glass-border)"
                  strokeWidth={wgt}
                />
                <line
                  x1={n1.x}
                  y1={n1.y}
                  x2={n2.x}
                  y2={n2.y}
                  stroke="var(--signal-teal)"
                  strokeWidth={Math.max(1, wgt - 1)}
                  opacity={0.35 * intensity}
                  className="particle-flow"
                />
              </g>
            );
          })}
      {nodes.map((n) => (
        <g
          key={n.id}
          onClick={() => onSelect?.(n.id)}
          className={onSelect ? "cursor-pointer" : undefined}
        >
          <circle
            cx={n.x}
            cy={n.y}
            r={n.size + 8}
            fill={`color-mix(in oklab, ${stateColorVar[n.state]} ${n.state === "normal" ? 8 : 18}%, transparent)`}
          />
          <circle
            cx={n.x}
            cy={n.y}
            r={n.size}
            fill={stateColorVar[n.state]}
            opacity={n.state === "normal" ? 0.65 : 0.95}
            stroke={selected === n.id ? "var(--paper-100)" : "transparent"}
            strokeWidth="2.5"
          />
          <text
            x={n.x}
            y={n.y + n.size + 15}
            textAnchor="middle"
            className="font-mono"
            fontSize="10"
            fill="var(--fog-400)"
          >
            {n.id}
          </text>
        </g>
      ))}
    </svg>
  );
}

export function LossCurve({ train, val }: { train: number[]; val: number[] }) {
  const w = 720;
  const h = 220;
  const scale = (s: number[]) => s.map((v) => 1 - v);
  return (
    <svg viewBox={`0 0 ${w} ${h}`} className="h-auto w-full" role="img" aria-label="Training and validation loss">
      {[0.25, 0.5, 0.75, 1].map((g) => (
        <line key={g} x1={16} x2={w - 16} y1={h - 16 - g * (h - 32)} y2={h - 16 - g * (h - 32)} stroke="var(--glass-border)" />
      ))}
      <path d={path(scale(train), w, h, 16)} fill="none" stroke="var(--signal-teal)" strokeWidth="2" />
      <path d={path(scale(val), w, h, 16)} fill="none" stroke="var(--watch-amber)" strokeWidth="2" strokeDasharray="6 5" />
    </svg>
  );
}
