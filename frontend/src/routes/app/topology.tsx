import { useState, useMemo } from "react";
import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import {
  Activity,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Network,
  LayoutGrid,
  RefreshCw,
  X,
  ArrowRight,
  Zap,
  Radio,
  Lock,
  Unlock,
  AlertTriangle,
  ChevronRight,
  Server,
  ExternalLink,
  Layers,
  Search,
  Cpu,
  Clock,
  CheckCircle2,
  TrendingUp,
} from "lucide-react";
import { FlatPanel, HeroPanel, PageTitle, RiskBadge } from "@/components/app/panels";
import { pageHead } from "@/lib/head";
import { stateColorVar } from "@/lib/telemetry";
import {
  useTopology,
  useSegmentDeepDive,
  useIsolateSegment,
  type TopologySegment,
  type InterSegmentLink,
} from "@/hooks/useApi";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/app/topology")({
  head: pageHead(
    "Topology overview — Flow दृष्टि",
    "Organisation-wide segment map sized by traffic volume, telemetry throughput, and live threat progression.",
  ),
  component: Topology,
});

// Coordinates for layout in the SVG Flow Nexus canvas (920 x 540)
const SEGMENT_COORDINATES: Record<string, { x: number; y: number; r: number }> = {
  "corp-core": { x: 310, y: 260, r: 52 },
  "finance": { x: 650, y: 230, r: 48 },
  "dmz-edge": { x: 470, y: 90, r: 42 },
  "dev-build": { x: 180, y: 420, r: 38 },
  "ot-plant-a": { x: 430, y: 440, r: 36 },
  "ot-plant-b": { x: 720, y: 430, r: 32 },
  "guest-wifi": { x: 140, y: 110, r: 36 },
};

function Topology() {
  const navigate = useNavigate();
  const [viewMode, setViewMode] = useState<"nexus" | "treemap">("nexus");
  const [selectedSegment, setSelectedSegment] = useState<string | null>("finance");
  const [searchQuery, setSearchQuery] = useState("");
  const [hoveredLink, setHoveredLink] = useState<string | null>(null);

  const { data: topology, isLoading, refetch, isFetching } = useTopology();
  const { data: deepDive, isLoading: isDeepDiveLoading } = useSegmentDeepDive(selectedSegment);
  const isolateMutation = useIsolateSegment();

  const segments = topology?.segments || [];
  const links = topology?.interSegmentLinks || [];
  const summary = topology?.summary;
  const modelIntel = topology?.modelIntelligence;

  const totalTrafficVolume = useMemo(
    () => segments.reduce((sum, s) => sum + s.trafficVolume, 0) || 100,
    [segments]
  );

  const filteredSegments = useMemo(() => {
    if (!searchQuery.trim()) return segments;
    const q = searchQuery.toLowerCase();
    return segments.filter(
      (s) =>
        s.name.toLowerCase().includes(q) ||
        s.state.toLowerCase().includes(q) ||
        s.topTalkers?.some((t) => t.ip.includes(q) || t.hostname.toLowerCase().includes(q))
    );
  }, [segments, searchQuery]);

  const handleToggleIsolation = (segName: string, currentIsolated: boolean) => {
    isolateMutation.mutate({
      name: segName,
      isolate: !currentIsolated,
    });
  };

  // 48-window model timeline SVG path
  const timelinePoints = useMemo(() => {
    const series = modelIntel?.probabilityTimeline || [];
    if (series.length < 2) return "";
    const w = 420;
    const h = 48;
    return series
      .map((val, idx) => {
        const x = (idx / (series.length - 1)) * w;
        const y = h - Math.max(0, Math.min(1, val)) * (h - 6) - 3;
        return `${x.toFixed(1)},${y.toFixed(1)}`;
      })
      .join(" ");
  }, [modelIntel?.probabilityTimeline]);

  return (
    <>
      <PageTitle
        title="Topology overview"
        note="Organisation-wide segment architecture grounded in physical flow telemetry and evaluated by SparseRSSM + TFCNet deep hybrid ensemble."
        actions={
          <div className="flex flex-wrap items-center gap-2">
            {/* View Mode Toggle Switch */}
            <div className="inline-flex rounded-lg border border-fog-deep/40 bg-void-800 p-0.5">
              <button
                type="button"
                onClick={() => setViewMode("nexus")}
                className={cn(
                  "flex items-center gap-1.5 rounded-md px-3 py-1.5 text-[12px] font-mono transition-all",
                  viewMode === "nexus"
                    ? "bg-teal/15 text-teal shadow-xs font-semibold"
                    : "text-fog hover:text-paper"
                )}
              >
                <Network className="size-3.5" />
                Flow Nexus Map
              </button>
              <button
                type="button"
                onClick={() => setViewMode("treemap")}
                className={cn(
                  "flex items-center gap-1.5 rounded-md px-3 py-1.5 text-[12px] font-mono transition-all",
                  viewMode === "treemap"
                    ? "bg-teal/15 text-teal shadow-xs font-semibold"
                    : "text-fog hover:text-paper"
                )}
              >
                <LayoutGrid className="size-3.5" />
                Adaptive Treemap
              </button>
            </div>

            {/* Refresh / Telemetry Stream Status */}
            <button
              type="button"
              onClick={() => refetch()}
              disabled={isFetching}
              className="flex items-center gap-1.5 rounded-lg border border-fog-deep/40 bg-void-800 px-3 py-1.5 text-[12px] font-mono text-fog transition-colors hover:border-teal/50 hover:text-teal"
              title="Refresh topology telemetry"
            >
              <RefreshCw className={cn("size-3.5", isFetching && "animate-spin text-teal")} />
              <span>{isFetching ? "Syncing..." : "Live Telemetry"}</span>
            </button>
          </div>
        }
      />

      {/* Cyber World Model Neural Intelligence Command HUD */}
      {modelIntel && (
        <div className="mb-6 overflow-hidden rounded-2xl border border-teal/40 bg-void-900/90 p-4 shadow-xl backdrop-blur-md">
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-fog-deep/30 pb-3.5">
            <div className="flex items-center gap-2.5">
              <span className="relative flex size-3">
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-teal opacity-75" />
                <span className="relative inline-flex size-3 rounded-full bg-teal" />
              </span>
              <div>
                <div className="flex items-center gap-2">
                  <span className="font-mono text-[13px] font-bold text-paper">
                    Cyber World Model Neural Engine
                  </span>
                  <span className="rounded bg-teal/15 px-2 py-0.5 font-mono text-[10px] font-semibold text-teal border border-teal/30">
                    {modelIntel.engine.includes("SparseRSSM") ? "SparseRSSM + TFCNet Ensemble" : modelIntel.engine}
                  </span>
                  <span className="rounded bg-void-700 px-1.5 py-0.5 font-mono text-[10px] text-fog">
                    {modelIntel.modelVersion}
                  </span>
                </div>
                <p className="text-[11px] text-fog">
                  Active window index: <strong className="text-paper font-mono">W#{modelIntel.windowIndex}</strong> · Inference Source: <strong className="text-teal font-mono">{modelIntel.inferenceSource}</strong>
                </p>
              </div>
            </div>

            <div className="flex items-center gap-2 font-mono text-[11px]">
              <span className="rounded border border-fog-deep/40 bg-void-800 px-2.5 py-1 text-fog">
                Confidence: <strong className="text-paper">{modelIntel.confidence}</strong>
              </span>
              <span className="rounded border border-fog-deep/40 bg-void-800 px-2.5 py-1 text-fog">
                Stage: <strong className={cn(modelIntel.currentStage === "Lateral Movement" ? "text-crimson" : "text-amber")}>{modelIntel.currentStage}</strong>
              </span>
            </div>
          </div>

          {/* Model Dual-Branch Probability Grid & 48-Window Timeline */}
          <div className="mt-3.5 grid grid-cols-1 gap-4 lg:grid-cols-[minmax(0,1.4fr)_minmax(0,1fr)]">
            {/* 4 Real-time PyTorch Ensemble Gauges */}
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
              {/* Ensemble Infiltration Prob */}
              <div className="rounded-xl border border-fog-deep/30 bg-void-800/80 p-3">
                <span className="text-[10px] font-mono uppercase tracking-wider text-fog">
                  Ensemble Infiltration
                </span>
                <div className="mt-1 flex items-baseline gap-1">
                  <span
                    className={cn(
                      "font-mono text-2xl font-bold",
                      modelIntel.ensembleProbability >= 0.7
                        ? "text-crimson"
                        : modelIntel.ensembleProbability >= 0.4
                        ? "text-amber"
                        : "text-teal"
                    )}
                  >
                    {Math.round(modelIntel.ensembleProbability * 100)}%
                  </span>
                  <span className="text-[11px] text-fog">P(atk)</span>
                </div>
                <div className="mt-2 h-1.5 w-full overflow-hidden rounded-full bg-void-700">
                  <div
                    className={cn(
                      "h-full rounded-full transition-all duration-500",
                      modelIntel.ensembleProbability >= 0.7
                        ? "bg-crimson"
                        : modelIntel.ensembleProbability >= 0.4
                        ? "bg-amber"
                        : "bg-teal"
                    )}
                    style={{ width: `${modelIntel.ensembleProbability * 100}%` }}
                  />
                </div>
              </div>

              {/* SparseRSSM Latent State Branch */}
              <div className="rounded-xl border border-fog-deep/30 bg-void-800/80 p-3">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-mono uppercase tracking-wider text-fog">
                    SparseRSSM (State)
                  </span>
                  <Cpu className="size-3 text-fog" />
                </div>
                <div className="mt-1 flex items-baseline gap-1">
                  <span className="font-mono text-2xl font-bold text-paper">
                    {(modelIntel.rssmProbability * 100).toFixed(1)}%
                  </span>
                  <span className="text-[10px] text-fog">256-D</span>
                </div>
                <div className="mt-2 h-1.5 w-full overflow-hidden rounded-full bg-void-700">
                  <div
                    className="h-full rounded-full bg-teal transition-all duration-500"
                    style={{ width: `${Math.min(100, modelIntel.rssmProbability * 200)}%` }}
                  />
                </div>
              </div>

              {/* TFCNet Spectral Attention Branch */}
              <div className="rounded-xl border border-fog-deep/30 bg-void-800/80 p-3">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-mono uppercase tracking-wider text-fog">
                    TFCNet (Spectral)
                  </span>
                  <Activity className="size-3 text-fog" />
                </div>
                <div className="mt-1 flex items-baseline gap-1">
                  <span className="font-mono text-2xl font-bold text-paper">
                    {(modelIntel.tfcProbability * 100).toFixed(1)}%
                  </span>
                  <span className="text-[10px] text-fog">iTrans</span>
                </div>
                <div className="mt-2 h-1.5 w-full overflow-hidden rounded-full bg-void-700">
                  <div
                    className="h-full rounded-full bg-amber transition-all duration-500"
                    style={{ width: `${Math.min(100, modelIntel.tfcProbability * 100)}%` }}
                  />
                </div>
              </div>

              {/* Early Warning Lead Time */}
              <div className="rounded-xl border border-fog-deep/30 bg-void-800/80 p-3">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-mono uppercase tracking-wider text-fog">
                    Warning Horizon
                  </span>
                  <Clock className="size-3 text-teal" />
                </div>
                <div className="mt-1 flex items-baseline gap-1">
                  <span className="font-mono text-2xl font-bold text-teal">
                    {modelIntel.leadTimeSeconds}s
                  </span>
                  <span className="text-[10px] text-fog">Lead</span>
                </div>
                <p className="mt-1.5 font-mono text-[10px] text-fog">
                  Pre-propagation margin
                </p>
              </div>
            </div>

            {/* 48-Window PyTorch Probability Waveform */}
            <div className="rounded-xl border border-fog-deep/30 bg-void-800/80 p-3">
              <div className="flex items-center justify-between text-[11px] font-mono">
                <span className="text-fog">48-Window Infiltration Trajectory</span>
                <span className="text-teal font-semibold">Active: W#{modelIntel.windowIndex}</span>
              </div>
              <div className="mt-2 h-12 w-full">
                <svg viewBox="0 0 420 48" className="h-full w-full overflow-visible">
                  <defs>
                    <linearGradient id="prob-grad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#2dd4bf" stopOpacity="0.4" />
                      <stop offset="100%" stopColor="#2dd4bf" stopOpacity="0.0" />
                    </linearGradient>
                  </defs>
                  {/* Threshold dashed line */}
                  <line
                    x1="0"
                    y1={48 - 0.65 * 42}
                    x2="420"
                    y2={48 - 0.65 * 42}
                    stroke="rgba(244, 63, 94, 0.4)"
                    strokeDasharray="4 4"
                    strokeWidth="1"
                  />
                  {/* Timeline curve */}
                  {timelinePoints && (
                    <>
                      <polygon
                        fill="url(#prob-grad)"
                        points={`0,48 ${timelinePoints} 420,48`}
                      />
                      <polyline
                        fill="none"
                        stroke="#2dd4bf"
                        strokeWidth="2"
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        points={timelinePoints}
                      />
                      {/* Active end marker */}
                      <circle
                        cx="420"
                        cy={48 - Math.max(0, Math.min(1, modelIntel.ensembleProbability)) * 42 - 3}
                        r="4"
                        fill="#f43f5e"
                        stroke="#ffffff"
                        strokeWidth="1.5"
                        className="animate-pulse"
                      />
                    </>
                  )}
                </svg>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Global Executive NOC/SOC HUD Ribbon */}
      <div className="mb-6 grid grid-cols-2 gap-3 sm:grid-cols-4 lg:grid-cols-5">
        {/* Estate Health Index */}
        <div className="rounded-xl border border-fog-deep/40 bg-void-800/80 p-3.5 backdrop-blur-sm">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-mono uppercase tracking-wider text-fog">
              Estate Health
            </span>
            <ShieldCheck
              className={cn(
                "size-4",
                (summary?.healthScore ?? 100) < 60
                  ? "text-crimson"
                  : (summary?.healthScore ?? 100) < 80
                  ? "text-amber"
                  : "text-teal"
              )}
            />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span
              className={cn(
                "font-mono text-2xl font-bold",
                (summary?.healthScore ?? 100) < 60
                  ? "text-crimson"
                  : (summary?.healthScore ?? 100) < 80
                  ? "text-amber"
                  : "text-teal"
              )}
            >
              {summary?.healthScore ?? 84}%
            </span>
            <span className="text-[11px] text-fog">
              {(summary?.healthScore ?? 100) < 60 ? "Degraded" : "Secured"}
            </span>
          </div>
          {/* Mini health bar */}
          <div className="mt-2.5 h-1.5 w-full overflow-hidden rounded-full bg-void-700">
            <div
              className={cn(
                "h-full rounded-full transition-all duration-500",
                (summary?.healthScore ?? 100) < 60
                  ? "bg-crimson"
                  : (summary?.healthScore ?? 100) < 80
                  ? "bg-amber"
                  : "bg-teal"
              )}
              style={{ width: `${summary?.healthScore ?? 84}%` }}
            />
          </div>
        </div>

        {/* Monitored Subnets & Hosts */}
        <div className="rounded-xl border border-fog-deep/40 bg-void-800/80 p-3.5 backdrop-blur-sm">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-mono uppercase tracking-wider text-fog">
              Monitored Scope
            </span>
            <Server className="size-4 text-fog" />
          </div>
          <div className="mt-2">
            <span className="font-mono text-2xl font-bold text-paper">
              {summary?.totalSegments ?? segments.length}
            </span>
            <span className="ml-1 text-[12px] text-fog">subnets</span>
          </div>
          <p className="mt-1 font-mono text-[11px] text-fog">
            {summary?.totalHosts ?? 1462} physical endpoints
          </p>
        </div>

        {/* Aggregate Network Throughput */}
        <div className="rounded-xl border border-fog-deep/40 bg-void-800/80 p-3.5 backdrop-blur-sm">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-mono uppercase tracking-wider text-fog">
              Aggregate Bandwidth
            </span>
            <Zap className="size-4 text-teal" />
          </div>
          <div className="mt-2">
            <span className="font-mono text-2xl font-bold text-paper">
              {summary?.totalThroughputMbps ?? 184.2}
            </span>
            <span className="ml-1 text-[12px] text-teal">Mbps</span>
          </div>
          <p className="mt-1 font-mono text-[11px] text-fog">
            active cross-segment transit
          </p>
        </div>

        {/* Active Threats / High Risk Segments */}
        <div className="rounded-xl border border-fog-deep/40 bg-void-800/80 p-3.5 backdrop-blur-sm">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-mono uppercase tracking-wider text-fog">
              Threat Escalation
            </span>
            <ShieldAlert
              className={cn(
                "size-4",
                (summary?.criticalSegments ?? 0) > 0 ? "text-crimson animate-pulse" : "text-teal"
              )}
            />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span
              className={cn(
                "font-mono text-2xl font-bold",
                (summary?.criticalSegments ?? 0) > 0 ? "text-crimson" : "text-paper"
              )}
            >
              {summary?.criticalSegments ?? 0}
            </span>
            <span className="text-[11px] text-fog">critical</span>
            <span className="ml-auto font-mono text-[12px] text-amber">
              {summary?.watchSegments ?? 0} watch
            </span>
          </div>
          <p className="mt-1 font-mono text-[11px] text-fog">
            {summary?.isolatedSegments ?? 0} isolated / quarantined
          </p>
        </div>

        {/* Active Threat Vector Banner */}
        <div className="col-span-2 rounded-xl border border-crimson/30 bg-crimson/10 p-3.5 sm:col-span-4 lg:col-span-1">
          <div className="flex items-center gap-1.5 text-crimson">
            <Radio className="size-3.5 animate-pulse" />
            <span className="font-mono text-[11px] font-semibold uppercase tracking-wider">
              Primary Threat Vector
            </span>
          </div>
          <p className="mt-1.5 text-[12px] leading-tight text-paper/90 line-clamp-2">
            {summary?.activeThreatVector || "No critical lateral movement detected."}
          </p>
        </div>
      </div>

      {/* Main Content Layout: Graph or Treemap + Slide-out / Side Details */}
      <div className="grid gap-6 lg:grid-cols-[minmax(0,1.8fr)_minmax(0,1.2fr)]">
        {/* Left Column: Visual Map (Nexus or Treemap) */}
        <div className="flex flex-col gap-4">
          {viewMode === "nexus" ? (
            <div className="relative overflow-hidden rounded-2xl border border-fog-deep/40 bg-void-900/90 shadow-2xl backdrop-blur-md">
              {/* Header inside canvas */}
              <div className="flex flex-wrap items-center justify-between gap-2 border-b border-fog-deep/30 px-3 sm:px-5 py-3">
                <div className="flex items-center gap-2">
                  <Network className="size-4 text-teal" />
                  <span className="font-mono text-[12px] sm:text-[13px] font-semibold text-paper">
                    Live Inter-Segment Flow Nexus
                  </span>
                </div>
                <div className="flex flex-wrap items-center gap-2 sm:gap-3 text-[10px] sm:text-[11px] font-mono text-fog">
                  <span className="flex items-center gap-1">
                    <span className="size-2 rounded-full bg-teal" /> Normal
                  </span>
                  <span className="flex items-center gap-1">
                    <span className="size-2 rounded-full bg-amber" /> Watch
                  </span>
                  <span className="flex items-center gap-1">
                    <span className="size-2 rounded-full bg-crimson animate-pulse" /> Threat
                  </span>
                </div>
              </div>

              {/* Interactive SVG Topology Map */}
              <div className="relative aspect-[880/500] min-h-[260px] sm:min-h-[460px] w-full overflow-hidden p-1 sm:p-2">
                <svg
                  viewBox="0 0 880 500"
                  className="h-full w-full select-none"
                  preserveAspectRatio="xMidYMid meet"
                >
                  <defs>
                    {/* Subtle grid pattern */}
                    <pattern id="nexus-grid" width="40" height="40" patternUnits="userSpaceOnUse">
                      <circle cx="2" cy="2" r="1" fill="rgba(255,255,255,0.06)" />
                    </pattern>

                    {/* Radial Glows for Nodes */}
                    <radialGradient id="glow-critical" cx="50%" cy="50%" r="50%">
                      <stop offset="0%" stopColor="oklch(0.6483 0.1819 13.23)" stopOpacity="0.7" />
                      <stop offset="60%" stopColor="oklch(0.6483 0.1819 13.23)" stopOpacity="0.2" />
                      <stop offset="100%" stopColor="transparent" stopOpacity="0" />
                    </radialGradient>
                    <radialGradient id="glow-watch" cx="50%" cy="50%" r="50%">
                      <stop offset="0%" stopColor="oklch(0.7846 0.1287 63.94)" stopOpacity="0.6" />
                      <stop offset="70%" stopColor="oklch(0.7846 0.1287 63.94)" stopOpacity="0.15" />
                      <stop offset="100%" stopColor="transparent" stopOpacity="0" />
                    </radialGradient>
                    <radialGradient id="glow-normal" cx="50%" cy="50%" r="50%">
                      <stop offset="0%" stopColor="oklch(0.803 0.1212 181.68)" stopOpacity="0.4" />
                      <stop offset="75%" stopColor="oklch(0.803 0.1212 181.68)" stopOpacity="0.1" />
                      <stop offset="100%" stopColor="transparent" stopOpacity="0" />
                    </radialGradient>

                    {/* Hazard pattern for isolated segments */}
                    <pattern id="hazard-quarantine" width="12" height="12" patternTransform="rotate(45 0 0)" patternUnits="userSpaceOnUse">
                      <line x1="0" y1="0" x2="0" y2="12" stroke="rgba(244, 63, 94, 0.4)" strokeWidth="4" />
                    </pattern>
                  </defs>

                  {/* Canvas Grid Background */}
                  <rect width="100%" height="100%" fill="url(#nexus-grid)" />

                  {/* Inter-Segment Link Paths */}
                  {links.map((link) => {
                    const srcCoord = SEGMENT_COORDINATES[link.source];
                    const dstCoord = SEGMENT_COORDINATES[link.target];
                    if (!srcCoord || !dstCoord) return null;

                    // Calculate curved path midpoint
                    const dx = dstCoord.x - srcCoord.x;
                    const dy = dstCoord.y - srcCoord.y;
                    const mx = (srcCoord.x + dstCoord.x) / 2 - dy * 0.18;
                    const my = (srcCoord.y + dstCoord.y) / 2 + dx * 0.18;
                    const pathD = `M ${srcCoord.x} ${srcCoord.y} Q ${mx} ${my} ${dstCoord.x} ${dstCoord.y}`;

                    const isThreat = link.status === "critical";
                    const isWatch = link.status === "watch";
                    const isHovered = hoveredLink === link.id;

                    const lineColor = isThreat
                      ? "oklch(0.6483 0.1819 13.23)" // Crimson
                      : isWatch
                      ? "oklch(0.7846 0.1287 63.94)" // Amber
                      : "oklch(0.803 0.1212 181.68 / 65%)"; // Teal

                    const particleColor = isThreat
                      ? "#f43f5e"
                      : isWatch
                      ? "#fbbf24"
                      : "#2dd4bf";

                    return (
                      <g
                        key={link.id}
                        onMouseEnter={() => setHoveredLink(link.id)}
                        onMouseLeave={() => setHoveredLink(null)}
                        className="cursor-pointer transition-opacity"
                        style={{ opacity: hoveredLink && !isHovered ? 0.35 : 1 }}
                      >
                        {/* Wide invisible path for easy hover */}
                        <path d={pathD} fill="none" stroke="transparent" strokeWidth="24" />

                        {/* Base link track */}
                        <path
                          d={pathD}
                          fill="none"
                          stroke={lineColor}
                          strokeWidth={isThreat ? 3 : isHovered ? 2.5 : 1.5}
                          strokeOpacity={isThreat ? 0.8 : isHovered ? 0.9 : 0.4}
                          strokeDasharray={isThreat ? "6,6" : undefined}
                          className={cn(isThreat && "particle-flow-fast")}
                        />

                        {/* Animated moving photons along the curve */}
                        <circle r={isThreat ? 4.5 : 3.5} fill={particleColor}>
                          <animateMotion
                            path={pathD}
                            dur={isThreat ? "1.8s" : "3.6s"}
                            repeatCount="indefinite"
                          />
                        </circle>
                        <circle r={isThreat ? 3 : 2.5} fill={particleColor} opacity="0.6">
                          <animateMotion
                            path={pathD}
                            dur={isThreat ? "1.8s" : "3.6s"}
                            begin={isThreat ? "0.9s" : "1.8s"}
                            repeatCount="indefinite"
                          />
                        </circle>

                        {/* Mid-point link telemetry pill */}
                        <g transform={`translate(${mx}, ${my})`}>
                          <rect
                            x="-48"
                            y="-11"
                            width="96"
                            height="22"
                            rx="5"
                            fill="#0c101d"
                            stroke={lineColor}
                            strokeWidth={isHovered ? 1.5 : 0.8}
                            strokeOpacity="0.8"
                          />
                          <text
                            x="0"
                            y="3.5"
                            textAnchor="middle"
                            className="font-mono text-[10px] font-semibold"
                            fill={isThreat ? "#f43f5e" : isWatch ? "#fbbf24" : "#2dd4bf"}
                          >
                            {link.throughput} {link.modelScore !== undefined ? `· P:${Math.round(link.modelScore * 100)}%` : ""}
                          </text>
                        </g>
                      </g>
                    );
                  })}

                  {/* Segment Nodes */}
                  {segments.map((seg) => {
                    const coord = SEGMENT_COORDINATES[seg.name] || { x: 440, y: 260, r: 38 };
                    const isSelected = selectedSegment === seg.name;
                    const isCritical = seg.state === "critical";
                    const isWatch = seg.state === "watch";

                    const stateColor = isCritical
                      ? "oklch(0.6483 0.1819 13.23)"
                      : isWatch
                      ? "oklch(0.7846 0.1287 63.94)"
                      : "oklch(0.803 0.1212 181.68)";

                    const glowId = isCritical
                      ? "url(#glow-critical)"
                      : isWatch
                      ? "url(#glow-watch)"
                      : "url(#glow-normal)";

                    return (
                      <g
                        key={seg.name}
                        transform={`translate(${coord.x}, ${coord.y})`}
                        onClick={() => setSelectedSegment(seg.name)}
                        className="cursor-pointer transition-transform duration-200 hover:scale-105"
                      >
                        {/* Expanding sonar radar ring for critical threats */}
                        {isCritical && (
                          <circle
                            r={coord.r + 28}
                            fill="none"
                            stroke="oklch(0.6483 0.1819 13.23)"
                            strokeWidth="2"
                            className="animate-radar"
                          />
                        )}

                        {/* Ambient glow backdrop circle */}
                        <circle r={coord.r + 18} fill={glowId} />

                        {/* Segment main circular tile */}
                        <circle
                          r={coord.r}
                          fill="#0f1424"
                          stroke={stateColor}
                          strokeWidth={isSelected ? 3.5 : 2}
                          strokeOpacity={isSelected ? 1 : 0.75}
                          className="transition-all"
                        />

                        {/* Quarantined hazard stripe overlay if isolated */}
                        {seg.isolated && (
                          <circle r={coord.r - 2} fill="url(#hazard-quarantine)" />
                        )}

                        {/* Center Icon or Beacon */}
                        <circle
                          cy="-16"
                          r="5"
                          fill={stateColor}
                          className={cn(isCritical && "animate-pulse")}
                        />

                        {/* Segment Name */}
                        <text
                          y="-2"
                          textAnchor="middle"
                          className="font-mono text-[12px] font-bold tracking-tight"
                          fill="#f1f5f9"
                        >
                          {seg.name}
                        </text>

                        {/* Host count & Throughput */}
                        <text
                          y="13"
                          textAnchor="middle"
                          className="font-mono text-[10px]"
                          fill="#94a3b8"
                        >
                          {seg.hosts} hosts · {seg.throughputMbps}M
                        </text>

                        {/* Neural Model Probability Badge */}
                        {seg.modelProbability !== undefined && (
                          <text
                            y="26"
                            textAnchor="middle"
                            className={cn(
                              "font-mono text-[9px] font-semibold",
                              seg.modelProbability >= 0.7
                                ? "fill-crimson"
                                : seg.modelProbability >= 0.4
                                ? "fill-amber"
                                : "fill-teal"
                            )}
                          >
                            P(infil): {Math.round(seg.modelProbability * 100)}%
                          </text>
                        )}

                        {/* Active alert badge */}
                        {seg.activeAlerts > 0 && (
                          <g transform={`translate(${coord.r - 8}, ${-coord.r + 8})`}>
                            <circle
                              r="10"
                              fill={isCritical ? "#f43f5e" : "#fbbf24"}
                              stroke="#0f1424"
                              strokeWidth="2"
                            />
                            <text
                              y="3.5"
                              textAnchor="middle"
                              className="font-mono text-[10px] font-bold text-void-900"
                              fill="#0f1424"
                            >
                              {seg.activeAlerts}
                            </text>
                          </g>
                        )}

                        {/* Quarantined lock badge */}
                        {seg.isolated && (
                          <g transform={`translate(${-coord.r + 8}, ${-coord.r + 8})`}>
                            <circle r="10" fill="#f43f5e" stroke="#0f1424" strokeWidth="2" />
                            <text
                              y="3.5"
                              textAnchor="middle"
                              className="font-mono text-[9px] font-bold"
                              fill="#ffffff"
                            >
                              Q
                            </text>
                          </g>
                        )}
                      </g>
                    );
                  })}
                </svg>
              </div>
            </div>
          ) : (
            /* Treemap View with Sized Tiles & Mini Sparklines */
            <HeroPanel
              title="Adaptive Segment Treemap"
              state={segments.some((s) => s.state === "critical") ? "critical" : "normal"}
            >
              <p className="mb-3 text-[12px] text-fog font-mono">
                Tile surface area tracks physical traffic share; dynamic aura reflects real-time threat stage.
              </p>
              <div className="flex flex-wrap gap-3">
                {filteredSegments.map((s) => {
                  const isSelected = selectedSegment === s.name;
                  const isCritical = s.state === "critical";
                  const isWatch = s.state === "watch";

                  // Sparkline SVG path calculation (12 points)
                  const sparklinePoints = s.sparkline && s.sparkline.length > 0 ? s.sparkline : [20, 22, 21, 24, 28, 26, 32, 36, 42, 48, 52, 60];
                  const min = Math.min(...sparklinePoints);
                  const max = Math.max(...sparklinePoints) || 1;
                  const pts = sparklinePoints
                    .map((val, idx) => {
                      const x = (idx / (sparklinePoints.length - 1)) * 120;
                      const y = 26 - ((val - min) / (max - min || 1)) * 22;
                      return `${x.toFixed(1)},${y.toFixed(1)}`;
                    })
                    .join(" ");

                  return (
                    <button
                      key={s.name}
                      type="button"
                      onClick={() => setSelectedSegment(s.name)}
                      className={cn(
                        "group relative overflow-hidden rounded-xl border p-4 text-left transition-all duration-300 hover:brightness-110",
                        isSelected
                          ? "ring-2 ring-teal ring-offset-2 ring-offset-void-900 shadow-xl"
                          : "hover:border-fog-deep",
                        isCritical && "shadow-lg shadow-crimson/20",
                        isWatch && "shadow-md shadow-amber/15"
                      )}
                      style={{
                        flexBasis: `${Math.max(28, (s.trafficVolume / totalTrafficVolume) * 280)}%`,
                        minHeight: 130 + s.trafficVolume * 1.5,
                        borderColor: `color-mix(in oklab, ${stateColorVar[s.state]} 50%, transparent)`,
                        background: `radial-gradient(circle at top left, color-mix(in oklab, ${stateColorVar[s.state]} 22%, transparent), #0f1424 85%)`,
                      }}
                    >
                      {/* Pulse beacon if critical */}
                      {isCritical && (
                        <span className="absolute top-3 right-3 flex size-3">
                          <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-crimson opacity-75" />
                          <span className="relative inline-flex size-3 rounded-full bg-crimson" />
                        </span>
                      )}

                      {/* Quarantined banner if isolated */}
                      {s.isolated && (
                        <div className="absolute top-0 right-0 rounded-bl-lg bg-crimson/90 px-2 py-0.5 text-[9px] font-mono font-bold uppercase text-white shadow-xs">
                          Quarantined
                        </div>
                      )}

                      <div className="flex items-start justify-between">
                        <div>
                          <p className="mono text-base font-bold text-paper group-hover:text-teal transition-colors">
                            {s.name}
                          </p>
                          <p className="mt-1 text-[12px] font-mono text-fog">
                            {s.hosts} hosts · {s.trafficVolume}% estate share
                          </p>
                        </div>
                      </div>

                      <div className="mt-2 flex items-baseline gap-2">
                        <span className="font-mono text-xl font-bold text-paper">
                          {s.throughputMbps}
                        </span>
                        <span className="font-mono text-[11px] text-teal">Mbps</span>
                        <span className="ml-auto font-mono text-[11px] text-fog">
                          Model P: <strong className={cn(s.modelProbability && s.modelProbability >= 0.7 ? "text-crimson" : "text-teal")}>{s.modelProbability ? `${Math.round(s.modelProbability * 100)}%` : "—"}</strong>
                        </span>
                      </div>

                      {/* Embedded Live SVG Sparkline */}
                      <div className="mt-3 flex items-end justify-between">
                        <div className="w-[120px]">
                          <svg viewBox="0 0 120 28" className="h-7 w-full overflow-visible">
                            <polyline
                              fill="none"
                              stroke={
                                isCritical
                                  ? "#f43f5e"
                                  : isWatch
                                  ? "#fbbf24"
                                  : "#2dd4bf"
                              }
                              strokeWidth="2"
                              strokeLinecap="round"
                              strokeLinejoin="round"
                              points={pts}
                            />
                          </svg>
                        </div>

                        <div>
                          <RiskBadge state={s.state} />
                        </div>
                      </div>
                    </button>
                  );
                })}
              </div>
            </HeroPanel>
          )}

          {/* Segment Telemetry Table Roster */}
          <FlatPanel
            title="Monitored Subnet Roster"
            control={
              <div className="relative w-48">
                <Search className="absolute left-2.5 top-2.5 size-3.5 text-fog" />
                <input
                  type="text"
                  placeholder="Filter segment or host..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="w-full rounded-md border border-fog-deep/40 bg-void-900 py-1.5 pl-8 pr-2.5 text-[12px] font-mono text-paper placeholder:text-fog focus:border-teal focus:outline-none"
                />
              </div>
            }
            bodyClassName="p-0"
          >
            <div className="overflow-x-auto">
              <table className="w-full text-left">
                <thead className="border-b border-fog-deep/60 text-[12px] text-fog">
                  <tr>
                    <th className="px-4 py-2.5 font-medium">Segment</th>
                    <th className="px-4 py-2.5 font-medium">Status</th>
                    <th className="px-4 py-2.5 font-medium">Model Stage</th>
                    <th className="px-4 py-2.5 text-right font-medium">Model P(infil)</th>
                    <th className="px-4 py-2.5 text-right font-medium">Throughput</th>
                    <th className="px-4 py-2.5 text-right font-medium">Alerts</th>
                    <th className="px-4 py-2.5 font-medium">Isolation</th>
                    <th className="px-4 py-2.5 text-right font-medium">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredSegments.map((s) => {
                    const isSelected = selectedSegment === s.name;
                    return (
                      <tr
                        key={s.name}
                        onClick={() => setSelectedSegment(s.name)}
                        className={cn(
                          "cursor-pointer border-b border-fog-deep/40 last:border-0 transition-colors hover:bg-paper/4",
                          isSelected && "bg-teal/8"
                        )}
                      >
                        <td className="mono px-4 py-2.5 font-semibold text-paper">
                          <span className="hover:text-teal transition-colors">{s.name}</span>
                        </td>
                        <td className="px-4 py-2.5">
                          <RiskBadge state={s.state} />
                        </td>
                        <td className="mono px-4 py-2.5 text-fog text-[12px]">
                          {s.modelStage || "Normal"}
                        </td>
                        <td className="mono px-4 py-2.5 text-right">
                          <span
                            className={cn(
                              s.modelProbability && s.modelProbability >= 0.7
                                ? "font-bold text-crimson"
                                : s.modelProbability && s.modelProbability >= 0.4
                                ? "text-amber"
                                : "text-teal"
                            )}
                          >
                            {s.modelProbability ? `${Math.round(s.modelProbability * 100)}%` : "—"}
                          </span>
                        </td>
                        <td className="mono px-4 py-2.5 text-right text-paper">
                          {s.throughputMbps} Mbps
                        </td>
                        <td className="mono px-4 py-2.5 text-right">
                          <span
                            className={cn(
                              s.activeAlerts > 0 ? "font-bold text-crimson" : "text-fog"
                            )}
                          >
                            {s.activeAlerts}
                          </span>
                        </td>
                        <td className="px-4 py-2.5">
                          {s.isolated ? (
                            <span className="inline-flex items-center gap-1 rounded bg-crimson/15 px-2 py-0.5 font-mono text-[11px] font-semibold text-crimson border border-crimson/30">
                              <Lock className="size-3" /> Quarantined
                            </span>
                          ) : (
                            <span className="inline-flex items-center gap-1 rounded bg-teal/10 px-2 py-0.5 font-mono text-[11px] text-teal border border-teal/20">
                              <Unlock className="size-3" /> Integrated
                            </span>
                          )}
                        </td>
                        <td className="mono px-4 py-2.5 text-right">
                          <button
                            type="button"
                            onClick={(e) => {
                              e.stopPropagation();
                              setSelectedSegment(s.name);
                            }}
                            className="inline-flex items-center gap-1 text-[12px] text-teal hover:underline"
                          >
                            Inspect <ChevronRight className="size-3.5" />
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </FlatPanel>
        </div>

        {/* Right Column: Interactive Segment Deep-Dive Inspection Drawer */}
        <div className="flex flex-col gap-4">
          {selectedSegment && deepDive ? (
            <div className="rounded-2xl border border-fog-deep/40 bg-void-800/95 p-5 shadow-2xl backdrop-blur-md">
              {/* Header */}
              <div className="flex items-start justify-between border-b border-fog-deep/30 pb-4">
                <div>
                  <div className="flex items-center gap-2">
                    <h3 className="font-mono text-xl font-bold text-paper">
                      {deepDive.segment.name}
                    </h3>
                    <RiskBadge state={deepDive.segment.state} />
                  </div>
                  <p className="mt-1 text-[12px] text-fog">
                    {deepDive.segment.hosts} physical endpoints · Last incident: {deepDive.segment.lastIncident}
                  </p>
                </div>

                {/* Microsegmentation Quarantine Trigger */}
                <button
                  type="button"
                  onClick={() =>
                    handleToggleIsolation(deepDive.segment.name, deepDive.segment.isolated)
                  }
                  disabled={isolateMutation.isPending}
                  className={cn(
                    "flex items-center gap-1.5 rounded-lg px-3 py-1.5 font-mono text-[12px] font-semibold transition-all shadow-md",
                    deepDive.segment.isolated
                      ? "bg-teal/20 text-teal border border-teal/50 hover:bg-teal/30"
                      : "bg-crimson/20 text-crimson border border-crimson/50 hover:bg-crimson/30"
                  )}
                >
                  {deepDive.segment.isolated ? (
                    <>
                      <Unlock className="size-3.5" />
                      Restore Routing
                    </>
                  ) : (
                    <>
                      <Lock className="size-3.5" />
                      Quarantine Segment
                    </>
                  )}
                </button>
              </div>

              {/* Real-time Telemetry Metrics Grid */}
              <div className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-4">
                <div className="rounded-lg border border-fog-deep/30 bg-void-900/60 p-2.5">
                  <span className="text-[10px] font-mono uppercase text-fog">Throughput</span>
                  <p className="mt-1 font-mono text-base font-bold text-paper">
                    {deepDive.segment.throughputMbps} <span className="text-[10px] text-teal">Mbps</span>
                  </p>
                </div>
                <div className="rounded-lg border border-fog-deep/30 bg-void-900/60 p-2.5">
                  <span className="text-[10px] font-mono uppercase text-fog">Active Alerts</span>
                  <p
                    className={cn(
                      "mt-1 font-mono text-base font-bold",
                      deepDive.segment.activeAlerts > 0 ? "text-crimson" : "text-paper"
                    )}
                  >
                    {deepDive.segment.activeAlerts}
                  </p>
                </div>
                <div className="rounded-lg border border-fog-deep/30 bg-void-900/60 p-2.5">
                  <span className="text-[10px] font-mono uppercase text-fog">Model P(infil)</span>
                  <p className="mt-1 font-mono text-base font-bold text-amber">
                    {deepDive.modelAnalysis?.probability ? `${Math.round(deepDive.modelAnalysis.probability * 100)}%` : `${deepDive.segment.threatScore}%`}
                  </p>
                </div>
                <div className="rounded-lg border border-fog-deep/30 bg-void-900/60 p-2.5">
                  <span className="text-[10px] font-mono uppercase text-fog">Zero-Trust ACL</span>
                  <p
                    className={cn(
                      "mt-1 font-mono text-xs font-semibold uppercase",
                      deepDive.segment.isolated ? "text-crimson" : "text-teal"
                    )}
                  >
                    {deepDive.segment.isolated ? "Quarantined" : "Normal"}
                  </p>
                </div>
              </div>

              {/* Cyber World Model Diagnostic Section */}
              {deepDive.modelAnalysis && (
                <div className="mt-5 rounded-xl border border-teal/30 bg-teal/5 p-3.5">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-1.5 text-teal font-mono text-[12px] font-semibold">
                      <Cpu className="size-3.5" />
                      Neural World Model Evaluation
                    </div>
                    <span className="font-mono text-[11px] text-fog">
                      Lead time: <strong className="text-teal">{deepDive.modelAnalysis.leadTimeSeconds}s</strong>
                    </span>
                  </div>

                  {/* Dual branch breakdown */}
                  <div className="mt-2.5 grid grid-cols-2 gap-2 text-[11px] font-mono">
                    <div className="rounded border border-fog-deep/20 bg-void-900/60 p-2">
                      <span className="text-fog">SparseRSSM Branch:</span>
                      <p className="text-paper font-bold mt-0.5">{(deepDive.modelAnalysis.rssmScore * 100).toFixed(1)}%</p>
                    </div>
                    <div className="rounded border border-fog-deep/20 bg-void-900/60 p-2">
                      <span className="text-fog">TFCNet Spectral:</span>
                      <p className="text-paper font-bold mt-0.5">{(deepDive.modelAnalysis.tfcScore * 100).toFixed(1)}%</p>
                    </div>
                  </div>

                  {/* Feature Drivers (Explainability Bar Chart) */}
                  {deepDive.modelAnalysis.featureDrivers && deepDive.modelAnalysis.featureDrivers.length > 0 && (
                    <div className="mt-3">
                      <span className="font-mono text-[11px] font-medium text-fog">Top Feature Attributions (SHAP weights)</span>
                      <div className="mt-1.5 flex flex-col gap-1">
                        {deepDive.modelAnalysis.featureDrivers.slice(0, 4).map((feat) => {
                          const isPos = feat.weight > 0;
                          return (
                            <div key={feat.feature} className="flex items-center justify-between text-[10px] font-mono">
                              <span className="text-paper w-32 truncate" title={feat.feature}>
                                {feat.feature}
                              </span>
                              <div className="flex-1 mx-2 h-1.5 rounded-full bg-void-700 overflow-hidden">
                                <div
                                  className={cn("h-full rounded-full", isPos ? "bg-crimson" : "bg-teal")}
                                  style={{ width: `${Math.min(100, Math.abs(feat.weight) * 250)}%` }}
                                />
                              </div>
                              <span className={cn(isPos ? "text-crimson font-bold" : "text-teal")}>
                                {isPos ? `+${feat.weight.toFixed(2)}` : feat.weight.toFixed(2)}
                              </span>
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  )}

                  {/* Model Flow Telemetry */}
                  {deepDive.modelAnalysis.modelFlows && deepDive.modelAnalysis.modelFlows.length > 0 && (
                    <div className="mt-3 pt-2.5 border-t border-teal/20">
                      <span className="font-mono text-[11px] font-medium text-fog">Model Observed Flow Tuples</span>
                      <div className="mt-1.5 flex flex-col gap-1.5">
                        {deepDive.modelAnalysis.modelFlows.map((fl, idx) => (
                          <div
                            key={idx}
                            className="flex items-center justify-between rounded bg-void-900/60 px-2 py-1 text-[10px] font-mono border border-fog-deep/20"
                          >
                            <span className="text-paper truncate max-w-[170px]" title={`${fl.src} -> ${fl.dst}`}>
                              {fl.src.split(":")[0]} → {fl.dst}
                            </span>
                            <span className="text-fog">{fl.proto} [{fl.flags}]</span>
                            <span className={cn("font-bold", fl.prob >= 0.7 ? "text-crimson" : "text-amber")}>
                              P: {Math.round(fl.prob * 100)}%
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* Protocol Breakdown Visualizer */}
              <div className="mt-5">
                <div className="flex items-center justify-between text-[12px]">
                  <span className="font-mono font-medium text-paper">Traffic Protocol Distribution</span>
                  <span className="text-fog font-mono text-[11px]">Primary signatures</span>
                </div>
                {/* Segmented multi-color bar */}
                <div className="mt-2 flex h-3 w-full overflow-hidden rounded-md bg-void-700">
                  {deepDive.protocols.map((proto, idx) => {
                    const colors = ["bg-teal", "bg-amber", "bg-blue-400", "bg-purple-400"];
                    const barColor = colors[idx % colors.length];
                    return (
                      <div
                        key={proto.name}
                        className={cn("h-full transition-all duration-300", barColor)}
                        style={{ width: `${proto.pct}%` }}
                        title={`${proto.name} (Port ${proto.port}): ${proto.pct}%`}
                      />
                    );
                  })}
                </div>
                {/* Protocol legend chips */}
                <div className="mt-2.5 flex flex-wrap gap-2">
                  {deepDive.protocols.map((proto, idx) => {
                    const textColors = ["text-teal", "text-amber", "text-blue-400", "text-purple-400"];
                    const col = textColors[idx % textColors.length];
                    return (
                      <span
                        key={proto.name}
                        className="inline-flex items-center gap-1 rounded bg-void-900 px-2 py-0.5 font-mono text-[11px] text-fog"
                      >
                        <span className={cn("size-2 rounded-full", col?.replace("text-", "bg-"))} />
                        {proto.name} ({proto.port}): <strong className={col}>{proto.pct}%</strong>
                      </span>
                    );
                  })}
                </div>
              </div>

              {/* Host Inventory Roster in this Segment */}
              <div className="mt-5">
                <div className="flex items-center justify-between border-b border-fog-deep/30 pb-2">
                  <span className="font-mono text-[13px] font-semibold text-paper">
                    Physical Endpoints in Segment
                  </span>
                  <Link
                    to="/app/network"
                    className="inline-flex items-center gap-1 font-mono text-[11px] text-teal hover:underline"
                  >
                    Open Network Graph <ExternalLink className="size-3" />
                  </Link>
                </div>

                <div className="mt-3 flex flex-col gap-2">
                  {(deepDive.hostRoster || []).map((host) => (
                    <div
                      key={host.ip}
                      className="flex items-center justify-between rounded-lg border border-fog-deep/30 bg-void-900/50 p-2.5 transition-colors hover:border-teal/40"
                    >
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-[12px] font-bold text-paper">
                            {host.hostname}
                          </span>
                          <span className="font-mono text-[11px] text-fog">({host.ip})</span>
                        </div>
                        <p className="text-[11px] text-fog">
                          {host.role} · <span className="text-fog-deep">{host.os}</span>
                        </p>
                      </div>

                      <div className="flex items-center gap-2">
                        <button
                          type="button"
                          onClick={() => navigate({ to: "/app/explorer" })}
                          className="rounded border border-fog-deep/40 px-2 py-1 font-mono text-[10px] text-fog hover:border-teal hover:text-teal"
                        >
                          DPI Flows
                        </button>
                        <button
                          type="button"
                          onClick={() => navigate({ to: "/app/network" })}
                          className="rounded border border-fog-deep/40 px-2 py-1 font-mono text-[10px] text-fog hover:border-teal hover:text-teal"
                        >
                          Trace
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Active Enforced ACL Security Policies */}
              <div className="mt-5">
                <span className="font-mono text-[13px] font-semibold text-paper">
                  Enforced Microsegmentation Policies
                </span>
                <div className="mt-2.5 flex flex-col gap-1.5">
                  {deepDive.policies.map((p) => (
                    <div
                      key={p.id}
                      className="flex items-center justify-between rounded-md border border-fog-deep/20 bg-void-900/40 px-3 py-2 text-[11px] font-mono"
                    >
                      <div className="flex items-center gap-2">
                        <Shield className="size-3.5 text-teal" />
                        <span className="text-paper">{p.rule}</span>
                      </div>
                      <span className="text-fog">{p.status}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Related Alerts for hosts in this segment */}
              {deepDive.relatedAlerts && deepDive.relatedAlerts.length > 0 && (
                <div className="mt-5 border-t border-fog-deep/30 pt-4">
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-[13px] font-semibold text-crimson">
                      Active Incidents in Segment
                    </span>
                    <Link
                      to="/app/alerts"
                      className="font-mono text-[11px] text-fog hover:text-paper"
                    >
                      View in Alerts Kanban →
                    </Link>
                  </div>
                  <div className="mt-2.5 flex flex-col gap-2">
                    {deepDive.relatedAlerts.map((a) => (
                      <div
                        key={a.alertId}
                        className="rounded-lg border border-crimson/30 bg-crimson/10 p-2.5"
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-mono text-[12px] font-bold text-crimson">
                            {a.alertId} · {a.host}
                          </span>
                          <RiskBadge state={a.state} />
                        </div>
                        <p className="mt-1 text-[11px] text-paper/90">{a.reason}</p>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="flex h-64 flex-col items-center justify-center rounded-2xl border border-dashed border-fog-deep/40 bg-void-800/40 p-6 text-center">
              <Server className="size-8 text-fog/50" />
              <p className="mt-2 font-mono text-[13px] text-paper">Select a segment to inspect</p>
              <p className="mt-1 text-[12px] text-fog">
                Click any tile or nexus node to inspect live endpoints, protocols, and micro-segmentation controls.
              </p>
            </div>
          )}
        </div>
      </div>
    </>
  );
}
