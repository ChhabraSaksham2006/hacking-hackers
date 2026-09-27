import { useState, useMemo, useEffect } from "react";
import { createFileRoute, Link } from "@tanstack/react-router";
import { X, RefreshCw, Radio } from "lucide-react";
import { HeroPanel, PageTitle, RiskBadge } from "@/components/app/panels";
import { NetworkGraph, type GraphNode, type GraphEdge } from "@/components/app/charts";
import { pageHead } from "@/lib/head";
import { cn } from "@/lib/utils";
import { useNetworkGraph, useHostDetails } from "@/hooks/useApi";
import { subscribeDashboardStream } from "@/api/dashboardApi";

export const Route = createFileRoute("/app/network")({
  head: pageHead(
    "Network state â€” Flow दृष्टि",
    "Live host and flow graph with a time scrubber across historical and forecast network states.",
  ),
  component: NetworkState,
});

function NetworkState() {
  const [view, setView] = useState<"flow" | "packet">("flow");
  const [segmentFilter, setSegmentFilter] = useState<string>("all segments");
  const [isLiveMode, setIsLiveMode] = useState<boolean>(true);
  const [scrub, setScrub] = useState(100);
  const [selected, setSelected] = useState<string | null>("192.168.10.44");

  // Subscribe to real-time simulation/dashboard stream
  useEffect(() => {
    const unsubscribe = subscribeDashboardStream((state) => {
      if (isLiveMode) {
        const liveWin = state.actual_window_index;
        const mappedScrub = Math.max(0, Math.min(100, Math.round(((liveWin - 1750) / 60) * 100)));
        setScrub(mappedScrub);
      }
    });
    return () => unsubscribe();
  }, [isLiveMode]);

  const { data: graphData, isLoading, refetch } = useNetworkGraph({
    scrub: isLiveMode ? undefined : scrub,
    live: isLiveMode,
  });
  const { data: hostDetail } = useHostDetails(selected || "192.168.10.44", isLiveMode ? undefined : scrub);

  // Keep slider position synced when live graph data returns
  useEffect(() => {
    if (isLiveMode && graphData?.scrub !== undefined) {
      setScrub(graphData.scrub);
    }
  }, [isLiveMode, graphData?.scrub]);

  const nodes: GraphNode[] = useMemo(() => {
    if (!graphData?.nodes || graphData.nodes.length === 0) return [];

    let filtered = graphData.nodes as GraphNode[];
    if (segmentFilter !== "all segments") {
      filtered = filtered.filter((n) => n.segment === segmentFilter);
    }
    return filtered;
  }, [graphData?.nodes, segmentFilter]);

  const edges: GraphEdge[] = useMemo(() => {
    if (!graphData?.edges) return [];
    return graphData.edges as GraphEdge[];
  }, [graphData?.edges]);

  const activeNode = useMemo(() => {
    if (!selected) return null;
    return nodes.find((n) => n.id === selected) || nodes[0] || null;
  }, [selected, nodes]);

  // Derive highest risk state across estate for hero panel
  const overallState = useMemo(() => {
    if (nodes.some((n) => n.state === "critical")) return "critical";
    if (nodes.some((n) => n.state === "watch")) return "watch";
    return "normal";
  }, [nodes]);

  const currentWindow = graphData?.windowIndex ?? Math.round(1750 + (scrub / 100) * 60);
  const currentPhase = graphData?.phase ?? (scrub >= 77 ? "Lateral Movement" : scrub >= 52 ? "Recon" : "Benign Baseline");
  const currentProb = graphData?.probability !== undefined ? `${(graphData.probability * 100).toFixed(0)}%` : "â€”";

  return (
    <>
      <PageTitle
        title="Network state"
        note="Node size tracks real telemetry flow volume, colour tracks predicted risk. Grounded in CIC-IDS-2018 benchmark telemetry."
        actions={
          <div className="flex items-center gap-2">
            {isLiveMode ? (
              <div className="flex items-center gap-1.5 px-2.5 py-1 text-[11px] font-mono text-teal border border-teal/40 rounded bg-teal/10">
                <span className="size-2 rounded-full bg-teal animate-pulse" />
                Live Telemetry Stream
              </div>
            ) : (
              <button
                onClick={() => {
                  setIsLiveMode(true);
                  refetch();
                }}
                className="flex items-center gap-1.5 px-2.5 py-1 text-[11px] font-mono text-amber border border-amber/40 rounded bg-amber/10 hover:bg-amber/20 transition-colors"
              >
                <Radio className="size-3 text-amber animate-pulse" />
                Resume Live Stream â†’
              </button>
            )}
            <button
              onClick={() => {
                setIsLiveMode(true);
                refetch();
              }}
              className="flex items-center gap-1.5 rounded-md border border-fog-deep/60 px-3 py-1.5 text-[12px] font-medium text-fog transition-colors hover:border-paper hover:text-paper"
            >
              <RefreshCw className={cn("size-3.5", isLoading && "animate-spin")} />
              Sync topology
            </button>
          </div>
        }
      />

      <div className="grid gap-5 lg:grid-cols-[220px_minmax(0,1fr)]">
        <div className="flat h-fit p-4">
          <p className="text-[13px] font-medium">View level</p>
          <div className="mt-2 flex flex-col gap-1">
            {(["flow", "packet"] as const).map((v) => (
              <button
                key={v}
                onClick={() => setView(v)}
                className={cn(
                  "rounded-md px-3 py-1.5 text-left text-[13px] font-medium",
                  view === v ? "bg-teal/12 text-teal" : "text-fog hover:text-paper",
                )}
              >
                {v === "flow" ? "Flow level" : "Packet level"}
              </button>
            ))}
          </div>

          <p className="mt-5 text-[13px] font-medium">Segment</p>
          <select
            value={segmentFilter}
            onChange={(e) => setSegmentFilter(e.target.value)}
            className="mono mt-2 w-full rounded-md border border-fog-deep bg-void-700 px-2.5 py-1.5 text-[13px] outline-none"
          >
            <option>all segments</option>
            <option>corp-core</option>
            <option>finance</option>
            <option>dmz-edge</option>
          </select>

          <p className="mt-5 text-[13px] font-medium">Timeline Presets</p>
          <div className="mt-2 flex flex-col gap-1">
            {[
              { label: "Live Telemetry", value: -1 },
              { label: "Baseline (Normal)", value: 0 },
              { label: "Recon Sweep", value: 58 },
              { label: "Initial Access", value: 72 },
              { label: "Lateral Movement", value: 85 },
              { label: "C2 Beaconing", value: 98 },
            ].map((p) => (
              <button
                key={p.label}
                onClick={() => {
                  if (p.value === -1) {
                    setIsLiveMode(true);
                  } else {
                    setIsLiveMode(false);
                    setScrub(p.value);
                  }
                }}
                className={cn(
                  "rounded-md px-2.5 py-1 text-left text-[11px] font-mono transition-colors",
                  (p.value === -1 ? isLiveMode : (!isLiveMode && scrub === p.value))
                    ? "bg-teal/15 text-teal font-semibold"
                    : "text-fog hover:text-paper hover:bg-paper/5",
                )}
              >
                {p.label}
              </button>
            ))}
          </div>

          <div className="mt-6 border-t border-fog-deep/40 pt-4 text-[12px] text-fog">
            <p className="font-medium text-paper">Active Subnet</p>
            <p className="mono mt-1 text-[11px]">192.168.10.0/24</p>
            <p className="mt-2 font-medium text-paper">Dataset Target</p>
            <p className="mono mt-1 text-[11px]">Thursday-01-03-2018 (EP_0001)</p>
          </div>
        </div>

        <HeroPanel
          title="Host and flow graph"
          state={overallState}
          control={
            <div className="flex items-center gap-3">
              <span className="mono text-[12px] text-paper font-medium">
                {currentPhase}
              </span>
              <span className="mono text-fog text-[12px]">
                {isLiveMode ? "live telemetry" : `historical window #${currentWindow}`}
              </span>
            </div>
          }
          bodyClassName="p-0"
        >
          <div className="p-5">
            <NetworkGraph
              nodes={nodes}
              edges={edges}
              onSelect={(id) => setSelected(id)}
              selected={selected ?? undefined}
              scrub={scrub}
            />
          </div>
          <div className="flex flex-col gap-2 border-t border-[var(--glass-border)] bg-void-800/70 px-5 py-3">
            <div className="flex items-center justify-between text-[12px]">
              <span className="mono text-fog">Window #1750 (Baseline)</span>
              <div className="flex items-center gap-2">
                <span className="mono text-paper font-semibold">Window #{currentWindow}</span>
                <span className="text-fog">Â·</span>
                <span className={cn("mono font-semibold", overallState === "critical" ? "text-crimson" : overallState === "watch" ? "text-amber" : "text-teal")}>
                  {currentProb} Risk
                </span>
                {!isLiveMode && (
                  <button
                    onClick={() => setIsLiveMode(true)}
                    className="ml-2 rounded border border-teal/40 bg-teal/10 px-2 py-0.5 text-[10px] font-mono text-teal hover:bg-teal/20"
                  >
                    Track Live Stream
                  </button>
                )}
              </div>
              <span className="mono text-fog">Window #1810 (C2 Egress)</span>
            </div>
            <input
              type="range"
              min={0}
              max={100}
              value={scrub}
              onChange={(e) => {
                setIsLiveMode(false);
                setScrub(Number(e.target.value));
              }}
              aria-label="Time scrubber"
              className="w-full accent-teal cursor-pointer"
            />
          </div>
        </HeroPanel>
      </div>

      {activeNode ? (
        <aside className="fixed inset-y-0 right-0 z-30 w-[380px] overflow-y-auto border-l border-fog-deep bg-void-800 p-5 shadow-2xl">
          <div className="flex items-start justify-between">
            <div>
              <p className="mono text-[16px] font-semibold text-paper">{activeNode.id}</p>
              <p className="text-[12px] text-fog">{activeNode.hostname ?? activeNode.role ?? "Network Host"}</p>
              <div className="mt-2">
                <RiskBadge state={activeNode.state} />
              </div>
            </div>
            <button
              onClick={() => setSelected(null)}
              aria-label="Close host detail"
              className="text-fog hover:text-paper"
            >
              <X className="size-4" />
            </button>
          </div>

          <dl className="mt-6 space-y-3">
            {[
              ["Role", activeNode.role ?? "Endpoint Node"],
              ["Segment", activeNode.segment ?? "corp-core"],
              ["Risk score", hostDetail ? hostDetail.riskScore.toFixed(2) : (activeNode.state === "critical" ? "0.91" : activeNode.state === "watch" ? "0.52" : "0.08")],
              ["Active flows", `${hostDetail?.activeFlows ?? activeNode.flows ?? 14}`],
              ["Telemetry bytes", `${((hostDetail?.totalBytes ?? activeNode.bytes ?? 12400) / 1024).toFixed(1)} KB`],
              ["First seen", hostDetail?.firstSeen ?? "2018-03-01 01:40:00 UTC"],
            ].map(([k, v]) => (
              <div key={k} className="flex justify-between border-b border-fog-deep/40 pb-2 text-[13px]">
                <dt className="text-fog">{k}</dt>
                <dd className="mono text-paper">{v}</dd>
              </div>
            ))}
          </dl>

          <p className="mt-6 text-[13px] font-medium text-paper">Active telemetry flows</p>
          <ul className="mono mt-2 space-y-2 text-[12px] text-fog">
            {hostDetail?.recentFlows && hostDetail.recentFlows.length > 0 ? (
              hostDetail.recentFlows.map((rf: any, idx: number) => (
                <li key={idx} className="flex items-center justify-between rounded bg-paper/5 p-2">
                  <span>â†’ {rf.dst}</span>
                  <span className="text-paper">{typeof rf.bytes === 'number' ? `${(rf.bytes / 1024).toFixed(1)} KB` : rf.bytes}</span>
                </li>
              ))
            ) : (
              <li className="text-fog-deep">No recent suspicious flows for this node</li>
            )}
          </ul>

          <Link
            to="/app/explorer"
            className="mt-6 inline-block text-[13px] font-medium text-teal hover:underline"
          >
            Investigate host in flow explorer â†’
          </Link>
        </aside>
      ) : null}
    </>
  );
}

export default NetworkState;

