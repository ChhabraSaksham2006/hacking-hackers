import { Fragment, useState, useMemo, useEffect } from "react";
import { createFileRoute } from "@tanstack/react-router";
import {
  ArrowRight,
  Binary,
  Check,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Clock,
  Copy,
  Download,
  Eye,
  FileText,
  Filter,
  Layers,
  Radio,
  RefreshCw,
  Search,
  ShieldAlert,
  Sliders,
} from "lucide-react";
import { FlatPanel, PageTitle, RiskBadge } from "@/components/app/panels";
import { pageHead } from "@/lib/head";
import { useFlows, type Flow, type PacketFrame } from "@/hooks/useApi";
import { subscribeDashboardStream } from "@/api/dashboardApi";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/app/explorer")({
  head: pageHead(
    "Flow & packet explorer â€” Flow दृष्टि",
    "Real-time and forensic flow reference table with deep packet inspection (DPI), protocol layer hierarchy, and Wireshark hex dumps.",
  ),
  component: Explorer,
});

const PROTOCOL_FILTERS = ["ALL", "TCP", "UDP", "SMB", "HTTP", "SSH", "DNS"] as const;

function formatBytes(bytes: number): string {
  if (bytes >= 1048576) return `${(bytes / 1048576).toFixed(2)} MB`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${bytes} B`;
}

function Explorer() {
  const [isLiveMode, setIsLiveMode] = useState<boolean>(true);
  const [targetWindow, setTargetWindow] = useState<number>(1796);
  const [flaggedOnly, setFlaggedOnly] = useState<boolean>(false);
  const [minScore, setMinScore] = useState<number>(0);
  const [search, setSearch] = useState<string>("");
  const [selectedProto, setSelectedProto] = useState<string>("ALL");
  const [openFlowId, setOpenFlowId] = useState<string | null>(null);
  const [selectedPacketIndex, setSelectedPacketIndex] = useState<Record<string, number>>({});
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // Subscribe to real-time simulation/dashboard stream
  useEffect(() => {
    const unsubscribe = subscribeDashboardStream((state) => {
      if (isLiveMode) {
        setTargetWindow(state.actual_window_index);
      }
    });
    return () => unsubscribe();
  }, [isLiveMode]);

  const { data: flowsData, isLoading, refetch } = useFlows({
    page: 1,
    limit: 50,
    windowIndex: isLiveMode ? undefined : targetWindow,
    live: isLiveMode,
    minScore: minScore > 0 ? minScore : undefined,
    flaggedOnly,
    search: search || undefined,
    proto: selectedProto !== "ALL" && ["TCP", "UDP", "ICMP"].includes(selectedProto) ? selectedProto : undefined,
    service: selectedProto !== "ALL" && !["TCP", "UDP", "ICMP"].includes(selectedProto) ? selectedProto : undefined,
  });

  // Keep targetWindow synced when live flowsData returns
  useEffect(() => {
    if (isLiveMode && flowsData?.windowIndex !== undefined) {
      setTargetWindow(flowsData.windowIndex);
    }
  }, [isLiveMode, flowsData?.windowIndex]);

  const rows = flowsData?.data ?? [];
  const total = flowsData?.pagination.total ?? 0;
  const summary = flowsData?.summary;

  const activeStage = flowsData?.stage ?? (targetWindow >= 1804 ? "C2" : targetWindow >= 1796 ? "Lateral Movement" : targetWindow >= 1781 ? "Recon" : "Normal");
  const riskState: "normal" | "watch" | "critical" =
    targetWindow >= 1796 ? "critical" : targetWindow >= 1781 ? "watch" : "normal";

  // Handle export
  const handleExportJSON = () => {
    const exportPayload = {
      exportTime: new Date().toISOString(),
      windowIndex: targetWindow,
      isLive: isLiveMode,
      totalFlows: total,
      flows: rows,
    };
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(exportPayload, null, 2));
    const downloadAnchor = document.createElement("a");
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `aegis-flows-w${targetWindow}-${Date.now()}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  const handleCopyHex = (content: string, id: string) => {
    navigator.clipboard.writeText(content);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  return (
    <>
      <PageTitle
        title="Flow and packet explorer"
        note="Reference view over ingested flows. Select a row to dissect its protocol layers, packet sequence, and raw hex payload."
        actions={
          <div className="flex items-center gap-2">
            {isLiveMode ? (
              <div className="flex items-center gap-1.5 rounded-full border border-teal/40 bg-teal/10 px-2.5 py-1 text-[11px] font-mono text-teal">
                <span className="relative flex h-2 w-2">
                  <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-teal opacity-75"></span>
                  <span className="relative inline-flex h-2 w-2 rounded-full bg-teal"></span>
                </span>
                Live Telemetry Stream
              </div>
            ) : (
              <button
                onClick={() => setIsLiveMode(true)}
                className="flex items-center gap-1.5 rounded-full border border-amber/50 bg-amber/10 px-2.5 py-1 text-[11px] font-mono text-amber hover:bg-amber/20 transition-colors"
              >
                <Radio className="size-3 text-amber animate-pulse" />
                Forensic review (paused) â€” Track Live Stream &rarr;
              </button>
            )}

            <button
              onClick={() => refetch()}
              className="flex items-center gap-1.5 rounded-md border border-fog-deep/60 px-3 py-1.5 text-[12px] font-medium text-fog transition-colors hover:border-paper hover:text-paper"
            >
              <RefreshCw className={cn("size-3.5", isLoading && "animate-spin")} />
              Refresh
            </button>

            <button
              onClick={handleExportJSON}
              className="flex items-center gap-1.5 rounded-md border border-fog-deep/60 px-3 py-1.5 text-[12px] font-medium text-fog transition-colors hover:border-paper hover:text-paper"
            >
              <Download className="size-3.5" />
              Export JSON
            </button>
          </div>
        }
      />

      {/* Top Telemetry & Scenario Presets Scrubber */}
      <div className="flat mb-6 p-4">
        <div className="flex flex-wrap items-center justify-between gap-2 pb-3">
          <div className="flex items-center gap-2">
            <Sliders className="size-4 text-teal" />
            <span className="text-[13px] font-medium text-paper">
              Temporal Window Scrubber &amp; Traffic Scenario Bookmarks
            </span>
          </div>
          <span className="mono text-[12px] text-fog">
            {isLiveMode
              ? `Live Tracking: Window #${flowsData?.windowIndex ?? targetWindow}`
              : `Historical Forensic Review: Window #${targetWindow}`}
          </span>
        </div>

        <div className="flex items-center gap-3">
          <span className="mono text-[11px] text-fog">#1750</span>
          <input
            type="range"
            min={1750}
            max={1810}
            value={targetWindow}
            onChange={(e) => {
              setIsLiveMode(false);
              setTargetWindow(Number(e.target.value));
            }}
            aria-label="Timeline window scrubber"
            className="w-full accent-teal cursor-pointer"
          />
          <span className="mono text-[11px] text-fog">#1810</span>
        </div>

        <div className="mt-3 flex flex-wrap gap-2 pt-2 border-t border-fog-deep/40">
          <button
            onClick={() => setIsLiveMode(true)}
            className={cn(
              "rounded-md px-2.5 py-1 text-[11px] font-mono transition-colors border flex items-center gap-1.5",
              isLiveMode
                ? "border-teal/60 bg-teal/15 text-teal font-semibold shadow-sm"
                : "border-fog-deep/50 bg-void-700/40 text-fog hover:border-paper hover:text-paper",
            )}
          >
            <Radio className="size-3 text-teal" />
            Live Telemetry (#{flowsData?.windowIndex ?? targetWindow})
          </button>
          {[
            { label: "Benign Baseline", windowIndex: 1750 },
            { label: "Port Reconnaissance", windowIndex: 1785 },
            { label: "Initial Exploitation", windowIndex: 1792 },
            { label: "Lateral SMB Pivot", windowIndex: 1796 },
            { label: "C2 Beacon Egress", windowIndex: 1805 },
          ].map((preset) => (
            <button
              key={preset.label}
              onClick={() => {
                setIsLiveMode(false);
                setTargetWindow(preset.windowIndex);
              }}
              className={cn(
                "rounded-md px-2.5 py-1 text-[11px] font-mono transition-colors border",
                !isLiveMode && targetWindow === preset.windowIndex
                  ? "border-teal/60 bg-teal/15 text-teal font-semibold shadow-sm"
                  : "border-fog-deep/50 bg-void-700/40 text-fog hover:border-paper hover:text-paper",
              )}
            >
              {preset.label} (#{preset.windowIndex})
            </button>
          ))}
        </div>
      </div>

      {/* KPI Stats Strip */}
      <div className="flat mb-6 grid gap-4 p-5 sm:grid-cols-2 lg:grid-cols-4">
        <div>
          <span className="text-[11px] font-mono uppercase tracking-wider text-fog">
            Active Flows
          </span>
          <p className="mono mt-1 text-[20px] font-bold text-paper">
            {total} <span className="text-[13px] font-normal text-fog">monitored</span>
          </p>
          <p className="mt-0.5 text-[11px] text-fog">Window #{targetWindow} concurrent sessions</p>
        </div>

        <div>
          <span className="text-[11px] font-mono uppercase tracking-wider text-fog">
            Threat Anomalies
          </span>
          <div className="mt-1 flex items-center gap-2">
            <p
              className={cn(
                "mono text-[20px] font-bold",
                summary?.threatFlows ? "text-crimson" : "text-teal",
              )}
            >
              {summary?.threatFlows ?? 0}
            </p>
            <RiskBadge state={riskState} label={activeStage} />
          </div>
          <p className="mt-0.5 text-[11px] text-fog">
            {summary?.threatFlows
              ? `${summary.threatFlows} sessions exceed anomaly threshold`
              : "All concurrent sessions within baseline"}
          </p>
        </div>

        <div>
          <span className="text-[11px] font-mono uppercase tracking-wider text-fog">
            Aggregated Volume
          </span>
          <p className="mono mt-1 text-[20px] font-bold text-paper">
            {formatBytes(summary?.totalBytes ?? 0)}
          </p>
          <p className="mt-0.5 text-[11px] text-fog">
            {(summary?.totalPackets ?? 0).toLocaleString()} packets transmitted
          </p>
        </div>

        <div>
          <span className="text-[11px] font-mono uppercase tracking-wider text-fog">
            Primary Protocol
          </span>
          <p className="mono mt-1 text-[20px] font-bold text-teal">
            {summary?.topService ?? "TCP"}
          </p>
          <p className="mt-0.5 text-[11px] text-fog">Dominant application layer service</p>
        </div>
      </div>

      {/* Interactive Filter Toolbar */}
      <div className="sticky top-14 z-10 mb-4 flex flex-wrap items-center justify-between gap-3 rounded-md border border-fog-deep/60 bg-void-800 p-3 shadow-md">
        <div className="flex flex-wrap items-center gap-2.5">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 size-3.5 -translate-y-1/2 text-fog" />
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search IP, port, service or flags..."
              className="mono w-[260px] rounded-full border border-fog-deep/80 bg-void-700 py-1.5 pl-8 pr-3 text-[12px] text-paper outline-none placeholder:text-fog focus:border-teal"
            />
          </div>

          <div className="flex items-center gap-1 rounded-full border border-fog-deep/60 bg-void-700 p-1">
            {PROTOCOL_FILTERS.map((p) => (
              <button
                key={p}
                onClick={() => setSelectedProto(p)}
                className={cn(
                  "rounded-full px-2.5 py-0.5 text-[11px] font-mono transition-colors",
                  selectedProto === p
                    ? "bg-teal text-void-900 font-semibold"
                    : "text-fog hover:text-paper",
                )}
              >
                {p}
              </button>
            ))}
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <label className="flex items-center gap-2 rounded-full border border-fog-deep/60 bg-void-700 px-3 py-1 text-[12px] text-fog">
            <span>Score &ge;</span>
            <input
              type="range"
              min={0}
              max={0.9}
              step={0.05}
              value={minScore}
              onChange={(e) => setMinScore(Number(e.target.value))}
              className="w-20 accent-teal cursor-pointer"
            />
            <span className="mono font-semibold text-paper">{minScore.toFixed(2)}</span>
          </label>

          <button
            onClick={() => setFlaggedOnly((v) => !v)}
            className={cn(
              "rounded-full border px-3 py-1 text-[12px] font-medium transition-colors",
              flaggedOnly
                ? "border-crimson/60 bg-crimson/15 text-crimson font-semibold"
                : "border-fog-deep/60 text-fog hover:text-paper",
            )}
          >
            Flagged anomalies only
          </button>

          <span className="mono text-[12px] text-fog">
            Showing {rows.length} of {total} flows
          </span>
        </div>
      </div>

      {/* Main Flow Dissector Table */}
      <FlatPanel bodyClassName="p-0 overflow-x-auto">
        <table className="w-full min-w-[1240px] text-left">
          <thead className="text-[12px] text-fog bg-void-800/80">
            <tr className="border-b border-fog-deep/60">
              <th className="w-8 px-3 py-2.5"></th>
              <th className="px-3 py-2.5 font-medium">Source (Client)</th>
              <th className="px-3 py-2.5 font-medium">Destination (Server)</th>
              <th className="px-3 py-2.5 font-medium">Proto / Service</th>
              <th className="px-3 py-2.5 font-medium">Flags</th>
              <th className="px-3 py-2.5 font-medium text-right">Volume</th>
              <th className="px-3 py-2.5 font-medium text-right">Packets</th>
              <th className="px-3 py-2.5 font-medium text-right">Duration</th>
              <th className="px-3 py-2.5 font-medium text-right">IAT Mean</th>
              <th className="px-3 py-2.5 font-medium text-right">TCP Win</th>
              <th className="px-3 py-2.5 font-medium text-right">Retrans</th>
              <th className="px-4 py-2.5 font-medium text-right">Threat Score</th>
              <th className="px-3 py-2.5 text-center font-medium">Inspection</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-fog-deep/30">
            {rows.map((f) => {
              const isOpen = openFlowId === f._id;
              const isThreat = f.score >= 0.65;
              const isWatch = f.score >= 0.4 && f.score < 0.65;
              const packets = f.packetSequence || [];
              const activePacketIdx = selectedPacketIndex[f._id] ?? 0;
              const activePacket: PacketFrame | undefined = packets[activePacketIdx] || packets[0];

              return (
                <Fragment key={f._id}>
                  <tr
                    onClick={() => setOpenFlowId(isOpen ? null : f._id)}
                    className={cn(
                      "cursor-pointer transition-colors group",
                      isOpen
                        ? "bg-void-700/60"
                        : "hover:bg-paper/4",
                      isThreat && "bg-crimson/5",
                    )}
                  >
                    <td className="px-3 py-3 text-center">
                      <span
                        className={cn(
                          "inline-block size-2 rounded-full",
                          isThreat
                            ? "bg-crimson shadow-[0_0_8px_rgba(255,75,75,0.7)]"
                            : isWatch
                            ? "bg-amber"
                            : "bg-teal",
                        )}
                      />
                    </td>
                    <td className="mono px-3 py-3 text-[13px] font-medium text-paper">
                      {f.src}
                    </td>
                    <td className="mono px-3 py-3 text-[13px] text-paper">
                      {f.dst}
                    </td>
                    <td className="px-3 py-3">
                      <div className="flex items-center gap-1.5">
                        <span className="mono text-[12px] font-semibold text-paper">
                          {f.proto}
                        </span>
                        <span className="rounded bg-void-900 border border-fog-deep/60 px-1.5 py-0.5 text-[10px] font-mono text-teal">
                          {f.service || "TCP"}
                        </span>
                      </div>
                    </td>
                    <td className="mono px-3 py-3 text-[12px] text-fog">
                      <span className="rounded bg-void-900/80 px-1.5 py-0.5 border border-fog-deep/40">
                        {f.flags}
                      </span>
                    </td>
                    <td className="mono px-3 py-3 text-right text-[13px] font-medium text-paper">
                      {formatBytes(f.bytes)}
                    </td>
                    <td className="mono px-3 py-3 text-right text-[12px] text-fog">
                      {f.packets.toLocaleString()}
                    </td>
                    <td className="mono px-3 py-3 text-right text-[12px] text-fog">
                      {f.duration.toFixed(1)}s
                    </td>
                    <td className="mono px-3 py-3 text-right text-[12px] text-fog">
                      {f.iatMean.toFixed(3)}s
                    </td>
                    <td className="mono px-3 py-3 text-right text-[12px] text-fog">
                      {f.window || "â€”"}
                    </td>
                    <td
                      className={cn(
                        "mono px-3 py-3 text-right text-[12px]",
                        f.retrans > 0 ? "text-crimson font-bold" : "text-fog",
                      )}
                    >
                      {f.retrans}
                    </td>
                    <td className="mono px-4 py-3 text-right">
                      <div className="flex items-center justify-end gap-2">
                        <div className="h-1.5 w-14 overflow-hidden rounded bg-void-900 border border-fog-deep/40">
                          <div
                            className={cn(
                              "h-full rounded",
                              isThreat
                                ? "bg-crimson"
                                : isWatch
                                ? "bg-amber"
                                : "bg-teal",
                            )}
                            style={{ width: `${Math.round(f.score * 100)}%` }}
                          />
                        </div>
                        <span
                          className={cn(
                            "min-w-[42px] font-bold text-[13px]",
                            isThreat
                              ? "text-crimson"
                              : isWatch
                              ? "text-amber"
                              : "text-teal",
                          )}
                        >
                          {(f.score * 100).toFixed(0)}%
                        </span>
                      </div>
                    </td>
                    <td className="px-3 py-3 text-center">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          setOpenFlowId(isOpen ? null : f._id);
                        }}
                        className="inline-flex items-center gap-1 rounded border border-fog-deep/60 bg-void-800 px-2 py-1 text-[11px] font-mono text-fog transition-colors hover:border-paper hover:text-paper"
                      >
                        {isOpen ? (
                          <>
                            <ChevronDown className="size-3 text-teal" />
                            Collapse
                          </>
                        ) : (
                          <>
                            <ChevronRight className="size-3" />
                            Dissect
                          </>
                        )}
                      </button>
                    </td>
                  </tr>

                  {/* Deep Packet Dissection Accordion Panel */}
                  {isOpen ? (
                    <tr className="border-b border-fog-deep/60 bg-void-900/90">
                      <td colSpan={13} className="p-5">
                        <div className="rounded-lg border border-fog-deep/60 bg-void-800/80 p-5 space-y-5">
                          {/* Flow 5-Tuple Meta Banner */}
                          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-fog-deep/40 pb-4">
                            <div className="flex items-center gap-3">
                              <div className="rounded-md border border-teal/40 bg-teal/10 p-2 text-teal">
                                <Layers className="size-5" />
                              </div>
                              <div>
                                <div className="flex items-center gap-2">
                                  <h4 className="mono text-[14px] font-bold text-paper">
                                    {f.src} &rarr; {f.dst}
                                  </h4>
                                  <span className="rounded bg-teal/15 border border-teal/40 px-2 py-0.5 text-[11px] font-mono text-teal">
                                    {f.proto} · {f.service}
                                  </span>
                                  {f.mitreTechnique ? (
                                    <span className="rounded bg-crimson/15 border border-crimson/40 px-2 py-0.5 text-[11px] font-mono text-crimson">
                                      {f.mitreTechnique}
                                    </span>
                                  ) : null}
                                </div>
                                <p className="mt-0.5 text-[12px] text-fog">
                                  Captured at {f.timestamp} · Total Payload: {formatBytes(f.bytes)} across {f.packets} packets · Duration: {f.duration}s
                                </p>
                              </div>
                            </div>

                            <div className="flex items-center gap-2">
                              <button
                                onClick={() => handleExportJSON()}
                                className="flex items-center gap-1.5 rounded border border-fog-deep/60 bg-void-700 px-2.5 py-1 text-[11px] font-mono text-fog hover:border-paper hover:text-paper transition-colors"
                              >
                                <Download className="size-3" />
                                Export Dissection
                              </button>
                            </div>
                          </div>

                          {/* Packet Sequence Timeline */}
                          <div>
                            <div className="flex items-center justify-between pb-2">
                              <span className="text-[12px] font-mono uppercase tracking-wider text-fog">
                                Packet-Level Sequence Timeline ({packets.length} frames dissected)
                              </span>
                              <span className="text-[11px] text-fog italic">
                                Select a frame to view decoded protocol stack and raw hex dump
                              </span>
                            </div>

                            <div className="overflow-x-auto rounded border border-fog-deep/50 bg-void-900">
                              <table className="w-full text-left text-[12px]">
                                <thead className="bg-void-800 text-fog text-[11px] font-mono uppercase border-b border-fog-deep/40">
                                  <tr>
                                    <th className="px-3 py-2 w-12">No.</th>
                                    <th className="px-3 py-2 w-20">Time</th>
                                    <th className="px-3 py-2 w-28">Direction</th>
                                    <th className="px-3 py-2 w-24">Protocol</th>
                                    <th className="px-3 py-2 w-24">Flags</th>
                                    <th className="px-3 py-2 w-20 text-right">Length</th>
                                    <th className="px-4 py-2">Decoded Info</th>
                                  </tr>
                                </thead>
                                <tbody className="divide-y divide-fog-deep/30 font-mono">
                                  {packets.map((pkt, idx) => {
                                    const isPktActive = activePacketIdx === idx;
                                    return (
                                      <tr
                                        key={pkt.frameNumber}
                                        onClick={() =>
                                          setSelectedPacketIndex((prev) => ({
                                            ...prev,
                                            [f._id]: idx,
                                          }))
                                        }
                                        className={cn(
                                          "cursor-pointer transition-colors",
                                          isPktActive
                                            ? "bg-teal/15 text-paper font-semibold"
                                            : "hover:bg-void-700/60 text-fog-300",
                                        )}
                                      >
                                        <td className="px-3 py-1.5 text-fog">{pkt.frameNumber}</td>
                                        <td className="px-3 py-1.5 text-teal">{pkt.timeFormatted}</td>
                                        <td className="px-3 py-1.5">
                                          {pkt.direction === "outbound" ? (
                                            <span className="text-teal">&rarr; Outbound</span>
                                          ) : (
                                            <span className="text-amber">&larr; Inbound</span>
                                          )}
                                        </td>
                                        <td className="px-3 py-1.5 text-paper">{pkt.protocol}</td>
                                        <td className="px-3 py-1.5">
                                          {pkt.flags ? (
                                            <span className="rounded bg-void-800 px-1 py-0.5 text-[10px] border border-fog-deep/40">
                                              {pkt.flags}
                                            </span>
                                          ) : (
                                            "â€”"
                                          )}
                                        </td>
                                        <td className="px-3 py-1.5 text-right">{pkt.length} B</td>
                                        <td className="px-4 py-1.5 truncate max-w-[420px] text-paper">
                                          {pkt.info}
                                        </td>
                                      </tr>
                                    );
                                  })}
                                </tbody>
                              </table>
                            </div>
                          </div>

                          {/* Selected Packet Deep Dive Inspector: Protocol Tree + Raw Hex Dump */}
                          {activePacket ? (
                            <div className="grid gap-4 lg:grid-cols-2 pt-2">
                              {/* Decoded Protocol Layers */}
                              <div className="rounded border border-fog-deep/60 bg-void-900 p-4 space-y-3">
                                <div className="flex items-center gap-2 border-b border-fog-deep/40 pb-2">
                                  <FileText className="size-4 text-teal" />
                                  <h5 className="text-[13px] font-medium text-paper">
                                    Frame #{activePacket.frameNumber} Protocol Stack &amp; Field Dissection
                                  </h5>
                                </div>
                                <div className="space-y-2 font-mono text-[12px] leading-relaxed">
                                  {activePacket.layers.map((layer, lIdx) => (
                                    <div
                                      key={lIdx}
                                      className="rounded bg-void-800/80 border border-fog-deep/30 px-3 py-2 text-paper"
                                    >
                                      <span className="text-teal font-bold mr-2">&gt;</span>
                                      {layer}
                                    </div>
                                  ))}
                                </div>
                              </div>

                              {/* Raw Monospace Hex Dump Viewer */}
                              <div className="rounded border border-fog-deep/60 bg-void-900 p-4 space-y-3">
                                <div className="flex items-center justify-between border-b border-fog-deep/40 pb-2">
                                  <div className="flex items-center gap-2">
                                    <Binary className="size-4 text-teal" />
                                    <h5 className="text-[13px] font-medium text-paper">
                                      Raw Payload Hex Dump &amp; ASCII Stream
                                    </h5>
                                  </div>
                                  <button
                                    onClick={() =>
                                      handleCopyHex(
                                        activePacket.hexDump.join("\n"),
                                        `hex-${f._id}-${activePacket.frameNumber}`,
                                      )
                                    }
                                    className="flex items-center gap-1 rounded bg-void-800 px-2 py-0.5 text-[11px] font-mono text-fog hover:text-paper border border-fog-deep/40 transition-colors"
                                  >
                                    {copiedId === `hex-${f._id}-${activePacket.frameNumber}` ? (
                                      <>
                                        <Check className="size-3 text-teal" />
                                        Copied
                                      </>
                                    ) : (
                                      <>
                                        <Copy className="size-3" />
                                        Copy Hex
                                      </>
                                    )}
                                  </button>
                                </div>

                                <div className="rounded bg-void-950 p-3 font-mono text-[11px] text-teal overflow-x-auto max-h-56 leading-tight border border-fog-deep/30">
                                  {activePacket.hexDump.map((line, hIdx) => (
                                    <pre key={hIdx} className="whitespace-pre">
                                      {line}
                                    </pre>
                                  ))}
                                </div>

                                {activePacket.payloadAscii ? (
                                  <div className="rounded bg-void-950/60 p-2 text-[11px] font-mono text-fog border border-fog-deep/30 truncate">
                                    <span className="text-paper font-semibold mr-1.5">ASCII:</span>
                                    {activePacket.payloadAscii}
                                  </div>
                                ) : null}
                              </div>
                            </div>
                          ) : null}
                        </div>
                      </td>
                    </tr>
                  ) : null}
                </Fragment>
              );
            })}
          </tbody>
        </table>

        {rows.length === 0 ? (
          <div className="px-5 py-12 text-center text-fog space-y-2">
            <Filter className="size-8 mx-auto text-fog-deep" />
            <p className="text-[15px] font-medium text-paper">No flows match the active filters</p>
            <p className="text-[12px]">
              Lower the anomaly score threshold, clear the search term, or select "ALL" protocols.
            </p>
          </div>
        ) : null}
      </FlatPanel>
    </>
  );
}
