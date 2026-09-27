import { useState, useRef, useMemo } from "react";
import { createFileRoute } from "@tanstack/react-router";
import {
  Upload,
  FileSearch,
  Play,
  CheckCircle2,
  AlertTriangle,
  ShieldAlert,
  Clock,
  Activity,
  Cpu,
  Database,
  Filter,
  ArrowRight,
  Sparkles,
  RefreshCw,
  Download,
  Layers,
  Terminal,
  Search,
  Sliders,
} from "lucide-react";
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ReferenceLine,
  CartesianGrid,
} from "recharts";
import { FlatPanel, HeroPanel, PageTitle, RiskBadge } from "@/components/app/panels";
import { pageHead } from "@/lib/head";
import { cn } from "@/lib/utils";
import {
  useAnalyzeCapture,
  useDemonstrationPresets,
  type DemonstrationAnalysisResult,
  type IFlaggedFlow,
  type IStageAnnotation,
} from "@/hooks/useApi";

export const Route = createFileRoute("/app/demonstration")({
  head: pageHead(
    "Inference Lab — Flow दृष्टि",
    "On-demand Cyber World Model demonstration interface for PCAP/CSV file upload, multi-stage infiltration timelines, flagged flows, and MITRE ATT&CK annotations.",
  ),
  component: DemonstrationPage,
});

function DemonstrationPage() {
  const [selectedPresetId, setSelectedPresetId] = useState<string>("thursday_infiltration");
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [activeAnalysis, setActiveAnalysis] = useState<DemonstrationAnalysisResult | null>(null);
  const [flowSearch, setFlowSearch] = useState("");
  const [stageFilter, setStageFilter] = useState("all");
  const [selectedFlow, setSelectedFlow] = useState<IFlaggedFlow | null>(null);

  const fileInputRef = useRef<HTMLInputElement>(null);

  const { data: presetsData, isLoading: presetsLoading } = useDemonstrationPresets();
  const analyzeMutation = useAnalyzeCapture();

  // Load default preset on mount if analysis is empty
  const presets = presetsData?.presets || [
    {
      id: "thursday_infiltration",
      name: "CSE-CIC-IDS2018 Thursday Infiltration (Gold Standard)",
      description: "Real-world multi-stage infiltration starting from perimeter reconnaissance to internal SMB lateral spread and C2 beaconing.",
      fileType: "pcap",
      duration: "120.0s (60 Windows)",
      attackOnset: "Window #1781 (Recon onset) / Window #1796 (Lateral Breach)",
      expectedStages: ["Reconnaissance", "Initial Access", "Lateral Movement", "Command & Control"],
    },
    {
      id: "recon_sweep",
      name: "Stealth Nmap Port Sweep & Brute Force Episode",
      description: "High-entropy SYN port scans targeting administrative and remote management services (Ports 445, 22, 3389).",
      fileType: "csv",
      duration: "80.0s (40 Windows)",
      attackOnset: "Window #1785 (SYN sweep surge)",
      expectedStages: ["Reconnaissance", "Initial Access"],
    },
    {
      id: "c2_beacon",
      name: "Cobalt Strike External C2 Beaconing & Exfiltration Capture",
      description: "Low-jitter periodic egress over HTTP/8080 to external command server with data volume shock.",
      fileType: "pcap",
      duration: "100.0s (50 Windows)",
      attackOnset: "Window #1804 (Beacon egress)",
      expectedStages: ["Lateral Movement", "Command & Control", "Exfiltration"],
    },
  ];

  // Initial trigger
  const runPreset = (presetId: string) => {
    setSelectedPresetId(presetId);
    setSelectedFile(null);
    analyzeMutation.mutate(
      { presetId },
      {
        onSuccess: (data) => {
          setActiveAnalysis(data);
          if (data.flaggedFlows.length > 0) {
            setSelectedFlow(data.flaggedFlows[0] ?? null);
          }
        },
      }
    );
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setSelectedFile(file);
    setSelectedPresetId("");

    analyzeMutation.mutate(
      { file },
      {
        onSuccess: (data) => {
          setActiveAnalysis(data);
          if (data.flaggedFlows.length > 0) {
            setSelectedFlow(data.flaggedFlows[0] ?? null);
          }
        },
      }
    );
  };

  const handleDrop = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    const file = e.dataTransfer.files?.[0];
    if (!file) return;
    setSelectedFile(file);
    setSelectedPresetId("");

    analyzeMutation.mutate(
      { file },
      {
        onSuccess: (data) => {
          setActiveAnalysis(data);
          if (data.flaggedFlows.length > 0) {
            setSelectedFlow(data.flaggedFlows[0] ?? null);
          }
        },
      }
    );
  };

  // Run default analysis on first render if empty
  if (!activeAnalysis && !analyzeMutation.isPending && !analyzeMutation.isError) {
    runPreset("thursday_infiltration");
  }

  // Filtered flows
  const filteredFlows = useMemo(() => {
    if (!activeAnalysis) return [];
    return activeAnalysis.flaggedFlows.filter((f) => {
      const matchesSearch =
        flowSearch === "" ||
        f.src.toLowerCase().includes(flowSearch.toLowerCase()) ||
        f.dst.toLowerCase().includes(flowSearch.toLowerCase()) ||
        f.reason.toLowerCase().includes(flowSearch.toLowerCase()) ||
        f.proto.toLowerCase().includes(flowSearch.toLowerCase()) ||
        f.techniqueId.toLowerCase().includes(flowSearch.toLowerCase());

      const matchesStage =
        stageFilter === "all" ||
        f.stage.toLowerCase() === stageFilter.toLowerCase();

      return matchesSearch && matchesStage;
    });
  }, [activeAnalysis, flowSearch, stageFilter]);

  const summary = activeAnalysis?.summary;
  const metadata = activeAnalysis?.fileMetadata;

  return (
    <div className="space-y-6 pb-12">
      {/* Top Header */}
      <PageTitle
        title="Inference Lab & Capture Demonstrator"
        note="Independent evaluation sandbox for Cyber World Model inference. Upload custom packet captures (.pcap, .pcapng) or NetFlow CSV datasets to reconstruct continuous temporal state trajectories, forecast multi-stage breach progression, and isolate anomalous forensic flows."
        actions={
          <div className="flex items-center gap-3">
            <span className="inline-flex items-center gap-1.5 rounded-full border border-teal/40 bg-teal/10 px-3 py-1 text-[12px] font-medium text-teal">
              <span className="size-1.5 rounded-full bg-teal shadow-[0_0_8px_1px_rgba(20,184,166,0.6)]" />
              Independent Sandbox Active
            </span>
            {activeAnalysis && (
              <button
                onClick={() => {
                  const blob = new Blob([JSON.stringify(activeAnalysis, null, 2)], {
                    type: "application/json",
                  });
                  const url = URL.createObjectURL(blob);
                  const a = document.createElement("a");
                  a.href = url;
                  a.download = `aegis_inference_${activeAnalysis.fileMetadata.filename.replace(/[^a-z0-9]/gi, "_")}.json`;
                  a.click();
                }}
                className="flex items-center gap-2 rounded-lg border border-fog-deep/60 bg-void-800/90 px-3 py-1.5 text-[12px] font-medium text-paper transition-colors hover:border-teal/50 hover:bg-void-700"
              >
                <Download className="size-3.5 text-fog" />
                Export Telemetry JSON
              </button>
            )}
          </div>
        }
      />

      {/* Input Section: 1-Click Judge Presets & File Upload Dropzone */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
        {/* Presets Cards (7 cols) */}
        <div className="space-y-3 lg:col-span-7">
          <div className="flex items-center justify-between">
            <h3 className="text-[13px] font-semibold tracking-wider text-fog uppercase">
              1-Click Benchmark Presets (Evaluation Mode)
            </h3>
            <span className="text-[11px] text-fog/70">Instant microservice evaluation</span>
          </div>

          <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
            {presets.map((preset) => {
              const isActive = selectedPresetId === preset.id && !selectedFile;
              return (
                <button
                  key={preset.id}
                  onClick={() => runPreset(preset.id)}
                  disabled={analyzeMutation.isPending}
                  className={cn(
                    "flex flex-col justify-between rounded-xl border p-3.5 text-left transition-all",
                    isActive
                      ? "border-teal bg-teal/10 shadow-[0_0_18px_rgba(20,184,166,0.15)]"
                      : "border-fog-deep/40 bg-void-800/60 hover:border-fog-deep/80 hover:bg-void-800/90"
                  )}
                >
                  <div className="space-y-1.5">
                    <div className="flex items-center justify-between">
                      <span className="mono rounded border border-fog-deep/60 bg-void-900 px-1.5 py-0.5 text-[10px] font-medium text-fog uppercase">
                        {preset.fileType}
                      </span>
                      {isActive ? (
                        <CheckCircle2 className="size-4 text-teal" />
                      ) : (
                        <Play className="size-3.5 text-fog/50" />
                      )}
                    </div>
                    <p className="font-display text-[13px] font-semibold text-paper line-clamp-2">
                      {preset.name}
                    </p>
                    <p className="text-[11px] text-fog/80 line-clamp-2 leading-relaxed">
                      {preset.description}
                    </p>
                  </div>

                  <div className="mt-3 flex items-center justify-between border-t border-fog-deep/30 pt-2 text-[10px] text-fog">
                    <span className="mono">{preset.duration}</span>
                    <span className="text-teal font-medium">Run Pass →</span>
                  </div>
                </button>
              );
            })}
          </div>
        </div>

        {/* Upload Dropzone (5 cols) */}
        <div className="space-y-3 lg:col-span-5">
          <div className="flex items-center justify-between">
            <h3 className="text-[13px] font-semibold tracking-wider text-fog uppercase">
              Upload Custom Capture File
            </h3>
            <span className="text-[11px] text-fog/70">.PCAP, .PCAPNG, or .CSV (max 30MB)</span>
          </div>

          <div
            onDragOver={(e) => e.preventDefault()}
            onDrop={handleDrop}
            onClick={() => fileInputRef.current?.click()}
            className={cn(
              "group relative flex min-h-[148px] cursor-pointer flex-col items-center justify-center rounded-xl border-2 border-dashed p-4 text-center transition-all",
              selectedFile
                ? "border-teal/80 bg-teal/5"
                : "border-fog-deep/60 bg-void-800/40 hover:border-teal/50 hover:bg-void-800/70"
            )}
          >
            <input
              ref={fileInputRef}
              type="file"
              accept=".pcap,.pcapng,.csv"
              onChange={handleFileUpload}
              className="hidden"
            />

            <div className="flex size-10 items-center justify-center rounded-full bg-void-700/80 text-fog transition-colors group-hover:bg-teal/20 group-hover:text-teal">
              <Upload className="size-5" />
            </div>

            {selectedFile ? (
              <div className="mt-2 text-center">
                <p className="font-display text-[13px] font-semibold text-paper">
                  {selectedFile.name}
                </p>
                <p className="mono text-[11px] text-teal">
                  {(selectedFile.size / 1024).toFixed(1)} KB â€¢ Loaded & Processed
                </p>
              </div>
            ) : (
              <div className="mt-2 text-center">
                <p className="text-[13px] font-medium text-paper">
                  Drag & drop capture file here, or <span className="text-teal underline">browse</span>
                </p>
                <p className="mt-0.5 text-[11px] text-fog">
                  Automatically extracts IPv4/TCP headers, entropy & window features
                </p>
              </div>
            )}

            {analyzeMutation.isPending && (
              <div className="absolute inset-0 flex items-center justify-center rounded-xl bg-void-900/85 backdrop-blur-sm">
                <div className="flex items-center gap-2 text-[13px] font-medium text-teal">
                  <RefreshCw className="size-4 animate-spin" />
                  Running World Model Forward Pass...
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Main Analysis Display */}
      {activeAnalysis && summary && metadata && (
        <div className="space-y-6">
          {/* File Metadata & Executive Metrics Strip */}
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
            {/* Peak Probability */}
            <div className="rounded-xl border border-fog-deep/40 bg-void-800/70 p-3.5">
              <span className="text-[11px] font-medium text-fog uppercase">Peak Infiltration Prob</span>
              <div className="mt-1 flex items-baseline gap-2">
                <span
                  className={cn(
                    "font-display text-[26px] font-bold tracking-tight",
                    summary.peakProbability >= 0.8
                      ? "text-crimson"
                      : summary.peakProbability >= 0.5
                      ? "text-amber-400"
                      : "text-teal"
                  )}
                >
                  {summary.peakProbabilityPct}
                </span>
                <span className="text-[11px] text-fog">
                  {summary.overallRiskLevel.toUpperCase()}
                </span>
              </div>
              <div className="mt-2 h-1.5 w-full overflow-hidden rounded-full bg-void-900">
                <div
                  className={cn(
                    "h-full rounded-full transition-all duration-500",
                    summary.peakProbability >= 0.8
                      ? "bg-crimson"
                      : summary.peakProbability >= 0.5
                      ? "bg-amber-400"
                      : "bg-teal"
                  )}
                  style={{ width: `${Math.min(100, summary.peakProbability * 100)}%` }}
                />
              </div>
            </div>

            {/* Dominant Attack Stage */}
            <div className="rounded-xl border border-fog-deep/40 bg-void-800/70 p-3.5">
              <span className="text-[11px] font-medium text-fog uppercase">Dominant Stage</span>
              <div className="mt-1 font-display text-[20px] font-semibold text-paper truncate">
                {summary.dominantStage}
              </div>
              <p className="mt-2 flex items-center gap-1.5 text-[11px] text-fog">
                <Layers className="size-3 text-teal" />
                MITRE Stage Trajectory
              </p>
            </div>

            {/* Model Confidence */}
            <div className="rounded-xl border border-fog-deep/40 bg-void-800/70 p-3.5">
              <span className="text-[11px] font-medium text-fog uppercase">Model Confidence</span>
              <div className="mt-1 font-display text-[26px] font-bold text-teal">
                {summary.modelConfidence}
              </div>
              <p className="mt-2 flex items-center gap-1.5 text-[11px] text-fog">
                <Sparkles className="size-3 text-teal" />
                SparseRSSM + TFCNet
              </p>
            </div>

            {/* Early Warning Lead Time */}
            <div className="rounded-xl border border-fog-deep/40 bg-void-800/70 p-3.5">
              <span className="text-[11px] font-medium text-fog uppercase">Early Warning Lead</span>
              <div className="mt-1 flex items-baseline gap-1 font-display text-[26px] font-bold text-teal">
                +{summary.earlyWarningLeadTimeSeconds.toFixed(1)}
                <span className="text-[14px] font-normal text-fog">s</span>
              </div>
              <p className="mt-2 flex items-center gap-1.5 text-[11px] text-fog">
                <Clock className="size-3 text-teal" />
                Onset lead advantage
              </p>
            </div>

            {/* Monitored Windows */}
            <div className="rounded-xl border border-fog-deep/40 bg-void-800/70 p-3.5">
              <span className="text-[11px] font-medium text-fog uppercase">Analyzed Windows</span>
              <div className="mt-1 font-display text-[26px] font-bold text-paper">
                {metadata.analyzedWindowsCount}
              </div>
              <p className="mt-2 mono text-[11px] text-fog">
                {metadata.durationSeconds.toFixed(0)}s temporal span
              </p>
            </div>

            {/* Flagged Flows Count */}
            <div className="rounded-xl border border-fog-deep/40 bg-void-800/70 p-3.5">
              <span className="text-[11px] font-medium text-fog uppercase">Flagged Flows</span>
              <div className="mt-1 font-display text-[26px] font-bold text-amber-400">
                {summary.flaggedFlowsCount}
              </div>
              <p className="mt-2 text-[11px] text-fog">
                {summary.anomalousHostsCount} suspect IPs identified
              </p>
            </div>
          </div>

          {/* Infiltration Probability Timeline Chart */}
          <HeroPanel
            title="Infiltration Probability Timeline & Temporal Trajectory"
            state={summary.overallRiskLevel}
            control={
              <div className="flex items-center gap-3 text-[11px]">
                <div className="flex items-center gap-1.5">
                  <span className="size-2 rounded-full bg-teal" />
                  <span className="text-fog">Baseline Normal (&lt;0.45)</span>
                </div>
                <div className="flex items-center gap-1.5">
                  <span className="size-2 rounded-full bg-amber-400" />
                  <span className="text-fog">Observation Watch (0.45 - 0.65)</span>
                </div>
                <div className="flex items-center gap-1.5">
                  <span className="size-2 rounded-full bg-crimson" />
                  <span className="text-fog">SOC Breach Escalation (&gt;0.65)</span>
                </div>
              </div>
            }
          >
            <div className="h-[280px] w-full">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart
                  data={activeAnalysis.timeline}
                  margin={{ top: 10, right: 10, left: -20, bottom: 0 }}
                >
                  <defs>
                    <linearGradient id="probGradient" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor={summary.peakProbability >= 0.75 ? "#ef4444" : "#14b8a6"} stopOpacity={0.4} />
                      <stop offset="95%" stopColor={summary.peakProbability >= 0.75 ? "#ef4444" : "#14b8a6"} stopOpacity={0.0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#262626" vertical={false} />
                  <XAxis
                    dataKey="timeOffset"
                    stroke="#737373"
                    fontSize={11}
                    tickLine={false}
                  />
                  <YAxis
                    stroke="#737373"
                    fontSize={11}
                    domain={[0, 1]}
                    ticks={[0, 0.25, 0.5, 0.65, 0.85, 1.0]}
                    tickFormatter={(v) => `${Math.round(v * 100)}%`}
                    tickLine={false}
                  />
                  <Tooltip
                    content={({ active, payload }) => {
                      if (!active || !payload?.length) return null;
                      const pt = payload[0]?.payload;
                      if (!pt) return null;
                      return (
                        <div className="rounded-lg border border-fog-deep/80 bg-void-900/95 p-3 shadow-xl backdrop-blur-md">
                          <div className="flex items-center justify-between gap-4 border-b border-fog-deep/40 pb-1.5">
                            <span className="mono text-[11px] font-semibold text-paper">
                              Window #{pt.windowIndex} ({pt.timeOffset})
                            </span>
                            <RiskBadge state={pt.riskLevel} />
                          </div>
                          <div className="mt-2 space-y-1 text-[11px]">
                            <div className="flex justify-between gap-4">
                              <span className="text-fog">Infiltration Prob:</span>
                              <span className="mono font-bold text-teal">{pt.calibratedProbPct}</span>
                            </div>
                            <div className="flex justify-between gap-4">
                              <span className="text-fog">Stage Attribution:</span>
                              <span className="font-semibold text-paper">{pt.stage}</span>
                            </div>
                            <div className="flex justify-between gap-4">
                              <span className="text-fog">Flows / Window:</span>
                              <span className="mono text-paper">{pt.flowCount} flows</span>
                            </div>
                            <div className="flex justify-between gap-4">
                              <span className="text-fog">Port Entropy:</span>
                              <span className="mono text-paper">{pt.portEntropy}</span>
                            </div>
                            <div className="flex justify-between gap-4">
                              <span className="text-fog">Byte Throughput:</span>
                              <span className="mono text-paper">{(pt.byteRate / 1024).toFixed(1)} KB/s</span>
                            </div>
                          </div>
                        </div>
                      );
                    }}
                  />
                  <ReferenceLine
                    y={0.65}
                    stroke="#f59e0b"
                    strokeDasharray="4 4"
                    label={{
                      value: "SOC Escalation Gate (65%)",
                      fill: "#f59e0b",
                      fontSize: 10,
                      position: "insideTopRight",
                    }}
                  />
                  <Area
                    type="monotone"
                    dataKey="probability"
                    stroke={summary.peakProbability >= 0.75 ? "#ef4444" : "#14b8a6"}
                    strokeWidth={2.5}
                    fillOpacity={1}
                    fill="url(#probGradient)"
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </HeroPanel>

          {/* MITRE ATT&CK Stage Annotations Sequence */}
          <FlatPanel
            title="MITRE ATT&CK Stage Annotations & Behavioral Breakdown"
            control={
              <span className="mono text-[11px] text-fog">
                {activeAnalysis.stageAnnotations.length} Attack Progression Phases
              </span>
            }
          >
            <div className="grid grid-cols-1 gap-4 lg:grid-cols-4">
              {activeAnalysis.stageAnnotations.map((stage, idx) => (
                <div
                  key={stage.id}
                  className="flex flex-col justify-between rounded-xl border border-fog-deep/40 bg-void-800/40 p-4 transition-colors hover:border-fog-deep/80 hover:bg-void-800/70"
                >
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <span
                        className="rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider"
                        style={{
                          color: stage.color,
                          backgroundColor: `${stage.color}15`,
                          border: `1px solid ${stage.color}40`,
                        }}
                      >
                        Phase {idx + 1}: {stage.stage}
                      </span>
                      <span className="mono text-[11px] text-fog">
                        {stage.startOffset} → {stage.endOffset}
                      </span>
                    </div>

                    <h4 className="font-display text-[14px] font-semibold text-paper">
                      {stage.label}
                    </h4>

                    <div className="flex items-center gap-2">
                      <span className="mono rounded bg-void-900 px-1.5 py-0.5 text-[10px] font-medium text-fog">
                        {stage.techniqueId}
                      </span>
                      <span className="text-[11px] font-medium text-fog truncate">
                        {stage.techniqueName}
                      </span>
                    </div>

                    <p className="text-[11px] text-fog/90 leading-relaxed">
                      {stage.description}
                    </p>
                  </div>

                  <div className="mt-3 border-t border-fog-deep/30 pt-2.5">
                    <span className="text-[10px] font-medium uppercase tracking-wider text-teal">
                      SOC Mitigation Recommendation:
                    </span>
                    <p className="mt-0.5 text-[11px] text-paper/90">
                      {stage.mitigation}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          </FlatPanel>

          {/* Flagged Forensic Flows Grid & Detail Inspector */}
          <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
            {/* Flows Table (8 cols) */}
            <div className="lg:col-span-8">
              <FlatPanel
                title="Forensic Flagged Flows & Packet Evidence"
                control={
                  <div className="flex flex-wrap items-center gap-2">
                    <div className="relative">
                      <Search className="absolute left-2.5 top-2 size-3.5 text-fog" />
                      <input
                        type="text"
                        placeholder="Search IP, port, technique..."
                        value={flowSearch}
                        onChange={(e) => setFlowSearch(e.target.value)}
                        className="h-7 rounded-lg border border-fog-deep/50 bg-void-900 pl-8 pr-3 text-[11px] text-paper placeholder-fog focus:border-teal focus:outline-none"
                      />
                    </div>
                    <select
                      value={stageFilter}
                      onChange={(e) => setStageFilter(e.target.value)}
                      className="h-7 rounded-lg border border-fog-deep/50 bg-void-900 px-2 text-[11px] text-paper focus:border-teal focus:outline-none"
                    >
                      <option value="all">All Stages</option>
                      <option value="Recon">Reconnaissance</option>
                      <option value="Initial Access">Initial Access</option>
                      <option value="Lateral Movement">Lateral Movement</option>
                      <option value="C2">Command & Control</option>
                      <option value="Exfiltration">Exfiltration</option>
                    </select>
                  </div>
                }
              >
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-[12px]">
                    <thead>
                      <tr className="border-b border-fog-deep/40 text-[11px] text-fog uppercase">
                        <th className="pb-2 font-medium">Flow Target</th>
                        <th className="pb-2 font-medium">Proto / Flags</th>
                        <th className="pb-2 font-medium">Bytes / Pkts</th>
                        <th className="pb-2 font-medium">Risk Score</th>
                        <th className="pb-2 font-medium">Stage</th>
                        <th className="pb-2 font-medium text-right">Action</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-fog-deep/20 font-mono">
                      {filteredFlows.length === 0 ? (
                        <tr>
                          <td colSpan={6} className="py-6 text-center text-fog font-sans">
                            No flagged flows match the filter criteria.
                          </td>
                        </tr>
                      ) : (
                        filteredFlows.map((flow) => {
                          const isSelected = selectedFlow?.id === flow.id;
                          return (
                            <tr
                              key={flow.id}
                              onClick={() => setSelectedFlow(flow)}
                              className={cn(
                                "cursor-pointer transition-colors hover:bg-void-700/50",
                                isSelected && "bg-teal/10"
                              )}
                            >
                              <td className="py-2.5">
                                <div className="text-[12px] font-medium text-paper">
                                  {flow.src} → {flow.dst}
                                </div>
                                <span className="text-[10px] text-fog">{flow.timestamp}</span>
                              </td>
                              <td className="py-2.5">
                                <span className="rounded bg-void-900 px-1.5 py-0.5 text-[10px] text-fog">
                                  {flow.proto}
                                </span>
                                <span className="ml-1.5 text-[11px] text-fog">{flow.flags}</span>
                              </td>
                              <td className="py-2.5 text-[11px] text-fog">
                                {(flow.bytes / 1024).toFixed(1)} KB ({flow.packets} pkts)
                              </td>
                              <td className="py-2.5">
                                <span
                                  className={cn(
                                    "rounded px-2 py-0.5 text-[11px] font-bold",
                                    flow.score >= 0.8
                                      ? "bg-crimson/15 text-crimson"
                                      : flow.score >= 0.5
                                      ? "bg-amber-400/15 text-amber-400"
                                      : "bg-teal/15 text-teal"
                                  )}
                                >
                                  {(flow.score * 100).toFixed(0)}%
                                </span>
                              </td>
                              <td className="py-2.5 font-sans">
                                <span className="rounded-full border border-fog-deep/40 bg-void-900 px-2 py-0.5 text-[10px] text-paper">
                                  {flow.stage}
                                </span>
                              </td>
                              <td className="py-2.5 text-right font-sans">
                                <button
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    setSelectedFlow(flow);
                                  }}
                                  className="text-[11px] text-teal hover:underline"
                                >
                                  Inspect →
                                </button>
                              </td>
                            </tr>
                          );
                        })
                      )}
                    </tbody>
                  </table>
                </div>
              </FlatPanel>
            </div>

            {/* Flow Detail Inspector (4 cols) */}
            <div className="lg:col-span-4">
              <FlatPanel
                title="Forensic Anomaly Inspector"
                control={
                  selectedFlow && (
                    <span className="mono text-[10px] text-fog">{selectedFlow.id}</span>
                  )
                }
              >
                {selectedFlow ? (
                  <div className="space-y-4">
                    <div className="rounded-lg border border-fog-deep/40 bg-void-900/80 p-3">
                      <div className="flex items-center justify-between">
                        <span className="text-[10px] font-medium text-fog uppercase">
                          Anomaly Risk Score
                        </span>
                        <RiskBadge
                          state={
                            selectedFlow.score >= 0.8
                              ? "critical"
                              : selectedFlow.score >= 0.5
                              ? "watch"
                              : "normal"
                          }
                        />
                      </div>
                      <div className="mt-1 font-display text-[24px] font-bold text-paper">
                        {(selectedFlow.score * 100).toFixed(1)}% Suspicion
                      </div>
                    </div>

                    <div className="space-y-2.5 text-[12px]">
                      <div>
                        <span className="text-[11px] text-fog">Source Endpoint:</span>
                        <div className="mono font-semibold text-paper">{selectedFlow.src}</div>
                      </div>
                      <div>
                        <span className="text-[11px] text-fog">Destination Endpoint:</span>
                        <div className="mono font-semibold text-paper">{selectedFlow.dst}</div>
                      </div>
                      <div className="grid grid-cols-2 gap-2">
                        <div>
                          <span className="text-[11px] text-fog">Protocol:</span>
                          <div className="mono font-semibold text-paper">{selectedFlow.proto}</div>
                        </div>
                        <div>
                          <span className="text-[11px] text-fog">Flags:</span>
                          <div className="mono font-semibold text-paper">{selectedFlow.flags}</div>
                        </div>
                      </div>
                      <div className="grid grid-cols-2 gap-2">
                        <div>
                          <span className="text-[11px] text-fog">Payload Volume:</span>
                          <div className="mono font-semibold text-paper">
                            {(selectedFlow.bytes / 1024).toFixed(2)} KB
                          </div>
                        </div>
                        <div>
                          <span className="text-[11px] text-fog">Duration:</span>
                          <div className="mono font-semibold text-paper">
                            {selectedFlow.duration.toFixed(3)}s
                          </div>
                        </div>
                      </div>
                    </div>

                    <div className="rounded-lg border border-fog-deep/40 bg-void-900/60 p-3 space-y-1.5">
                      <div className="flex items-center gap-1.5 text-[11px] font-semibold text-amber-400">
                        <AlertTriangle className="size-3.5" />
                        Attribution Reason
                      </div>
                      <p className="text-[11px] text-fog/90 leading-relaxed">
                        {selectedFlow.reason}
                      </p>
                    </div>

                    <div className="rounded-lg border border-teal/30 bg-teal/5 p-3 space-y-1.5">
                      <div className="flex items-center gap-1.5 text-[11px] font-semibold text-teal">
                        <ShieldAlert className="size-3.5" />
                        Technique ID: {selectedFlow.techniqueId}
                      </div>
                      <p className="text-[11px] text-fog/90">
                        Mapped directly to MITRE ATT&CK matrix for automated perimeter containment and dynamic firewall filtering.
                      </p>
                    </div>
                  </div>
                ) : (
                  <div className="flex flex-col items-center justify-center py-12 text-center text-fog">
                    <FileSearch className="size-8 text-fog/40 mb-2" />
                    <p className="text-[13px]">Select a flow from the table to inspect details.</p>
                  </div>
                )}
              </FlatPanel>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
