import { useState, useMemo, useEffect } from "react";
import { createFileRoute, Link } from "@tanstack/react-router";
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  BrainCircuit,
  CheckCircle2,
  Clock,
  Cpu,
  Database,
  Eye,
  Filter,
  Info,
  Layers,
  Radio,
  RefreshCw,
  Search,
  ShieldAlert,
  Sliders,
  Sparkles,
} from "lucide-react";
import { FlatPanel, HeroPanel, PageTitle, RiskBadge } from "@/components/app/panels";
import { pageHead } from "@/lib/head";
import { cn } from "@/lib/utils";
import { useExplainability } from "@/hooks/useApi";
import { subscribeDashboardStream } from "@/api/dashboardApi";

export const Route = createFileRoute("/app/explainability")({
  head: pageHead(
    "Explainability — Aegis Vantage",
    "Feature contributions, raw values and a plain-language summary behind a single prediction.",
  ),
  component: ExplainabilityPage,
});

function ExplainabilityPage() {
  const [targetWindow, setTargetWindow] = useState<number>(1796);
  const [selectedCategory, setSelectedCategory] = useState<string>("all");
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [isLiveMode, setIsLiveMode] = useState<boolean>(true);

  // Subscribe to real-time simulation/dashboard stream
  useEffect(() => {
    const unsubscribe = subscribeDashboardStream((state) => {
      if (isLiveMode) {
        setTargetWindow(state.actual_window_index);
      }
    });
    return () => unsubscribe();
  }, [isLiveMode]);

  const { data: explainData, isLoading, refetch } = useExplainability({
    windowIndex: isLiveMode ? undefined : targetWindow,
    live: isLiveMode,
  });

  // Keep targetWindow synced when live explainData returns
  useEffect(() => {
    if (isLiveMode && explainData?.windowIndex !== undefined) {
      setTargetWindow(explainData.windowIndex);
    }
  }, [isLiveMode, explainData?.windowIndex]);

  const contributions = explainData?.featureContributions || [];
  const maxWeight = useMemo(() => {
    if (contributions.length === 0) return 1;
    return Math.max(...contributions.map((f) => Math.abs(f.weight)), 0.01);
  }, [contributions]);

  const categories = explainData?.featureCategories || [];

  // Filter raw metrics based on category and search query
  const filteredMetrics = useMemo(() => {
    let result: Array<{
      categoryName: string;
      key: string;
      label: string;
      value: number;
      formattedValue: string;
      unit: string;
      isAnomaly: boolean;
      anomalyDirection?: "elevated" | "depressed";
      attributionWeight?: number;
    }> = [];

    for (const cat of categories) {
      if (selectedCategory !== "all" && cat.id !== selectedCategory) continue;
      for (const feat of cat.features) {
        if (
          searchQuery &&
          !feat.label.toLowerCase().includes(searchQuery.toLowerCase()) &&
          !feat.key.toLowerCase().includes(searchQuery.toLowerCase())
        ) {
          continue;
        }
        result.push({
          categoryName: cat.name,
          ...feat,
        });
      }
    }
    return result;
  }, [categories, selectedCategory, searchQuery]);

  const scrubPct = useMemo(() => {
    if (!explainData?.timelineBounds) return 77;
    const { min, max, current } = explainData.timelineBounds;
    return Math.round(((current - min) / (max - min)) * 100);
  }, [explainData]);

  const prob = explainData?.probability ?? 0.88;
  const probFormatted = (prob * 100).toFixed(1);
  const riskState = explainData?.riskState ?? "critical";

  return (
    <>
      <PageTitle
        title="Predictive explainability"
        note="SparseRSSM + TFCNet ensemble feature attributions, SHAP divergence, and cyber causality reasoning."
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
                Forensic review (paused) — Track Live Stream &rarr;
              </button>
            )}
            <button
              onClick={() => refetch()}
              className="flex items-center gap-1.5 rounded-md border border-fog-deep/60 px-3 py-1.5 text-[12px] font-medium text-fog transition-colors hover:border-paper hover:text-paper"
            >
              <RefreshCw className={cn("size-3.5", isLoading && "animate-spin")} />
              Refresh attribution
            </button>
          </div>
        }
      />

      {/* Top Telemetry & MITRE Metadata Banner */}
      <div className="flat mb-6 grid gap-4 p-5 sm:grid-cols-2 lg:grid-cols-5">
        <div>
          <span className="text-[11px] font-mono uppercase tracking-wider text-fog">
            Telemetry Window
          </span>
          <p className="mono mt-1 text-[15px] font-semibold text-paper">
            Window #{explainData?.windowIndex ?? targetWindow}
          </p>
          <p className="mt-0.5 text-[11px] text-fog">
            {explainData?.timestampStart ? `${explainData.timestampStart} UTC` : "2018-03-01 01:59:50"}
          </p>
        </div>

        <div>
          <span className="text-[11px] font-mono uppercase tracking-wider text-fog">
            MITRE ATT&CK Stage
          </span>
          <div className="mt-1.5 flex items-center gap-2">
            <RiskBadge
              state={riskState}
              label={explainData?.stage ?? "Lateral Movement"}
            />
          </div>
          <p className="mt-1 text-[11px] text-fog">
            {explainData?.mitre.techniqueId
              ? `${explainData.mitre.techniqueId}: ${explainData.mitre.techniqueName}`
              : "T1021.002: SMB Admin Shares"}
          </p>
        </div>

        <div>
          <span className="text-[11px] font-mono uppercase tracking-wider text-fog">
            Calibrated Probability
          </span>
          <p
            className={cn(
              "font-display text-[26px] leading-none font-bold mt-1",
              riskState === "critical"
                ? "text-crimson"
                : riskState === "watch"
                ? "text-amber"
                : "text-teal",
            )}
          >
            {probFormatted}%
          </p>
          <p className="mt-1 text-[11px] text-fog">
            Confidence: {explainData ? `${(explainData.confidence * 100).toFixed(1)}%` : "94.2%"}
          </p>
        </div>

        <div>
          <span className="text-[11px] font-mono uppercase tracking-wider text-fog">
            Forecast Lead Time
          </span>
          <div className="mt-1 flex items-center gap-1.5">
            <Clock className="size-4 text-teal" />
            <p className="mono text-[18px] font-semibold text-paper">
              +{explainData?.leadTimeSeconds ?? 20.0}s
            </p>
          </div>
          <p className="mt-0.5 text-[11px] text-fog">pre-compromise warning</p>
        </div>

        <div>
          <span className="text-[11px] font-mono uppercase tracking-wider text-fog">
            Ensemble Engine
          </span>
          <p className="mono mt-1 text-[13px] font-medium text-paper">
            SparseRSSM + TFCNet
          </p>
          <p className="mt-0.5 text-[11px] text-teal">
            54-D world model fused
          </p>
        </div>
      </div>

      {/* Interactive Timeline Scrubber & Phase Presets */}
      <div className="flat mb-6 p-4">
        <div className="flex flex-wrap items-center justify-between gap-2 pb-3">
          <div className="flex items-center gap-2">
            <Sliders className="size-4 text-teal" />
            <span className="text-[13px] font-medium text-paper">
              Timeline Scrubber &amp; Scenario Bookmarks
            </span>
          </div>
          <span className="mono text-[12px] text-fog">
            {isLiveMode
              ? `Live Tracking: Window #${explainData?.windowIndex ?? targetWindow}`
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
            Live Telemetry (#{explainData?.windowIndex ?? targetWindow})
          </button>
          {(
            explainData?.presets || [
              { label: "Benign Baseline", windowIndex: 1750, stage: "Normal" },
              { label: "Port Reconnaissance", windowIndex: 1785, stage: "Recon" },
              { label: "Initial Exploitation", windowIndex: 1792, stage: "Initial Access" },
              { label: "Lateral SMB Pivot", windowIndex: 1796, stage: "Lateral Movement" },
              { label: "C2 Beacon Egress", windowIndex: 1805, stage: "C2" },
            ]
          ).map((preset) => (
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

      {/* Main Grid: Feature Contributions + AI Forensic Summary */}
      <div className="grid gap-6 lg:grid-cols-[1.2fr_0.8fr]">
        {/* SHAP Feature Contribution Waterfall */}
        <HeroPanel
          title="Feature contributions & SHAP divergence"
          state={riskState}
          control={
            <span className="mono text-fog text-[12px]">
              window #{targetWindow} · {contributions.length} driving indicators
            </span>
          }
        >
          <div className="space-y-4">
            {contributions.map((f) => {
              const pct = (Math.abs(f.weight) / maxWeight) * 100;
              const positive = f.weight > 0;
              return (
                <div key={f.feature} className="space-y-1">
                  <div className="flex items-center justify-between text-[13px]">
                    <div className="flex items-center gap-2">
                      <span className="font-medium text-paper">{f.label}</span>
                      <span className="mono text-[11px] text-fog">({f.feature})</span>
                    </div>
                    <div className="flex items-center gap-3">
                      <span className="mono text-[12px] text-fog-400">
                        val: <strong className="text-paper">{f.value}</strong>
                      </span>
                      <span
                        className={cn(
                          "mono font-semibold text-[13px] min-w-[54px] text-right",
                          positive ? "text-crimson" : "text-teal",
                        )}
                      >
                        {positive ? "+" : ""}
                        {f.weight.toFixed(2)}
                      </span>
                    </div>
                  </div>

                  {/* Relative contribution bar */}
                  <div className="relative flex h-2.5 w-full items-center overflow-hidden rounded bg-void-900 border border-fog-deep/40">
                    <div
                      className="h-full rounded transition-all duration-300"
                      style={{
                        width: `${Math.max(4, pct)}%`,
                        background: positive
                          ? "var(--critical-crimson)"
                          : "var(--signal-teal)",
                        opacity: 0.9,
                      }}
                    />
                  </div>

                  <p className="text-[11px] text-fog/80 italic">{f.description}</p>
                </div>
              );
            })}
          </div>

          <div className="mt-6 flex flex-wrap items-center justify-between gap-3 border-t border-fog-deep/40 pt-4 text-[12px] text-fog">
            <div className="flex items-center gap-4">
              <span className="flex items-center gap-1.5">
                <span className="size-2.5 rounded bg-crimson" />
                <span>Crimson: Elevates intrusion likelihood</span>
              </span>
              <span className="flex items-center gap-1.5">
                <span className="size-2.5 rounded bg-teal" />
                <span>Teal: Mitigating / baseline normalizing</span>
              </span>
            </div>
            <span className="mono text-[11px]">Normalized L1 divergence</span>
          </div>
        </HeroPanel>

        {/* AI Cyber Causality & Forensic Explanation */}
        <div className="space-y-6">
          <FlatPanel title="Causality & Plain-Language Summary">
            <div className="space-y-4 text-[14px] leading-relaxed">
              <div className="flex items-start gap-2.5 rounded-md border border-fog-deep/50 bg-void-700/50 p-3.5">
                <BrainCircuit className="size-5 shrink-0 text-teal mt-0.5" />
                <div>
                  <p className="font-semibold text-paper text-[13px]">
                    Ensemble Cyber Reasoning
                  </p>
                  <p className="mt-1 text-fog text-[13px]">
                    {explainData?.summary ||
                      "Telemetry displays standard enterprise background traffic. Port distribution and TCP handshake completion ratios remain within nominal operating bounds."}
                  </p>
                </div>
              </div>

              {explainData?.reason && (
                <div>
                  <p className="font-medium text-paper text-[13px]">Forensic Trigger:</p>
                  <p className="mt-1 text-fog text-[13px] bg-paper/5 p-2.5 rounded mono">
                    {explainData.reason}
                  </p>
                </div>
              )}

              {explainData?.mitre.techniqueId && (
                <div className="border-t border-fog-deep/40 pt-3">
                  <p className="font-medium text-paper text-[13px]">
                    Associated MITRE ATT&CK Technique
                  </p>
                  <div className="mt-2 flex items-center justify-between rounded bg-void-900 border border-fog-deep/50 p-2.5">
                    <div>
                      <p className="mono font-semibold text-teal text-[13px]">
                        {explainData.mitre.techniqueId}
                      </p>
                      <p className="text-[12px] text-fog">
                        {explainData.mitre.techniqueName}
                      </p>
                    </div>
                    <span className="mono text-[11px] text-amber">
                      Tactic: {explainData.mitre.tactic}
                    </span>
                  </div>
                </div>
              )}

              <div className="border-t border-fog-deep/40 pt-3 text-[12px] text-fog">
                <p className="font-medium text-paper">SOC Action Recommendation:</p>
                <p className="mt-1">
                  {riskState === "critical"
                    ? "Isolate endpoint 192.168.10.44 via network ACL. Terminate suspicious SMB sessions on port 445 and dump memory for LSASS credential scraping."
                    : riskState === "watch"
                    ? "Increase flow sampling frequency on perimeter gateway 192.168.10.1. Monitor workstation 192.168.10.44 for port-sweep follow-ups."
                    : "No immediate containment required. Baseline telemetry falls inside acceptable tolerance margins."}
                </p>
              </div>
            </div>
          </FlatPanel>

          {/* Model Ensemble Specification Card */}
          <FlatPanel title="Ensemble Architecture Attribution">
            <dl className="space-y-2.5 text-[12px]">
              <div className="flex justify-between border-b border-fog-deep/30 pb-1.5">
                <dt className="text-fog">World Model</dt>
                <dd className="mono text-paper">SparseRSSM (Temporal State-Space)</dd>
              </div>
              <div className="flex justify-between border-b border-fog-deep/30 pb-1.5">
                <dt className="text-fog">Spectral Model</dt>
                <dd className="mono text-paper">TFCNet (Spectral Transformer)</dd>
              </div>
              <div className="flex justify-between border-b border-fog-deep/30 pb-1.5">
                <dt className="text-fog">Fusion Weight</dt>
                <dd className="mono text-teal font-semibold">60% SparseRSSM / 40% TFCNet</dd>
              </div>
              <div className="flex justify-between border-b border-fog-deep/30 pb-1.5">
                <dt className="text-fog">Latent Dimensions</dt>
                <dd className="mono text-paper">256-D State / 128-D Hidden</dd>
              </div>
              <div className="flex justify-between border-b border-fog-deep/30 pb-1.5">
                <dt className="text-fog">Benchmark Dataset</dt>
                <dd className="mono text-paper">CSE-CIC-IDS2018 (Infiltration)</dd>
              </div>
              <div className="flex justify-between">
                <dt className="text-fog">Optimal F1 Threshold</dt>
                <dd className="mono text-amber">0.650</dd>
              </div>
            </dl>
          </FlatPanel>
        </div>
      </div>

      {/* 54-Dimensional Raw Network Metric Inspector */}
      <div className="mt-8">
        <div className="flex flex-wrap items-center justify-between gap-4 pb-4">
          <div>
            <h2 className="font-display text-[18px] font-semibold text-paper">
              Raw Network Telemetry Inspector (54 Dimensions)
            </h2>
            <p className="text-[12px] text-fog mt-0.5">
              Exact feature values fed into the deep state-space model at window #{targetWindow}
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            {/* Search Input */}
            <div className="relative">
              <Search className="absolute left-2.5 top-2.5 size-3.5 text-fog" />
              <input
                type="text"
                placeholder="Search metrics (e.g. syn, entropy, delta)..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="rounded-md border border-fog-deep bg-void-700/60 pl-8 pr-3 py-1.5 text-[12px] text-paper outline-none focus:border-teal w-[240px]"
              />
            </div>

            {/* Category Filter */}
            <select
              value={selectedCategory}
              onChange={(e) => setSelectedCategory(e.target.value)}
              className="mono rounded-md border border-fog-deep bg-void-700/60 px-3 py-1.5 text-[12px] text-paper outline-none focus:border-teal"
            >
              <option value="all">All 7 Categories ({explainData?.rawFeaturesCount || 54})</option>
              {categories.map((cat) => (
                <option key={cat.id} value={cat.id}>
                  {cat.name} ({cat.features.length})
                </option>
              ))}
            </select>
          </div>
        </div>

        {/* Metrics Table */}
        <div className="flat overflow-x-auto p-0">
          <table className="w-full text-left text-[13px]">
            <thead>
              <tr className="border-b border-fog-deep/60 bg-void-900/50 text-[11px] font-mono text-fog uppercase">
                <th className="px-5 py-3">Metric Name / Description</th>
                <th className="px-5 py-3">Feature Key</th>
                <th className="px-5 py-3">Category</th>
                <th className="px-5 py-3 text-right">Observed Value</th>
                <th className="px-5 py-3 text-right">SHAP Impact</th>
                <th className="px-5 py-3 text-center">Status</th>
              </tr>
            </thead>
            <tbody>
              {filteredMetrics.map((m) => (
                <tr
                  key={m.key}
                  className="border-b border-fog-deep/30 last:border-0 hover:bg-paper/4 transition-colors"
                >
                  <td className="px-5 py-2.5">
                    <p className="font-medium text-paper">{m.label}</p>
                  </td>
                  <td className="mono px-5 py-2.5 text-[11px] text-fog">
                    {m.key}
                  </td>
                  <td className="px-5 py-2.5 text-[11px] text-fog">
                    {m.categoryName}
                  </td>
                  <td className="mono px-5 py-2.5 text-right font-semibold text-paper">
                    {m.formattedValue}
                  </td>
                  <td className="mono px-5 py-2.5 text-right">
                    {m.attributionWeight !== undefined ? (
                      <span
                        className={cn(
                          "font-semibold",
                          m.attributionWeight > 0 ? "text-crimson" : "text-teal",
                        )}
                      >
                        {m.attributionWeight > 0 ? "+" : ""}
                        {m.attributionWeight.toFixed(2)}
                      </span>
                    ) : (
                      <span className="text-fog-deep">—</span>
                    )}
                  </td>
                  <td className="px-5 py-2.5 text-center">
                    {m.isAnomaly ? (
                      <span className="inline-flex items-center gap-1 rounded bg-crimson/15 px-2 py-0.5 text-[10px] font-semibold text-crimson">
                        <AlertTriangle className="size-3" />
                        Anomaly
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 rounded bg-teal/10 px-2 py-0.5 text-[10px] text-teal">
                        <CheckCircle2 className="size-3" />
                        Nominal
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </>
  );
}

export default ExplainabilityPage;
