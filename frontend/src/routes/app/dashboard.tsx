import { createFileRoute, Link } from "@tanstack/react-router";
import { useEffect, useMemo, useState } from "react";
import {
  ActionButton,
  FlatPanel,
  GlassPanel,
  HeroPanel,
  PageTitle,
  RiskBadge,
} from "@/components/app/panels";
import { ProbabilityTimeline, StageStrip } from "@/components/app/charts";
import { pageHead } from "@/lib/head";
import { attackStages, riskFromProbability } from "@/lib/telemetry";
import {
  useDashboardSummary,
  useDashboardTimeline,
  useDashboardStage,
  useAlerts,
  useFlows,
  useRunInference,
} from "@/hooks/useApi";
import {
  subscribeDashboardStream,
  stepDashboard,
  resetDashboard,
  jumpDashboard,
  type FullDashboardState,
} from "@/api/dashboardApi";
import { OnboardingModal } from "@/components/app/OnboardingModal";
import { fetchSensorsConfig, type SensorsConfigResponse } from "@/api/sensorsApi";
import { Zap, Radio } from "lucide-react";

export const Route = createFileRoute("/app/dashboard")({
  head: pageHead(
    "Dashboard — Aegis Vantage",
    "Current infiltration probability, predicted ATT&CK stage and recent alerts for the monitored estate.",
  ),
  component: Dashboard,
});

function Dashboard() {
  // REST snapshots for zero-delay initial render
  const { data: initialSummary } = useDashboardSummary();
  const { data: initialTimeline } = useDashboardTimeline();
  const { data: initialStage } = useDashboardStage();
  const { data: initialAlerts } = useAlerts();
  const { data: initialFlowsData } = useFlows({ page: 1, limit: 5, flaggedOnly: true });
  const runInference = useRunInference();

  // Real-time SSE live streaming state
  const [liveState, setLiveState] = useState<FullDashboardState | null>(null);
  const [isStreaming, setIsStreaming] = useState<boolean>(false);
  const [isActionPending, setIsActionPending] = useState<boolean>(false);

  // Sensor Onboarding & Scope State
  const [isOnboardingOpen, setIsOnboardingOpen] = useState<boolean>(false);
  const [selectedSensor, setSelectedSensor] = useState<string>("all");
  const [sensorConfig, setSensorConfig] = useState<SensorsConfigResponse | null>(null);

  useEffect(() => {
    let isMounted = true;
    const loadConfig = async () => {
      try {
        const data = await fetchSensorsConfig();
        if (isMounted) {
          setSensorConfig(data);
        }
      } catch (err) {
        console.warn("Could not load sensor config:", err);
      }
    };
    loadConfig();
    return () => {
      isMounted = false;
    };
  }, []);

  useEffect(() => {
    // Subscribe to SSE stream (/api/dashboard/stream)
    const unsubscribe = subscribeDashboardStream(
      (state) => {
        setLiveState(state);
        setIsStreaming(true);
      },
      () => {
        // Fallback gracefully to REST on network blip
        setIsStreaming(false);
      },
      selectedSensor,
    );

    return () => {
      unsubscribe();
    };
  }, [selectedSensor]);

  // Merged values (SSE stream takes precedence once connected)
  const currentProbability =
    liveState?.summary.infiltrationProbability ?? initialSummary?.currentProbability ?? 0.88;

  const activeFlowsDisplay =
    liveState?.summary.activeFlows ?? (initialSummary?.activeFlows ?? 14820).toLocaleString();

  const flaggedHostsDisplay =
    liveState?.summary.flaggedHosts ?? (initialSummary?.flaggedHosts ?? 3).toString();

  const modelConfidenceDisplay =
    liveState?.summary.modelConfidence ?? (initialSummary?.modelConfidence ?? 0.94).toFixed(2);

  const series = liveState?.timeline ?? initialTimeline?.series ?? [];

  const currentStageName =
    liveState?.summary.currentStage ?? initialStage?.stage ?? "Lateral Movement";

  const stageIndex = useMemo(() => {
    if (!currentStageName) return -1;
    const lower = currentStageName.toLowerCase();
    if (lower === "normal" || lower.includes("benign")) return -1;
    const idx = attackStages.findIndex((s) => lower.includes(s.toLowerCase()));
    return idx >= 0 ? idx : -1;
  }, [currentStageName]);

  const recentAlerts = useMemo(() => {
    if (liveState?.recentAlerts && liveState.recentAlerts.length > 0) {
      return liveState.recentAlerts.map((a) => ({
        _id: `alert-${a.id}`,
        state: a.level,
        host: a.host,
        detectedAt: a.ts,
        reason: a.reason,
      }));
    }
    return (
      initialAlerts?.data?.slice(0, 4).map((a) => ({
        _id: a._id,
        state: a.state,
        host: a.host,
        detectedAt: new Date(a.detectedAt || new Date()).toISOString().slice(11, 16) + "Z",
        reason: a.reason,
      })) ?? []
    );
  }, [liveState?.recentAlerts, initialAlerts?.data]);

  const recentFlows = useMemo(() => {
    if (liveState?.recentFlows && liveState.recentFlows.length > 0) {
      return liveState.recentFlows.map((f, idx) => ({
        _id: `flow-${idx}-${f.src}`,
        src: f.src,
        dst: f.dst,
        proto: f.proto,
        bytes: f.bytes,
        score: f.prob,
      }));
    }
    return (
      initialFlowsData?.data.map((f) => ({
        _id: f._id,
        src: f.src,
        dst: f.dst,
        proto: f.proto,
        bytes: f.bytes.toLocaleString() + " B",
        score: f.score,
      })) ?? []
    );
  }, [liveState?.recentFlows, initialFlowsData?.data]);

  const handleStep = async () => {
    setIsActionPending(true);
    try {
      await stepDashboard();
    } catch {
      runInference.mutate({ step: 1 });
    } finally {
      setIsActionPending(false);
    }
  };

  const handleReset = async () => {
    setIsActionPending(true);
    try {
      await resetDashboard();
    } catch {
      runInference.mutate({ action: "reset" });
    } finally {
      setIsActionPending(false);
    }
  };

  const handleJump = async () => {
    setIsActionPending(true);
    try {
      await jumpDashboard();
    } catch {
      runInference.mutate({ action: "jump_attack" });
    } finally {
      setIsActionPending(false);
    }
  };

  const stats = [
    {
      label: "Current probability",
      value: currentProbability.toFixed(2),
      tone:
        riskFromProbability(currentProbability) === "critical"
          ? "text-crimson"
          : riskFromProbability(currentProbability) === "watch"
            ? "text-amber"
            : "",
    },
    { label: "Active flows", value: activeFlowsDisplay },
    { label: "Flagged hosts", value: flaggedHostsDisplay },
    { label: "Model confidence", value: modelConfidenceDisplay },
  ];

  return (
    <>
      <PageTitle
        title="Overview"
        note={
          liveState
            ? `CIC-IDS-2018: Thursday-01-03-2018 · Window #${liveState.actual_window_index} [${liveState.summary.currentStage}]${
                liveState.summary.leadTimeSeconds ? ` · ${liveState.summary.leadTimeSeconds}s advance warning` : ""
              }`
            : "CIC-IDS-2018 benchmark telemetry · Infiltration Episode (EP_0001) · 20.0s advance warning"
        }
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <div className="flex items-center gap-1.5 px-2 py-1 text-[11px] font-mono text-fog border border-fog-deep/40 rounded bg-paper/5">
              <span
                className={`size-2 rounded-full ${
                  isStreaming ? "bg-teal animate-pulse" : "bg-fog"
                }`}
              />
              {isStreaming ? "Live SSE (3s)" : "Snapshot"}
            </div>

            <button
              onClick={handleReset}
              disabled={isActionPending || runInference.isPending}
              title="Reset telemetry to benign baseline (W#1750)"
              className="rounded-md border border-fog-deep/60 px-3 py-1.5 text-[12px] font-medium text-fog transition-colors hover:border-paper hover:text-paper disabled:opacity-50"
            >
              Reset (W#1750)
            </button>
            <button
              onClick={handleJump}
              disabled={isActionPending || runInference.isPending}
              title="Jump directly to infiltration attack onset (W#1796)"
              className="rounded-md border border-amber/40 bg-amber/10 px-3 py-1.5 text-[12px] font-medium text-amber transition-colors hover:bg-amber/20 disabled:opacity-50"
            >
              Attack Onset (W#1796)
            </button>
            <ActionButton
              onClick={handleStep}
              disabled={isActionPending || runInference.isPending}
            >
              {isActionPending || runInference.isPending ? "Inferencing..." : "Next Window (+1)"}
            </ActionButton>
          </div>
        }
      />

      {/* Telemetry Mode Banner */}
      {liveState?.isLive ? (
        <div className="mb-5 flex flex-col sm:flex-row sm:items-center justify-between gap-3 rounded-lg border border-teal/40 bg-teal/10 px-4 py-3 text-xs animate-fade-in">
          <div className="flex items-start sm:items-center gap-2.5">
            <span className="flex size-2.5 rounded-full bg-teal animate-pulse shrink-0 mt-1 sm:mt-0" />
            <div className="flex flex-col sm:flex-row sm:items-center gap-1 sm:gap-2">
              <span className="font-semibold text-paper tracking-wide shrink-0">
                LIVE INFRASTRUCTURE TELEMETRY
              </span>
              <span className="text-fog">
                Streaming from {liveState.activeSensorsCount || 1} active edge sensor(s) · Zero-latency neural predictions
              </span>
            </div>
          </div>
          <button
            onClick={() => setIsOnboardingOpen(true)}
            className="rounded border border-teal/40 bg-teal/20 px-3 py-1.5 font-medium text-teal hover:bg-teal/30 transition-colors shrink-0 text-center w-full sm:w-auto"
          >
            Edge Sensor Setup
          </button>
        </div>
      ) : (
        <div className="mb-5 flex flex-col sm:flex-row sm:items-center justify-between gap-3 rounded-lg border border-amber/40 bg-amber/10 px-4 py-3 text-xs animate-fade-in">
          <div className="flex items-start sm:items-center gap-2.5">
            <Radio className="size-4 text-amber animate-pulse shrink-0 mt-0.5 sm:mt-0" />
            <div className="flex flex-col sm:flex-row sm:items-center gap-1 sm:gap-2">
              <span className="font-semibold text-amber-light shrink-0">
                DEMO BENCHMARK MODE (CSE-CIC-IDS2018)
              </span>
              <span className="text-fog">
                Displaying simulated benchmark replay. Connect your edge sensor to start real-time threat forecasting.
              </span>
            </div>
          </div>
          <button
            onClick={() => setIsOnboardingOpen(true)}
            className="flex items-center justify-center gap-1.5 rounded-md border border-amber/50 bg-amber/20 px-3 py-1.5 font-medium text-amber hover:bg-amber/30 transition-colors shrink-0 shadow-sm w-full sm:w-auto"
          >
            <Zap className="size-3.5" /> Connect Edge Sensor
          </button>
        </div>
      )}

      <div className="flat mb-5 grid divide-fog-deep/60 sm:grid-cols-2 sm:divide-x lg:grid-cols-4">
        {stats.map((s) => (
          <div key={s.label} className="px-5 py-4">
            <p
              className={`font-display text-[28px] leading-none font-semibold ${s.tone ?? ""}`}
            >
              {s.value}
            </p>
            <p className="mt-1.5 text-[12px] text-fog">{s.label}</p>
          </div>
        ))}
      </div>

      <div className="grid gap-5 lg:grid-cols-[minmax(0,1.6fr)_minmax(0,1fr)]">
        <HeroPanel
          title="Infiltration probability timeline"
          state={riskFromProbability(currentProbability)}
          control={
            <>
              <RiskBadge state={riskFromProbability(currentProbability)} />
              <span className="mono text-fog">4h · 20s windows</span>
            </>
          }
        >
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-3 pt-1">
            <div className="flex flex-col sm:flex-row sm:items-center gap-1.5 sm:gap-2 w-full sm:w-auto">
              <span className="text-xs text-fog font-medium shrink-0">Timeline Scope:</span>
              <select
                value={selectedSensor}
                onChange={(e) => setSelectedSensor(e.target.value)}
                className="w-full sm:w-auto max-w-full rounded border border-fog-deep bg-void-800 px-2.5 py-1 text-xs text-paper focus:outline-none focus:border-teal"
              >
                <option value="all">Estate Aggregate (Global Max Threat across systems)</option>
                {sensorConfig?.activeSensors?.map((s) => (
                  <option key={s.sensorId} value={s.sensorId}>
                    Sensor: {s.sensorId} ({s.stage || "Active"})
                  </option>
                ))}
              </select>
            </div>
            {liveState?.isLive && (
              <span className="text-[11px] text-teal font-mono flex items-center gap-1 self-start sm:self-auto">
                <span className="size-1.5 rounded-full bg-teal animate-pulse" /> 2.0s Live Ticks
              </span>
            )}
          </div>
          <ProbabilityTimeline series={series} height={280} />
        </HeroPanel>

        <div className="grid gap-5 content-start">
          <GlassPanel
            title="Predicted ATT&CK stage"
            control={
              <span className={`mono ${currentStageName === "Normal" ? "text-teal" : "text-amber"}`}>
                {currentStageName}
              </span>
            }
          >
            <StageStrip current={stageIndex} />
            <p className="mt-5 text-[15px] text-fog">
              {currentStageName === "Normal"
                ? "Enterprise telemetry is currently within baseline parameters. SparseRSSM + TFCNet active surveillance."
                : `${currentStageName} is the active forecasted MITRE ATT&CK progression phase.`}
            </p>
          </GlassPanel>

          <GlassPanel
            title="Recent alerts"
            control={
              <Link to="/app/alerts" className="text-[13px] text-teal">
                View all
              </Link>
            }
          >
            <ul className="divide-y divide-[var(--glass-border)]">
              {recentAlerts.map((a) => (
                <li key={a._id} className="flex gap-3 py-3 first:pt-0 last:pb-0">
                  <RiskBadge state={a.state as any} />
                  <div className="min-w-0">
                    <p className="mono truncate">
                      {a.host} <span className="text-fog">{a.detectedAt}</span>
                    </p>
                    <p className="mt-0.5 truncate text-[13px] text-fog">
                      {a.reason}
                    </p>
                  </div>
                </li>
              ))}
            </ul>
          </GlassPanel>
        </div>
      </div>

      <FlatPanel
        className="mt-5"
        title="Most recent flagged flows"
        bodyClassName="p-0"
      >
        <table className="w-full text-left">
          <thead className="text-[12px] text-fog">
            <tr className="border-b border-fog-deep/60">
              <th className="px-5 py-2.5 font-medium">Source</th>
              <th className="px-5 py-2.5 font-medium">Destination</th>
              <th className="px-5 py-2.5 font-medium">Protocol</th>
              <th className="px-5 py-2.5 text-right font-medium">Bytes</th>
              <th className="px-5 py-2.5 text-right font-medium">Score</th>
              <th className="px-5 py-2.5 font-medium"></th>
            </tr>
          </thead>
          <tbody>
            {recentFlows.map((f) => (
              <tr
                key={f._id}
                className="border-b border-fog-deep/40 last:border-0 hover:bg-paper/4"
              >
                <td className="mono px-5 py-2.5">{f.src}</td>
                <td className="mono px-5 py-2.5">{f.dst}</td>
                <td className="mono px-5 py-2.5">{f.proto}</td>
                <td className="mono px-5 py-2.5 text-right">{f.bytes}</td>
                <td className="mono px-5 py-2.5 text-right">
                  {typeof f.score === "number" ? f.score.toFixed(2) : f.score}
                </td>
                <td className="px-5 py-2.5 text-right">
                  <Link to="/app/explorer" className="text-[13px] text-teal">
                    View in explorer
                  </Link>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </FlatPanel>

      <OnboardingModal
        isOpen={isOnboardingOpen}
        onClose={() => setIsOnboardingOpen(false)}
        onConnected={() => setIsOnboardingOpen(false)}
      />
    </>
  );
}

export default Dashboard;
