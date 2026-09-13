import { createFileRoute, Link } from "@tanstack/react-router";
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
import { riskFromProbability } from "@/lib/telemetry";
import {
  useDashboardSummary,
  useDashboardTimeline,
  useDashboardStage,
  useAlerts,
  useFlows,
} from "@/hooks/useApi";

export const Route = createFileRoute("/app/dashboard")({
  head: pageHead(
    "Dashboard — Aegis Vantage",
    "Current infiltration probability, predicted ATT&CK stage and recent alerts for the monitored estate.",
  ),
  component: Dashboard,
});

function Dashboard() {
  const { data: summary } = useDashboardSummary();
  const { data: timeline } = useDashboardTimeline();
  const { data: stage } = useDashboardStage();
  const { data: alerts } = useAlerts();
  const { data: flowsData } = useFlows({ page: 1, limit: 5, flaggedOnly: true });

  const stats = [
    {
      label: "Current probability",
      value: (summary?.currentProbability ?? 0).toFixed(2),
      tone:
        riskFromProbability(summary?.currentProbability ?? 0) === "critical"
          ? "text-crimson"
          : riskFromProbability(summary?.currentProbability ?? 0) === "watch"
            ? "text-amber"
            : "",
    },
    { label: "Active flows", value: (summary?.activeFlows ?? 0).toLocaleString() },
    { label: "Flagged hosts", value: (summary?.flaggedHosts ?? 0).toString() },
    { label: "Model confidence", value: (summary?.modelConfidence ?? 0).toFixed(2) },
  ];

  return (
    <>
      <PageTitle
        title="Overview"
        note="Corp-core is on a rising trajectory. The model places the estate in lateral movement two windows ahead of the current window."
        actions={<ActionButton>Run inference</ActionButton>}
      />

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
          state={riskFromProbability(summary?.currentProbability ?? 0)}
          control={
            <>
              <RiskBadge state={riskFromProbability(summary?.currentProbability ?? 0)} />
              <span className="mono text-fog">4h · 5m windows</span>
            </>
          }
        >
          <ProbabilityTimeline series={timeline?.series ?? []} height={280} />
        </HeroPanel>

        <div className="grid gap-5 content-start">
          <GlassPanel
            title="Predicted ATT&CK stage"
            control={<span className="mono text-amber">{stage?.stage ?? "Unknown"}</span>}
          >
            {/* Find the index of the predicted stage if needed, or pass 2 as default */}
            <StageStrip current={2} />
            <p className="mt-5 text-[15px] text-fog">
              {stage?.stage ?? "Unknown"} is the highest-likelihood next state.
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
              {alerts?.data?.slice(0, 4).map((a) => (
                <li key={a._id} className="flex gap-3 py-3 first:pt-0 last:pb-0">
                  <RiskBadge state={a.state} />
                  <div className="min-w-0">
                    <p className="mono truncate">
                      {a.host} <span className="text-fog">
                        {new Date(a.detectedAt || new Date()).toISOString().slice(11, 16) + "Z"}
                      </span>
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
            {flowsData?.data.map((f) => (
              <tr
                key={f._id}
                className="border-b border-fog-deep/40 last:border-0 hover:bg-paper/4"
              >
                <td className="mono px-5 py-2.5">{f.src}</td>
                <td className="mono px-5 py-2.5">{f.dst}</td>
                <td className="mono px-5 py-2.5">{f.proto}</td>
                <td className="mono px-5 py-2.5 text-right">
                  {f.bytes.toLocaleString()}
                </td>
                <td className="mono px-5 py-2.5 text-right">
                  {f.score.toFixed(2)}
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
    </>
  );
}
