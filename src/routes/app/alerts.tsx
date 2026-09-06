import { useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { X } from "lucide-react";
import {
  ActionButton,
  HeroPanel,
  PageTitle,
  RiskBadge,
} from "@/components/app/panels";
import { ProbabilityTimeline } from "@/components/app/charts";
import { pageHead } from "@/lib/head";
import { alerts, probabilitySeries, type Alert } from "@/lib/telemetry";

export const Route = createFileRoute("/app/alerts")({
  head: pageHead(
    "Alerts and incident queue — Aegis Vantage",
    "Triage predicted compromises across new, acknowledged, investigating and resolved states.",
  ),
  component: AlertsQueue,
});

const columns = ["New", "Acknowledged", "Investigating", "Resolved"] as const;

function AlertsQueue() {
  const [selected, setSelected] = useState<Alert | null>(alerts[0] ?? null);

  return (
    <>
      <PageTitle
        title="Alerts and incident queue"
        note="Alerts appear here once a predicted probability crosses your threshold."
      />

      <div className="grid gap-4 xl:grid-cols-4">
        {columns.map((col) => {
          const items = alerts.filter((a) => a.status === col);
          return (
            <div key={col} className="flat p-3">
              <div className="mb-3 flex items-center justify-between px-1">
                <span className="text-[13px] font-medium">{col}</span>
                <span className="mono text-fog">{items.length}</span>
              </div>
              <div className="space-y-2">
                {items.map((a) => (
                  <button
                    key={a.id}
                    onClick={() => setSelected(a)}
                    className="w-full rounded-md border border-fog-deep bg-void-700 p-3 text-left hover:bg-paper/4"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <RiskBadge state={a.state} />
                      <span className="mono flex size-6 items-center justify-center rounded-full bg-void-800 text-[11px] text-fog">
                        {a.analyst}
                      </span>
                    </div>
                    <p className="mono mt-2">{a.host}</p>
                    <p className="mt-1 text-[13px] text-fog">{a.stage}</p>
                    <p className="mono mt-1.5">{a.probability.toFixed(2)}</p>
                  </button>
                ))}
                {items.length === 0 ? (
                  <p className="px-1 py-3 text-[13px] text-fog">
                    Nothing in this state.
                  </p>
                ) : null}
              </div>
            </div>
          );
        })}
      </div>

      {selected ? (
        <aside className="fixed inset-y-0 right-0 z-30 w-[420px] overflow-y-auto p-4">
          <HeroPanel
            state={selected.state}
            className="min-h-full"
            title={selected.id}
            control={
              <button
                onClick={() => setSelected(null)}
                aria-label="Close alert detail"
                className="text-fog hover:text-paper"
              >
                <X className="size-4" />
              </button>
            }
          >
            <div className="flex items-center gap-3">
              <RiskBadge state={selected.state} />
              <span className="mono">{selected.host}</span>
              <span className="mono text-fog">{selected.ip}</span>
            </div>
            <p className="mt-4 text-[15px]">{selected.reason}</p>

            <div className="mt-5">
              <p className="text-[13px] font-medium">Probability trajectory</p>
              <ProbabilityTimeline
                series={probabilitySeries.slice(-16)}
                height={140}
                animate={false}
              />
            </div>

            <dl className="mt-4 space-y-2">
              {[
                ["Predicted stage", selected.stage],
                ["Probability", selected.probability.toFixed(2)],
                ["Detected", selected.at],
                ["Assigned to", selected.analyst],
              ].map(([k, v]) => (
                <div
                  key={k}
                  className="flex justify-between border-b border-[var(--glass-border)] pb-1.5"
                >
                  <dt className="text-[13px] text-fog">{k}</dt>
                  <dd className="mono">{v}</dd>
                </div>
              ))}
            </dl>

            <label className="mt-5 block">
              <span className="text-[13px] font-medium">Analyst notes</span>
              <textarea
                rows={3}
                placeholder="What did you check, and what did you find?"
                className="mt-1.5 w-full rounded-md border border-fog-deep bg-void-700 px-3 py-2 text-[15px] outline-none placeholder:text-fog-deep focus:border-teal"
              />
            </label>

            <div className="mt-4 flex flex-wrap gap-2">
              <ActionButton>Acknowledge alert</ActionButton>
              <ActionButton variant="ghost">Mark investigating</ActionButton>
              <ActionButton variant="ghost">Assign to…</ActionButton>
            </div>
          </HeroPanel>
        </aside>
      ) : null}
    </>
  );
}
