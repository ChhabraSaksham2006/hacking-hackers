import { useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import {
  ActionButton,
  FlatPanel,
  HeroPanel,
  PageTitle,
} from "@/components/app/panels";
import { DualTrajectory } from "@/components/app/charts";
import { pageHead } from "@/lib/head";
import { actualSeries, forecastSeries } from "@/lib/telemetry";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/app/simulation")({
  head: pageHead(
    "Simulation console — Aegis Vantage",
    "Perturb the current network state and compare the forecast trajectory against what actually happened.",
  ),
  component: Simulation,
});

const perturbations = [
  "Inject port scan on ops-jump-05",
  "Simulate lateral movement from fin-db-02",
  "Add 40x outbound volume on dev-ci-03",
  "Drop dmz-edge segmentation rule",
];

const divergence = [
  { step: "k+1", pred: 0.9, real: 0.87 },
  { step: "k+2", pred: 0.91, real: 0.85 },
  { step: "k+4", pred: 0.95, real: 0.81 },
  { step: "k+6", pred: 0.96, real: 0.8 },
];

function Simulation() {
  const [applied, setApplied] = useState<string | null>(perturbations[1] ?? null);
  const [overlay, setOverlay] = useState(true);

  return (
    <>
      <PageTitle
        title="Simulation console"
        note="Run the world model forward from a perturbed state and check the forecast against recorded reality."
      />

      <div className="grid gap-5 lg:grid-cols-[300px_minmax(0,1fr)]">
        <FlatPanel title="Run setup" className="h-fit">
          <ol className="space-y-5">
            <li>
              <p className="mono text-fog">1 — define state</p>
              <p className="mt-1.5 text-[15px]">corp-core at 14:40Z</p>
              <p className="mono mt-1 text-fog">
                412 hosts · 12,481 flows · p 0.88
              </p>
            </li>
            <li>
              <p className="mono text-fog">2 — apply perturbation</p>
              <div className="mt-2 flex flex-col gap-1">
                {perturbations.map((p) => (
                  <button
                    key={p}
                    onClick={() => setApplied(p)}
                    className={cn(
                      "rounded-md px-3 py-2 text-left text-[13px]",
                      applied === p
                        ? "bg-teal/12 text-teal"
                        : "text-fog hover:text-paper",
                    )}
                  >
                    {p}
                  </button>
                ))}
              </div>
            </li>
            <li>
              <p className="mono text-fog">3 — run forward simulation</p>
              <ActionButton className="mt-2 w-full">
                Run 8-step forecast
              </ActionButton>
            </li>
            <li>
              <p className="mono text-fog">4 — compare</p>
              <button
                onClick={() => setOverlay((v) => !v)}
                className="mt-2 w-full rounded-md border border-fog-deep px-3 py-2 text-[13px] font-medium hover:bg-void-700"
              >
                {overlay ? "Hide replay overlay" : "Overlay what actually happened"}
              </button>
            </li>
          </ol>
        </FlatPanel>

        <div className="grid gap-5 content-start">
          <HeroPanel
            title="Forecast trajectory — 8 steps"
            state="critical"
            control={<span className="mono text-fog">{applied}</span>}
          >
            <DualTrajectory
              predicted={forecastSeries}
              actual={overlay ? actualSeries : forecastSeries}
            />
            <div className="mt-3 flex gap-6 text-[13px]">
              <span className="flex items-center gap-2">
                <span className="h-0.5 w-6 border-t-2 border-dashed border-teal" />{" "}
                Model prediction
              </span>
              {overlay ? (
                <span className="flex items-center gap-2">
                  <span className="h-0.5 w-6 bg-paper" /> What actually happened
                </span>
              ) : null}
            </div>
          </HeroPanel>

          <FlatPanel title="Divergence readout" bodyClassName="p-0">
            <table className="w-full text-left">
              <thead className="text-[12px] text-fog">
                <tr className="border-b border-fog-deep/60">
                  <th className="px-5 py-2.5 font-medium">Step</th>
                  <th className="px-5 py-2.5 text-right font-medium">Predicted</th>
                  <th className="px-5 py-2.5 text-right font-medium">Observed</th>
                  <th className="px-5 py-2.5 text-right font-medium">Delta</th>
                </tr>
              </thead>
              <tbody>
                {divergence.map((d) => (
                  <tr
                    key={d.step}
                    className="border-b border-fog-deep/40 last:border-0 hover:bg-paper/4"
                  >
                    <td className="mono px-5 py-2.5">{d.step}</td>
                    <td className="mono px-5 py-2.5 text-right">{d.pred.toFixed(2)}</td>
                    <td className="mono px-5 py-2.5 text-right">{d.real.toFixed(2)}</td>
                    <td className="mono px-5 py-2.5 text-right text-amber">
                      {(d.pred - d.real).toFixed(2)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            <p className="max-w-[70ch] px-5 py-4 text-[15px] text-fog">
              Divergence grows after k+2 because containment isolated fin-db-02 at
              14:52Z, which the simulation state does not include.
            </p>
          </FlatPanel>
        </div>
      </div>
    </>
  );
}
