import { createFileRoute } from "@tanstack/react-router";
import {
  ActionButton,
  FlatPanel,
  HeroPanel,
  PageTitle,
} from "@/components/app/panels";
import { LossCurve } from "@/components/app/charts";
import { pageHead } from "@/lib/head";
import { benchmark, lossCurve } from "@/lib/telemetry";

export const Route = createFileRoute("/app/benchmark")({
  head: pageHead(
    "Model benchmarks — Aegis Vantage",
    "World model against a logistic-regression baseline on CIC-IDS-2018 and CTU-13, with loss curves and version history.",
  ),
  component: Benchmark,
});

const matrices = [
  { name: "Logistic regression baseline", cells: [812, 91, 143, 954] },
  { name: "World model wm-v4.2.1", cells: [948, 14, 39, 999] },
];

const versions = [
  { v: "wm-v4.2.1", at: "2026-09-06", note: "F1 +0.021, FPR −0.006", live: true },
  { v: "wm-v4.1.0", at: "2026-08-22", note: "F1 +0.014, recall +0.019" },
  { v: "wm-v4.0.3", at: "2026-08-04", note: "FPR −0.011" },
  { v: "wm-v3.9.0", at: "2026-07-15", note: "baseline for current architecture" },
];

function Benchmark() {
  return (
    <>
      <PageTitle
        title="Model benchmarks"
        note="Held-out evaluation across both public datasets, refreshed on every promoted version."
      />

      <div className="grid gap-5 lg:grid-cols-[minmax(0,1.1fr)_minmax(0,1fr)]">
        <FlatPanel title="World model versus baseline" bodyClassName="p-0">
          <table className="w-full text-left">
            <thead className="text-[12px] text-fog">
              <tr className="border-b border-fog-deep/60">
                <th className="px-5 py-2.5 font-medium">Metric</th>
                <th className="px-5 py-2.5 text-right font-medium">
                  WM · CIC-IDS
                </th>
                <th className="px-5 py-2.5 text-right font-medium">
                  LR · CIC-IDS
                </th>
                <th className="px-5 py-2.5 text-right font-medium">WM · CTU-13</th>
                <th className="px-5 py-2.5 text-right font-medium">LR · CTU-13</th>
              </tr>
            </thead>
            <tbody>
              {benchmark.map((b) => (
                <tr
                  key={b.metric}
                  className="border-b border-fog-deep/40 last:border-0 hover:bg-paper/4"
                >
                  <td className="px-5 py-2.5 text-[13px]">{b.metric}</td>
                  <td className="mono px-5 py-2.5 text-right text-teal">
                    {b.wmA.toFixed(3)}
                  </td>
                  <td className="mono px-5 py-2.5 text-right text-fog">
                    {b.lrA.toFixed(3)}
                  </td>
                  <td className="mono px-5 py-2.5 text-right text-teal">
                    {b.wmB.toFixed(3)}
                  </td>
                  <td className="mono px-5 py-2.5 text-right text-fog">
                    {b.lrB.toFixed(3)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </FlatPanel>

        <FlatPanel
          title="Confusion matrices"
          control={<span className="mono text-fog">CIC-IDS-2018</span>}
        >
          <div className="grid gap-6 sm:grid-cols-2">
            {matrices.map((m) => (
              <div key={m.name}>
                <div className="grid grid-cols-2 gap-1">
                  {m.cells.map((c, i) => (
                    <div
                      key={i}
                      className="mono rounded-[4px] px-3 py-4 text-center"
                      style={{
                        background:
                          i === 0 || i === 3
                            ? "color-mix(in oklab, var(--signal-teal) 18%, transparent)"
                            : "color-mix(in oklab, var(--critical-crimson) 18%, transparent)",
                      }}
                    >
                      {c}
                    </div>
                  ))}
                </div>
                <p className="mt-2 text-[12px] text-fog">{m.name}</p>
              </div>
            ))}
          </div>
        </FlatPanel>
      </div>

      <HeroPanel
        className="mt-5"
        title="Training and validation loss"
        control={
          <select className="mono rounded-md border border-fog-deep bg-void-700 px-2.5 py-1.5 outline-none">
            {versions.map((v) => (
              <option key={v.v}>{v.v}</option>
            ))}
          </select>
        }
      >
        <LossCurve train={lossCurve.train} val={lossCurve.val} />
        <div className="mt-3 flex gap-6 text-[13px]">
          <span className="flex items-center gap-2">
            <span className="h-0.5 w-6 bg-teal" /> Training loss
          </span>
          <span className="flex items-center gap-2">
            <span className="h-0.5 w-6 border-t-2 border-dashed border-amber" />{" "}
            Validation loss
          </span>
        </div>
      </HeroPanel>

      <FlatPanel className="mt-5" title="Version history">
        <ol className="relative border-l border-fog-deep pl-6">
          {versions.map((v) => (
            <li key={v.v} className="relative pb-5 last:pb-0">
              <span
                className="absolute top-1.5 -left-[27px] size-2.5 rounded-full"
                style={{
                  background: v.live ? "var(--signal-teal)" : "var(--fog-600)",
                }}
              />
              <div className="flex flex-wrap items-center gap-3">
                <span className="mono">{v.v}</span>
                <span className="mono text-fog">{v.at}</span>
                <span className="text-[13px] text-fog">{v.note}</span>
                {v.live ? (
                  <span className="text-[12px] text-teal">in production</span>
                ) : (
                  <ActionButton variant="ghost" className="py-1">
                    Promote to production
                  </ActionButton>
                )}
              </div>
            </li>
          ))}
        </ol>
      </FlatPanel>
    </>
  );
}
