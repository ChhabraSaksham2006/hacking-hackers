import { useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import {
  ActionButton,
  FlatPanel,
  HeroPanel,
  PageTitle,
} from "@/components/app/panels";
import { LossCurve } from "@/components/app/charts";
import { pageHead } from "@/lib/head";
import {
  useBenchmark,
  useModelVersions,
  usePromoteModel,
  type ModelVersionRecord,
} from "@/hooks/useApi";
import { Loader2, AlertCircle, CheckCircle2 } from "lucide-react";

export const Route = createFileRoute("/app/benchmark")({
  head: pageHead(
    "Model benchmarks — Aegis Vantage",
    "World model against a logistic-regression baseline on CIC-IDS-2018 and CTU-13, with loss curves and version history.",
  ),
  component: Benchmark,
});

function Benchmark() {
  const {
    data: bench,
    isLoading: benchLoading,
    isError: benchError,
  } = useBenchmark();

  const {
    data: versions,
    isLoading: versionsLoading,
    isError: versionsError,
  } = useModelVersions();

  const promote = usePromoteModel();

  // Selected version for the loss curve — default to production
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const selectedVersion: ModelVersionRecord | undefined =
    versions?.find((v) => v._id === selectedId) ??
    versions?.find((v) => v.isProduction) ??
    versions?.[0];

  function handlePromote(v: ModelVersionRecord) {
    if (v.isProduction || promote.isPending) return;
    promote.mutate(v._id);
  }

  const isLoading = benchLoading || versionsLoading;
  const isError   = benchError   || versionsError;

  if (isLoading) {
    return (
      <div className="flex h-64 items-center justify-center gap-2 text-fog">
        <Loader2 className="size-5 animate-spin" />
        <span>Loading benchmark data…</span>
      </div>
    );
  }

  if (isError || !bench || !versions) {
    return (
      <div className="flex h-64 flex-col items-center justify-center gap-3 text-fog">
        <AlertCircle className="size-6 text-red-400" />
        <p className="text-[14px]">Failed to load benchmark data from the server.</p>
      </div>
    );
  }

  return (
    <>
      <PageTitle
        title="Model benchmarks"
        note="Held-out evaluation across both public datasets, refreshed on every promoted version."
      />

      <div className="grid gap-5 lg:grid-cols-[minmax(0,1.1fr)_minmax(0,1fr)]">
        {/* ── Metrics table ──────────────────────────────── */}
        <FlatPanel title="World model versus baseline" bodyClassName="p-0">
          <table className="w-full text-left">
            <thead className="text-[12px] text-fog">
              <tr className="border-b border-fog-deep/60">
                <th className="px-5 py-2.5 font-medium">Metric</th>
                <th className="px-5 py-2.5 text-right font-medium">WM · CIC-IDS</th>
                <th className="px-5 py-2.5 text-right font-medium">LR · CIC-IDS</th>
                <th className="px-5 py-2.5 text-right font-medium">WM · CTU-13</th>
                <th className="px-5 py-2.5 text-right font-medium">LR · CTU-13</th>
              </tr>
            </thead>
            <tbody>
              {bench.rows.map((b) => (
                <tr
                  key={b.metric}
                  className="border-b border-fog-deep/40 last:border-0 hover:bg-paper/4"
                >
                  <td className="px-5 py-2.5 text-[13px]">{b.metric}</td>
                  <td className="mono px-5 py-2.5 text-right text-teal">{b.wmA.toFixed(3)}</td>
                  <td className="mono px-5 py-2.5 text-right text-fog">{b.lrA.toFixed(3)}</td>
                  <td className="mono px-5 py-2.5 text-right text-teal">{b.wmB.toFixed(3)}</td>
                  <td className="mono px-5 py-2.5 text-right text-fog">{b.lrB.toFixed(3)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </FlatPanel>

        {/* ── Confusion matrices ─────────────────────────── */}
        <FlatPanel
          title="Confusion matrices"
          control={<span className="mono text-fog">CIC-IDS-2018</span>}
        >
          <div className="grid gap-6 sm:grid-cols-2">
            {bench.matrices.map((m) => (
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

      {/* ── Loss curve ─────────────────────────────────────── */}
      <HeroPanel
        className="mt-5"
        title="Training and validation loss"
        control={
          <select
            value={selectedId ?? selectedVersion?._id ?? ""}
            onChange={(e) => setSelectedId(e.target.value)}
            className="mono rounded-md border border-fog-deep bg-void-700 px-2.5 py-1.5 outline-none"
          >
            {versions.map((v) => (
              <option key={v._id} value={v._id}>
                {v.version}{v.isProduction ? " (production)" : ""}
              </option>
            ))}
          </select>
        }
      >
        {selectedVersion?.lossCurve ? (
          <>
            <LossCurve
              train={selectedVersion.lossCurve.train}
              val={selectedVersion.lossCurve.val}
            />
            <div className="mt-3 flex gap-6 text-[13px]">
              <span className="flex items-center gap-2">
                <span className="h-0.5 w-6 bg-teal" /> Training loss
              </span>
              <span className="flex items-center gap-2">
                <span className="h-0.5 w-6 border-t-2 border-dashed border-amber" />{" "}
                Validation loss
              </span>
            </div>
          </>
        ) : (
          <p className="py-8 text-center text-fog">No loss curve data for this version.</p>
        )}
      </HeroPanel>

      {/* ── Version history ─────────────────────────────────── */}
      <FlatPanel className="mt-5" title="Version history">
        {promote.isError && (
          <p className="mb-4 flex items-center gap-2 text-[13px] text-red-400">
            <AlertCircle className="size-4" />
            Failed to promote model. Please try again.
          </p>
        )}
        {promote.isSuccess && (
          <p className="mb-4 flex items-center gap-2 text-[13px] text-teal">
            <CheckCircle2 className="size-4" />
            Model promoted to production successfully.
          </p>
        )}
        <ol className="relative border-l border-fog-deep pl-6">
          {versions.map((v) => (
            <li key={v._id} className="relative pb-5 last:pb-0">
              <span
                className="absolute top-1.5 -left-[27px] size-2.5 rounded-full"
                style={{
                  background: v.isProduction
                    ? "var(--signal-teal)"
                    : "var(--fog-600)",
                }}
              />
              <div className="flex flex-wrap items-center gap-3">
                <button
                  onClick={() => setSelectedId(v._id)}
                  className="mono hover:text-teal transition-colors"
                >
                  {v.version}
                </button>
                <span className="mono text-fog">
                  {new Date(v.releasedAt).toISOString().slice(0, 10)}
                </span>
                <span className="text-[13px] text-fog">{v.note}</span>
                {v.isProduction ? (
                  <span className="text-[12px] text-teal">in production</span>
                ) : (
                  <ActionButton
                    variant="ghost"
                    className="py-1"
                    disabled={promote.isPending}
                    onClick={() => handlePromote(v)}
                  >
                    {promote.isPending ? (
                      <span className="flex items-center gap-1.5">
                        <Loader2 className="size-3 animate-spin" /> Promoting…
                      </span>
                    ) : (
                      "Promote to production"
                    )}
                  </ActionButton>
                )}
                {/* Inline metrics summary */}
                <span className="mono ml-auto text-[12px] text-fog">
                  F1 {v.metrics.cicIds.f1.toFixed(3)} · FPR {v.metrics.cicIds.fpr.toFixed(3)}
                </span>
              </div>
            </li>
          ))}
        </ol>
      </FlatPanel>
    </>
  );
}
