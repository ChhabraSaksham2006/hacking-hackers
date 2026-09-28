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
import { Loader2, AlertCircle, CheckCircle2, ShieldAlert, Zap, Layers, Cpu } from "lucide-react";

export const Route = createFileRoute("/app/benchmark")({
  head: pageHead(
    "Model benchmarks — Flow दृष्टि",
    "Verbatim experimental record from CSE-CIC-IDS2018 across Setting A (In-Distribution), Setting B (Mixed Generalization), and Setting C (Unseen-Family OOD).",
  ),
  component: Benchmark,
});

// Master benchmark data from final.pdf (Tables V, VI, VII)
interface BenchmarkRow {
  model: string;
  variant: string;
  params: string;
  precision: string;
  recall: string;
  f1: string;
  fpr: string;
  onsetRecall: string;
  faWin: string;
  faInc: string;
  stateMae: string;
  highlight?: boolean;
}

const SETTING_C_ROWS: BenchmarkRow[] = [
  { model: "Majority", variant: "Constant 0", params: "0", precision: "0.00%", recall: "0.00%", f1: "0.00%", fpr: "0.00%", onsetRecall: "0% (0/7)", faWin: "0.00", faInc: "0.00", stateMae: "—" },
  { model: "Persistence", variant: "yt+10 = yt", params: "0", precision: "99.66%", recall: "99.66%", f1: "99.66%", fpr: "0.00%", onsetRecall: "0% (0/7)", faWin: "0.00", faInc: "0.00", stateMae: "—" },
  { model: "Logistic Regression", variant: "Static 54D", params: "55", precision: "41.18%", recall: "84.18%", f1: "55.31%", fpr: "49.35%", onsetRecall: "100% (7/7)", faWin: "888.35", faInc: "17.02", stateMae: "—" },
  { model: "Random Forest", variant: "Static 54D", params: "250k", precision: "40.90%", recall: "88.79%", f1: "56.00%", fpr: "52.67%", onsetRecall: "100% (7/7)", faWin: "948.12", faInc: "4.99", stateMae: "—" },
  { model: "Temporal GRU", variant: "10-Step Seq", params: "239,517", precision: "46.91%", recall: "49.07%", f1: "47.97%", fpr: "22.78%", onsetRecall: "42.9% (3/7)", faWin: "410.00", faInc: "26.02", stateMae: "0.2656" },
  { model: "Temporal Transformer", variant: "10-Step Seq", params: "341,789", precision: "30.87%", recall: "16.12%", f1: "21.18%", fpr: "14.84%", onsetRecall: "28.6% (2/7)", faWin: "267.23", faInc: "20.63", stateMae: "0.2721" },
  { model: "SparseRSSM", variant: "Raw AR Rollout", params: "214,334", precision: "38.90%", recall: "96.05%", f1: "55.37%", fpr: "61.96%", onsetRecall: "100% (7/7)", faWin: "1115.38", faInc: "34.12", stateMae: "0.3166" },
  { model: "SparseRSSM", variant: "Hysteresis", params: "214,334", precision: "84.46%", recall: "12.34%", f1: "21.53%", fpr: "0.93%", onsetRecall: "0% (0/7)", faWin: "16.78", faInc: "0.62", stateMae: "0.3166" },
  { model: "TFCNet-F", variant: "Raw Spectral", params: "400,914", precision: "38.08%", recall: "99.76%", f1: "55.12%", fpr: "66.64%", onsetRecall: "100% (7/7)", faWin: "1199.48", faInc: "38.24", stateMae: "0.2494" },
  { model: "TFCNet-F", variant: "Hysteresis", params: "400,914", precision: "52.89%", recall: "43.38%", f1: "47.67%", fpr: "15.84%", onsetRecall: "71.4% (5/7)", faWin: "285.07", faInc: "11.20", stateMae: "0.2494" },
  { model: "Hybrid Fusion", variant: "Latent Gated", params: "734,350", precision: "45.61%", recall: "35.18%", f1: "39.72%", fpr: "17.21%", onsetRecall: "42.9% (3/7)", faWin: "309.75", faInc: "12.80", stateMae: "0.2474" },
  { model: "Two-Stage Operational SOC", variant: "Scout + Gate + Agg", params: "615,248", precision: "96.88%", recall: "100.0%", f1: "98.41%", fpr: "66.14%", onsetRecall: "100% (7/7)", faWin: "1190.56", faInc: "0.12", stateMae: "0.2474", highlight: true },
];

const SETTING_A_ROWS: BenchmarkRow[] = [
  { model: "Majority", variant: "Constant 0", params: "0", precision: "0.00%", recall: "0.00%", f1: "0.00%", fpr: "0.00%", onsetRecall: "0% (0/29)", faWin: "0.00", faInc: "0.00", stateMae: "—" },
  { model: "Persistence", variant: "yt+10 = yt", params: "0", precision: "94.35%", recall: "94.16%", f1: "94.25%", fpr: "1.07%", onsetRecall: "0% (0/29)", faWin: "0.00", faInc: "0.00", stateMae: "—" },
  { model: "Logistic Regression", variant: "Static 54D", params: "55", precision: "36.26%", recall: "99.23%", f1: "53.12%", fpr: "32.93%", onsetRecall: "96.6% (28/29)", faWin: "576.74", faInc: "6.40", stateMae: "—" },
  { model: "Random Forest", variant: "Static 54D", params: "250k", precision: "36.81%", recall: "92.67%", f1: "52.69%", fpr: "30.04%", onsetRecall: "96.6% (28/29)", faWin: "524.34", faInc: "8.91", stateMae: "—" },
  { model: "Temporal GRU", variant: "10-Step Seq", params: "239,517", precision: "45.05%", recall: "99.47%", f1: "62.01%", fpr: "22.91%", onsetRecall: "96.6% (28/29)", faWin: "394.36", faInc: "10.08", stateMae: "0.2199" },
  { model: "Temporal Transformer", variant: "10-Step Seq", params: "341,789", precision: "51.14%", recall: "98.91%", f1: "67.42%", fpr: "17.84%", onsetRecall: "93.1% (27/29)", faWin: "303.02", faInc: "11.78", stateMae: "0.2354" },
  { model: "SparseRSSM", variant: "Raw AR Rollout", params: "214,334", precision: "51.06%", recall: "98.67%", f1: "67.29%", fpr: "17.86%", onsetRecall: "93.1% (27/29)", faWin: "303.68", faInc: "11.82", stateMae: "0.2234" },
  { model: "SparseRSSM", variant: "Hysteresis", params: "214,334", precision: "71.50%", recall: "94.78%", f1: "81.51%", fpr: "6.94%", onsetRecall: "79.3% (23/29)", faWin: "119.23", faInc: "4.24", stateMae: "0.2234" },
  { model: "TFCNet-F", variant: "Raw Spectral", params: "400,914", precision: "46.72%", recall: "94.78%", f1: "62.59%", fpr: "20.40%", onsetRecall: "96.6% (28/29)", faWin: "351.74", faInc: "13.62", stateMae: "0.1909" },
  { model: "TFCNet-F", variant: "Hysteresis", params: "400,914", precision: "77.39%", recall: "49.62%", f1: "60.47%", fpr: "2.72%", onsetRecall: "62.1% (18/29)", faWin: "46.74", faInc: "1.82", stateMae: "0.1909" },
  { model: "Hybrid Fusion", variant: "Latent Gated", params: "734,350", precision: "43.99%", recall: "87.15%", f1: "58.46%", fpr: "20.95%", onsetRecall: "96.6% (28/29)", faWin: "359.76", faInc: "14.12", stateMae: "0.1930" },
  { model: "Two-Stage Operational SOC", variant: "Scout + Gate + Agg", params: "615,248", precision: "98.42%", recall: "100.0%", f1: "99.20%", fpr: "21.04%", onsetRecall: "100% (29/29)", faWin: "350.20", faInc: "0.07", stateMae: "0.1909", highlight: true },
];

const SETTING_B_ROWS: BenchmarkRow[] = [
  { model: "Majority", variant: "Constant 0", params: "0", precision: "0.00%", recall: "0.00%", f1: "0.00%", fpr: "0.00%", onsetRecall: "0% (0/7)", faWin: "0.00", faInc: "0.00", stateMae: "—" },
  { model: "Persistence", variant: "yt+10 = yt", params: "0", precision: "99.66%", recall: "99.66%", f1: "99.66%", fpr: "0.00%", onsetRecall: "0% (0/7)", faWin: "0.00", faInc: "0.00", stateMae: "—" },
  { model: "Logistic Regression", variant: "Static 54D", params: "55", precision: "41.18%", recall: "84.18%", f1: "55.31%", fpr: "49.35%", onsetRecall: "100% (7/7)", faWin: "888.35", faInc: "17.02", stateMae: "—" },
  { model: "Random Forest", variant: "Static 54D", params: "250k", precision: "40.90%", recall: "88.79%", f1: "56.00%", fpr: "52.67%", onsetRecall: "100% (7/7)", faWin: "948.12", faInc: "4.99", stateMae: "—" },
  { model: "Temporal GRU", variant: "10-Step Seq", params: "239,517", precision: "44.44%", recall: "55.72%", f1: "49.44%", fpr: "28.56%", onsetRecall: "57.1% (4/7)", faWin: "514.18", faInc: "26.17", stateMae: "0.2640" },
  { model: "Temporal Transformer", variant: "10-Step Seq", params: "341,789", precision: "36.63%", recall: "16.97%", f1: "23.19%", fpr: "12.06%", onsetRecall: "28.6% (2/7)", faWin: "217.20", faInc: "28.14", stateMae: "0.2707" },
  { model: "SparseRSSM", variant: "Raw AR Rollout", params: "214,334", precision: "46.71%", recall: "31.08%", f1: "37.32%", fpr: "14.55%", onsetRecall: "42.9% (3/7)", faWin: "261.93", faInc: "12.44", stateMae: "0.2841" },
  { model: "TFCNet-F", variant: "Raw Spectral", params: "400,914", precision: "38.14%", recall: "99.67%", f1: "55.17%", fpr: "66.40%", onsetRecall: "100% (7/7)", faWin: "1195.19", faInc: "38.12", stateMae: "0.2557" },
  { model: "Two-Stage Operational SOC", variant: "Scout + Gate + Agg", params: "615,248", precision: "96.88%", recall: "100.0%", f1: "98.41%", fpr: "67.42%", onsetRecall: "100% (7/7)", faWin: "1213.51", faInc: "0.12", stateMae: "0.2510", highlight: true },
];

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

  const [activeRegime, setActiveRegime] = useState<"C" | "A" | "B">("C");
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
        <span>Loading benchmark dataâ€¦</span>
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

  const currentRows =
    activeRegime === "C" ? SETTING_C_ROWS : activeRegime === "A" ? SETTING_A_ROWS : SETTING_B_ROWS;

  return (
    <>
      <PageTitle
        title="Model benchmarks & research validation"
        note="Verbatim experimental record from CSE-CIC-IDS2018 (8.28M flows, 188.5k windows) evaluated across seen, mixed, and unseen-family OOD regimes."
      />

      {/* â”€â”€ Key Research Highlights Summary â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4 mb-5">
        <div className="rounded-xl border border-teal/40 bg-void-900/80 p-4 shadow-sm backdrop-blur-md">
          <div className="flex items-center gap-2 text-teal font-mono text-xs font-semibold">
            <Zap className="size-4" />
            <span>Onset Recall Lead</span>
          </div>
          <p className="mt-2 text-2xl font-bold font-display text-paper">100.0%</p>
          <p className="mt-1 text-xs text-fog font-mono">
            29/29 (Setting A) & 7/7 (Setting C) at 20s lead
          </p>
        </div>

        <div className="rounded-xl border border-teal/40 bg-void-900/80 p-4 shadow-sm backdrop-blur-md">
          <div className="flex items-center gap-2 text-teal font-mono text-xs font-semibold">
            <CheckCircle2 className="size-4" />
            <span>Incident F1 Score</span>
          </div>
          <p className="mt-2 text-2xl font-bold font-display text-paper">98.41%</p>
          <p className="mt-1 text-xs text-fog font-mono">
            96.88% precision on zero-day unseen attack families
          </p>
        </div>

        <div className="rounded-xl border border-amber/40 bg-void-900/80 p-4 shadow-sm backdrop-blur-md">
          <div className="flex items-center gap-2 text-amber font-mono text-xs font-semibold">
            <ShieldAlert className="size-4" />
            <span>False Alarm Collapse</span>
          </div>
          <p className="mt-2 text-2xl font-bold font-display text-paper">0.12 / hr</p>
          <p className="mt-1 text-xs text-fog font-mono">
            1,190/h window alarms collapsed to ~1 alert / 8 hours
          </p>
        </div>

        <div className="rounded-xl border border-fog-deep bg-void-900/80 p-4 shadow-sm backdrop-blur-md">
          <div className="flex items-center gap-2 text-paper font-mono text-xs font-semibold">
            <Cpu className="size-4" />
            <span>Parameter Budget</span>
          </div>
          <p className="mt-2 text-2xl font-bold font-display text-paper">615,248</p>
          <p className="mt-1 text-xs text-fog font-mono">
            400,914 TFCNet-F + 214,334 SparseRSSM + 0 rule
          </p>
        </div>
      </div>

      {/* â”€â”€ Master Architecture Benchmark Suite (Table V, VI, VII) â”€â”€â”€ */}
      <FlatPanel
        title="Master benchmark suite (CSE-CIC-IDS2018)"
        control={
          <div className="flex flex-wrap items-center gap-1.5 rounded-lg border border-fog-deep/60 bg-void-950 p-1 text-xs font-mono">
            <button
              onClick={() => setActiveRegime("C")}
              className={`rounded px-2.5 py-1 font-semibold transition-all ${
                activeRegime === "C"
                  ? "bg-teal text-void-950 shadow-xs"
                  : "text-fog hover:text-paper"
              }`}
            >
              Setting C (Zero-Day OOD)
            </button>
            <button
              onClick={() => setActiveRegime("A")}
              className={`rounded px-2.5 py-1 font-semibold transition-all ${
                activeRegime === "A"
                  ? "bg-teal text-void-950 shadow-xs"
                  : "text-fog hover:text-paper"
              }`}
            >
              Setting A (In-Distribution)
            </button>
            <button
              onClick={() => setActiveRegime("B")}
              className={`rounded px-2.5 py-1 font-semibold transition-all ${
                activeRegime === "B"
                  ? "bg-teal text-void-950 shadow-xs"
                  : "text-fog hover:text-paper"
              }`}
            >
              Setting B (Mixed)
            </button>
          </div>
        }
        bodyClassName="p-0 overflow-x-auto scrollbar-none [scrollbar-width:none] [-ms-overflow-style:none] [&::-webkit-scrollbar]:hidden"
      >
        <div className="px-5 py-2.5 bg-void-950/60 border-b border-fog-deep/40 text-xs font-mono text-fog flex flex-wrap justify-between items-center gap-2">
          <span>
            {activeRegime === "C" && "Table VII: Setting C — Zero-day unseen-family OOD holdout (Infiltration + Botnet ARES, 7 episodes, K=10, 20s lead)"}
            {activeRegime === "A" && "Table V: Setting A — Seen in-distribution master benchmark (29 attack episodes, K=10, 20s lead)"}
            {activeRegime === "B" && "Table VI: Setting B — Mixed-generalisation master benchmark (7 attack episodes, K=10, 20s lead)"}
          </span>
          <span className="text-teal font-semibold">Lead Horizon K=10 (20.0s)</span>
        </div>
        <table className="w-full text-left text-xs font-mono min-w-[760px]">
          <thead className="text-fog border-b border-fog-deep/60 bg-void-950/40">
            <tr>
              <th className="px-4 py-2.5 font-medium">Model Architecture</th>
              <th className="px-3 py-2.5 font-medium">Variant</th>
              <th className="px-3 py-2.5 text-right font-medium">Params</th>
              <th className="px-3 py-2.5 text-right font-medium">Precision</th>
              <th className="px-3 py-2.5 text-right font-medium">Recall</th>
              <th className="px-3 py-2.5 text-right font-medium">Incident F1</th>
              <th className="px-3 py-2.5 text-right font-medium">Onset Recall</th>
              <th className="px-3 py-2.5 text-right font-medium">FA/hr (Win)</th>
              <th className="px-3 py-2.5 text-right font-medium">FA/hr (Inc)</th>
              <th className="px-4 py-2.5 text-right font-medium">State MAE</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-fog-deep/30">
            {currentRows.map((r, i) => (
              <tr
                key={i}
                className={`transition-colors ${
                  r.highlight
                    ? "bg-teal/15 font-bold text-paper border-t-2 border-teal/70"
                    : "hover:bg-paper/5 text-paper/85"
                }`}
              >
                <td className="px-4 py-2.5 flex items-center gap-2">
                  {r.highlight && <span className="size-2 rounded-full bg-teal animate-pulse" />}
                  <span>{r.model}</span>
                </td>
                <td className="px-3 py-2.5 text-fog">{r.variant}</td>
                <td className="px-3 py-2.5 text-right text-fog">{r.params}</td>
                <td className="px-3 py-2.5 text-right">{r.precision}</td>
                <td className="px-3 py-2.5 text-right">{r.recall}</td>
                <td className={`px-3 py-2.5 text-right ${r.highlight ? "text-teal" : ""}`}>{r.f1}</td>
                <td className={`px-3 py-2.5 text-right ${r.onsetRecall.startsWith("100") ? "text-teal" : "text-amber"}`}>
                  {r.onsetRecall}
                </td>
                <td className="px-3 py-2.5 text-right text-fog">{r.faWin}</td>
                <td className={`px-3 py-2.5 text-right ${r.highlight ? "text-teal font-bold" : "text-crimson"}`}>
                  {r.faInc}
                </td>
                <td className="px-4 py-2.5 text-right text-fog">{r.stateMae}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </FlatPanel>

      <div className="mt-5 grid gap-5 lg:grid-cols-[minmax(0,1.1fr)_minmax(0,1fr)]">
        {/* â”€â”€ Head-to-Head Comparison â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */}
        <FlatPanel title="Production model versus baseline" bodyClassName="p-0 overflow-x-auto">
          <table className="w-full min-w-[560px] text-left">
            <thead className="text-[12px] text-fog">
              <tr className="border-b border-fog-deep/60">
                <th className="px-5 py-2.5 font-medium">Metric</th>
                <th className="px-5 py-2.5 text-right font-medium">Two-Stage SOC · OOD (C)</th>
                <th className="px-5 py-2.5 text-right font-medium">LR · OOD (C)</th>
                <th className="px-5 py-2.5 text-right font-medium">Two-Stage SOC · Seen (A)</th>
                <th className="px-5 py-2.5 text-right font-medium">LR · Seen (A)</th>
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
          <div className="p-4 bg-void-950/40 border-t border-fog-deep/40 text-xs font-mono text-fog">
            <p>
              <strong className="text-paper">Operational Takeaway:</strong> While static Logistic Regression and Random Forest obtain 100% onset recall in OOD, they do so at 49.35%â€“52.67% FPR (888â€“948 FA/hr), flooding SOC operators. Two-Stage SOC matches 100% onset recall while delivering a <strong>140Ã— reduction</strong> in false alerts down to 0.12 FA/hr.
            </p>
          </div>
        </FlatPanel>

        {/* â”€â”€ Confusion matrices from final.pdf â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */}
        <FlatPanel
          title="Confusion matrices (incident-level verification)"
          control={<span className="mono text-fog">CSE-CIC-IDS2018</span>}
        >
          <div className="grid gap-6 sm:grid-cols-2">
            {bench.matrices.map((m) => (
              <div key={m.name} className="rounded-lg border border-fog-deep/30 bg-void-950/50 p-3">
                <div className="grid grid-cols-2 gap-1.5">
                  {m.cells.map((c, i) => {
                    const label = i === 0 ? "TN" : i === 1 ? "FP" : i === 2 ? "FN" : "TP";
                    const isPositive = i === 0 || i === 3;
                    return (
                      <div
                        key={i}
                        className="mono rounded-[6px] px-3 py-3 text-center transition-transform hover:scale-102"
                        style={{
                          background: isPositive
                            ? "color-mix(in oklab, var(--signal-teal) 18%, transparent)"
                            : "color-mix(in oklab, var(--critical-crimson) 18%, transparent)",
                          border: isPositive
                            ? "1px solid color-mix(in oklab, var(--signal-teal) 35%, transparent)"
                            : "1px solid color-mix(in oklab, var(--critical-crimson) 35%, transparent)",
                        }}
                      >
                        <div className="text-[10px] uppercase font-mono text-fog tracking-wider">{label}</div>
                        <div className="text-lg font-bold text-paper mt-0.5">{c}</div>
                      </div>
                    );
                  })}
                </div>
                <p className="mt-2.5 text-[11px] font-mono text-fog leading-tight">{m.name}</p>
              </div>
            ))}
          </div>
          <div className="mt-4 pt-3 border-t border-fog-deep/30 text-[11px] font-mono text-fog flex justify-between">
            <span>Matrix format: [TN, FP, FN, TP]</span>
            <span className="text-teal font-semibold">Zero False Negatives in Setting C & A</span>
          </div>
        </FlatPanel>
      </div>

      {/* â”€â”€ Capability Matrix (Table XI) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */}
      <FlatPanel className="mt-5" title="Architectural capability matrix (Table XI)" bodyClassName="p-0 overflow-x-auto scrollbar-none [scrollbar-width:none] [-ms-overflow-style:none] [&::-webkit-scrollbar]:hidden">
        <table className="w-full text-left text-xs font-mono">
          <thead className="text-fog border-b border-fog-deep/60 bg-void-950/40">
            <tr>
              <th className="px-5 py-2.5 font-medium">Model Architecture</th>
              <th className="px-4 py-2.5 text-center font-medium">Temporal Memory</th>
              <th className="px-4 py-2.5 text-center font-medium">Latent Dynamics</th>
              <th className="px-4 py-2.5 text-center font-medium">Frequency Domain</th>
              <th className="px-4 py-2.5 text-center font-medium">Variable Attention</th>
              <th className="px-4 py-2.5 text-center font-medium">Autoregressive (AR)</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-fog-deep/30">
            <tr className="hover:bg-paper/4">
              <td className="px-5 py-2.5 text-fog">Logistic Regression</td>
              <td className="px-4 py-2.5 text-center text-fog">âœ—</td>
              <td className="px-4 py-2.5 text-center text-fog">âœ—</td>
              <td className="px-4 py-2.5 text-center text-fog">âœ—</td>
              <td className="px-4 py-2.5 text-center text-fog">âœ—</td>
              <td className="px-4 py-2.5 text-center text-fog">âœ—</td>
            </tr>
            <tr className="hover:bg-paper/4">
              <td className="px-5 py-2.5 text-fog">Random Forest</td>
              <td className="px-4 py-2.5 text-center text-fog">âœ—</td>
              <td className="px-4 py-2.5 text-center text-fog">âœ—</td>
              <td className="px-4 py-2.5 text-center text-fog">âœ—</td>
              <td className="px-4 py-2.5 text-center text-fog">âœ—</td>
              <td className="px-4 py-2.5 text-center text-fog">âœ—</td>
            </tr>
            <tr className="hover:bg-paper/4">
              <td className="px-5 py-2.5 text-paper">Temporal GRU</td>
              <td className="px-4 py-2.5 text-center text-teal">âœ“</td>
              <td className="px-4 py-2.5 text-center text-fog">âœ—</td>
              <td className="px-4 py-2.5 text-center text-fog">âœ—</td>
              <td className="px-4 py-2.5 text-center text-fog">âœ—</td>
              <td className="px-4 py-2.5 text-center text-fog">âœ—</td>
            </tr>
            <tr className="hover:bg-paper/4">
              <td className="px-5 py-2.5 text-paper">Temporal Transformer</td>
              <td className="px-4 py-2.5 text-center text-teal">âœ“</td>
              <td className="px-4 py-2.5 text-center text-fog">âœ—</td>
              <td className="px-4 py-2.5 text-center text-fog">âœ—</td>
              <td className="px-4 py-2.5 text-center text-fog">âœ—</td>
              <td className="px-4 py-2.5 text-center text-fog">âœ—</td>
            </tr>
            <tr className="hover:bg-paper/4">
              <td className="px-5 py-2.5 text-paper">SparseRSSM</td>
              <td className="px-4 py-2.5 text-center text-teal">âœ“</td>
              <td className="px-4 py-2.5 text-center text-teal">âœ“</td>
              <td className="px-4 py-2.5 text-center text-fog">âœ—</td>
              <td className="px-4 py-2.5 text-center text-fog">âœ—</td>
              <td className="px-4 py-2.5 text-center text-teal">âœ“</td>
            </tr>
            <tr className="hover:bg-paper/4">
              <td className="px-5 py-2.5 text-paper">TFCNet-F</td>
              <td className="px-4 py-2.5 text-center text-teal">âœ“</td>
              <td className="px-4 py-2.5 text-center text-fog">âœ—</td>
              <td className="px-4 py-2.5 text-center text-teal">âœ“</td>
              <td className="px-4 py-2.5 text-center text-teal">âœ“</td>
              <td className="px-4 py-2.5 text-center text-fog">âœ—</td>
            </tr>
            <tr className="bg-teal/15 font-bold text-paper border-t-2 border-teal/70">
              <td className="px-5 py-2.5 flex items-center gap-2">
                <span className="size-2 rounded-full bg-teal" />
                Two-Stage Operational SOC (Production)
              </td>
              <td className="px-4 py-2.5 text-center text-teal">âœ“</td>
              <td className="px-4 py-2.5 text-center text-teal">âœ“</td>
              <td className="px-4 py-2.5 text-center text-teal">âœ“</td>
              <td className="px-4 py-2.5 text-center text-teal">âœ“</td>
              <td className="px-4 py-2.5 text-center text-teal">âœ“</td>
            </tr>
          </tbody>
        </table>
      </FlatPanel>

      {/* â”€â”€ Loss curve â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */}
      <HeroPanel
        className="mt-5"
        title="Training and validation loss progression"
        control={
          <select
            value={selectedId ?? selectedVersion?._id ?? ""}
            onChange={(e) => setSelectedId(e.target.value)}
            className="mono rounded-md border border-fog-deep bg-void-700 px-2.5 py-1.5 outline-none text-xs text-paper"
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

      {/* â”€â”€ Version history â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */}
      <FlatPanel className="mt-5" title="Model registry & deployment history">
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
                  className="mono hover:text-teal transition-colors font-medium"
                >
                  {v.version}
                </button>
                <span className="mono text-fog text-xs">
                  {new Date(v.releasedAt).toISOString().slice(0, 10)}
                </span>
                <span className="text-[13px] text-fog">{v.note}</span>
                {v.isProduction ? (
                  <span className="text-[11px] text-teal font-mono bg-teal/15 px-2 py-0.5 rounded border border-teal/40">
                    active production
                  </span>
                ) : (
                  <ActionButton
                    variant="ghost"
                    className="py-1 text-xs"
                    disabled={promote.isPending}
                    onClick={() => handlePromote(v)}
                  >
                    {promote.isPending ? (
                      <span className="flex items-center gap-1.5">
                        <Loader2 className="size-3 animate-spin" /> Promotingâ€¦
                      </span>
                    ) : (
                      "Promote to production"
                    )}
                  </ActionButton>
                )}
                <span className="mono ml-auto text-[12px] text-fog">
                  F1 {v.metrics.cicIds.f1.toFixed(4)} · FPR {v.metrics.cicIds.fpr.toFixed(4)}
                </span>
              </div>
            </li>
          ))}
        </ol>
      </FlatPanel>
    </>
  );
}
