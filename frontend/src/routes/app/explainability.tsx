import { createFileRoute } from "@tanstack/react-router";
import { FlatPanel, HeroPanel, PageTitle, RiskBadge } from "@/components/app/panels";
import { pageHead } from "@/lib/head";
import { featureContributions } from "@/lib/telemetry";

export const Route = createFileRoute("/app/explainability")({
  head: pageHead(
    "Explainability — Aegis Vantage",
    "Feature contributions, raw values and a plain-language summary behind a single prediction.",
  ),
  component: Explainability,
});

function Explainability() {
  const max = Math.max(...featureContributions.map((f) => Math.abs(f.weight)));

  return (
    <>
      <PageTitle title="Explainability" />

      <div className="flat mb-5 flex flex-wrap items-center gap-x-8 gap-y-3 px-5 py-4">
        <div>
          <p className="mono">2026-09-06 14:35–14:40Z</p>
          <p className="mt-1 text-[12px] text-fog">prediction window</p>
        </div>
        <div>
          <RiskBadge state="critical" label="Lateral movement" />
          <p className="mt-1 text-[12px] text-fog">predicted ATT&amp;CK stage</p>
        </div>
        <div>
          <p className="font-display text-[28px] leading-none font-semibold text-crimson">
            0.88
          </p>
          <p className="mt-1 text-[12px] text-fog">probability score</p>
        </div>
      </div>

      <HeroPanel
        title="Feature contributions"
        state="critical"
        control={<span className="mono text-fog">SHAP · window 14:35Z</span>}
      >
        <ul className="space-y-3">
          {featureContributions.map((f) => {
            const pct = (Math.abs(f.weight) / max) * 100;
            const positive = f.weight > 0;
            return (
              <li key={f.feature} className="grid grid-cols-[220px_1fr_90px] items-center gap-4">
                <span className="text-[15px]">{f.feature}</span>
                <span className="relative flex h-3 items-center">
                  <span
                    className="h-3 rounded-[3px]"
                    style={{
                      width: `${pct}%`,
                      background: positive
                        ? "var(--critical-crimson)"
                        : "var(--signal-teal)",
                      opacity: 0.85,
                    }}
                  />
                </span>
                <span className="mono text-right">
                  {f.weight > 0 ? "+" : ""}
                  {f.weight.toFixed(2)}
                </span>
              </li>
            );
          })}
        </ul>
        <p className="mt-5 text-[12px] text-fog">
          Crimson bars push the window toward compromise; teal bars pull it back
          toward normal.
        </p>
      </HeroPanel>

      <div className="mt-5 grid gap-5 lg:grid-cols-2">
        <FlatPanel title="Raw feature values" bodyClassName="p-0">
          <table className="w-full text-left">
            <tbody>
              {featureContributions.map((f) => (
                <tr
                  key={f.feature}
                  className="border-b border-fog-deep/40 last:border-0 hover:bg-paper/4"
                >
                  <td className="mono px-5 py-2.5 text-fog">{f.feature}</td>
                  <td className="mono px-5 py-2.5 text-right">{f.value}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </FlatPanel>

        <FlatPanel title="Summary">
          <p className="max-w-[70ch] text-[15px]">
            This window was flagged primarily due to elevated SYN/ACK ratio and
            sequential port access on ports 22, 23 and 445, combined with 14 SMB
            session setups from fin-db-02 to distinct hosts inside 90 seconds.
            Flow duration and TTL variance argue slightly against compromise but
            do not offset the session fan-out.
          </p>
          <p className="mt-4 max-w-[70ch] text-[15px] text-fog">
            The same feature pattern preceded two confirmed lateral-movement
            incidents in this segment during the last 30 days.
          </p>
        </FlatPanel>
      </div>
    </>
  );
}
