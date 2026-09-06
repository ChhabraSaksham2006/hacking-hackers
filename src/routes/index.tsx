import { createFileRoute, Link } from "@tanstack/react-router";
import { HeroPanel, RiskBadge } from "@/components/app/panels";
import { ProbabilityTimeline, Sparkline } from "@/components/app/charts";
import { pageHead } from "@/lib/head";
import { probabilitySeries } from "@/lib/telemetry";

export const Route = createFileRoute("/")({
  head: pageHead(
    "Aegis Vantage — Forecast attacker progression",
    "A world model that learns how your network's state evolves and forecasts compromise before the kill chain completes.",
  ),
  component: Landing,
});

function Landing() {
  return (
    <div className="network-field min-h-screen">
      <header className="flex h-14 items-center justify-between border-b border-fog-deep/50 px-6 md:px-10">
        <div className="flex items-center gap-3">
          <span className="size-[18px] rotate-45 rounded-[4px] border-2 border-teal" />
          <span className="font-display text-[15px] font-semibold">
            Aegis Vantage
          </span>
        </div>
        <nav className="flex items-center gap-2 text-[13px] font-medium">
          <Link
            to="/login"
            className="rounded-md border border-fog-deep px-3.5 py-2 hover:bg-void-700"
          >
            Log in
          </Link>
          <Link
            to="/signup"
            className="rounded-md bg-teal px-3.5 py-2 text-void-900 hover:bg-teal/85"
          >
            Sign up
          </Link>
        </nav>
      </header>

      <main className="mx-auto max-w-[1320px] px-6 md:px-10">
        <section className="grid items-center gap-10 py-16 lg:grid-cols-[minmax(0,0.8fr)_minmax(0,1.2fr)]">
          <div>
            <h1 className="font-display text-[40px] leading-[1.1] font-semibold">
              Forecasts attacker progression before compromise completes
            </h1>
            <p className="mt-5 max-w-[62ch] text-[15px] text-fog">
              Aegis Vantage runs a temporal world model over your flow and
              packet telemetry. It learns how your network's state evolves, then
              projects the current trajectory forward — so an analyst sees
              lateral movement forming instead of reading about it afterwards.
            </p>
            <div className="mt-8 flex items-center gap-3">
              <Link
                to="/signup"
                className="rounded-md bg-teal px-4 py-2.5 text-[13px] font-medium text-void-900 hover:bg-teal/85"
              >
                Sign up
              </Link>
              <Link
                to="/app/dashboard"
                className="rounded-md border border-fog-deep px-4 py-2.5 text-[13px] font-medium hover:bg-void-700"
              >
                Open the live demo
              </Link>
            </div>
          </div>

          <HeroPanel
            title="Infiltration probability — corp-core"
            state="critical"
            control={
              <>
                <RiskBadge state="critical" />
                <span className="mono text-fog">last 4h</span>
              </>
            }
          >
            <div className="mb-4 flex items-end gap-8">
              <div>
                <p className="font-display text-[40px] leading-none font-semibold text-crimson">
                  0.88
                </p>
                <p className="mt-1 text-[12px] text-fog">
                  probability of compromise, window 14:35–14:40Z
                </p>
              </div>
              <div>
                <p className="mono text-paper">+0.31 / 30m</p>
                <p className="mt-1 text-[12px] text-fog">trajectory slope</p>
              </div>
            </div>
            <ProbabilityTimeline series={probabilitySeries} height={240} />
          </HeroPanel>
        </section>

        <section className="grid gap-10 border-t border-fog-deep/40 py-14 md:grid-cols-2">
          <div>
            <h2 className="font-display text-[20px] font-medium">
              Static classifiers see one flow at a time
            </h2>
            <p className="mt-3 max-w-[70ch] text-[15px] text-fog">
              A per-flow model scores each connection in isolation. A slow scan,
              a single SMB session and one outbound upload each look ordinary, so
              the detection only fires once the damage is already recorded.
            </p>
          </div>
          <div>
            <h2 className="font-display text-[20px] font-medium">
              A world model learns how your network's state evolves
            </h2>
            <p className="mt-3 max-w-[70ch] text-[15px] text-fog">
              Aegis Vantage encodes the whole segment state per time window and
              predicts the next K windows. Rising probability is a forecast about
              where the sequence is going, not a verdict about one packet.
            </p>
            <div className="mt-5 flex items-center gap-4">
              <Sparkline
                series={[0.1, 0.12, 0.11, 0.13, 0.12, 0.14, 0.13]}
                color="var(--fog-400)"
              />
              <span className="mono text-fog">per-flow score</span>
            </div>
            <div className="mt-2 flex items-center gap-4">
              <Sparkline series={[0.1, 0.2, 0.3, 0.42, 0.58, 0.74, 0.88]} />
              <span className="mono text-teal">state trajectory</span>
            </div>
          </div>
        </section>

        <section className="grid gap-4 border-t border-fog-deep/40 py-14 md:grid-cols-3">
          {[
            {
              title: "Flow and packet ingestion",
              body: "PCAP and NetFlow/IPFIX land in the same feature pipeline — parsing, extraction, normalisation, inference.",
              glyph: <Sparkline series={[0.2, 0.5, 0.3, 0.7, 0.4, 0.8, 0.6]} />,
            },
            {
              title: "Temporal world model",
              body: "A sequence model over segment state windows, forecasting K steps ahead with a calibrated probability.",
              glyph: <Sparkline series={[0.1, 0.25, 0.4, 0.55, 0.7, 0.82, 0.9]} />,
            },
            {
              title: "Explainable predictions",
              body: "Every prediction ships feature contributions, raw values and the ATT&CK stage it maps to.",
              glyph: (
                <svg viewBox="0 0 120 32" className="h-8 w-[120px]" aria-hidden="true">
                  {[22, 16, 11, 7].map((w, i) => (
                    <rect
                      key={i}
                      x="0"
                      y={i * 8}
                      width={w * 4}
                      height="4"
                      fill="var(--signal-teal)"
                      opacity={1 - i * 0.2}
                    />
                  ))}
                </svg>
              ),
            },
          ].map((c) => (
            <div key={c.title} className="flat p-5">
              {c.glyph}
              <h3 className="mt-4 font-display text-[20px] font-medium">
                {c.title}
              </h3>
              <p className="mt-2 text-[15px] text-fog">{c.body}</p>
            </div>
          ))}
        </section>

        <section className="flex flex-wrap items-center gap-x-8 gap-y-3 border-t border-fog-deep/40 py-8 text-[13px] text-fog">
          <span>Evaluated on</span>
          <span className="mono">CIC-IDS-2018</span>
          <span className="mono">CTU-13</span>
          <span>Mapped to</span>
          <span className="mono">MITRE ATT&amp;CK</span>
        </section>
      </main>

      <footer className="border-t border-fog-deep/40 px-6 py-8 text-[13px] text-fog md:px-10">
        <div className="mx-auto flex max-w-[1320px] flex-wrap gap-6">
          <span>Contact us</span>
          <span>Privacy policy</span>
          <span>Terms of service</span>
        </div>
      </footer>
    </div>
  );
}
