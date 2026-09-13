import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { FlatPanel, HeroPanel, PageTitle, RiskBadge } from "@/components/app/panels";
import { pageHead } from "@/lib/head";
import { stateColorVar } from "@/lib/telemetry";
import { useSegments } from "@/hooks/useApi";

export const Route = createFileRoute("/app/topology")({
  head: pageHead(
    "Topology overview — Aegis Vantage",
    "Organisation-wide segment map sized by traffic volume and coloured by current predicted risk.",
  ),
  component: Topology,
});

function Topology() {
  const navigate = useNavigate();
  const { data: segments = [] } = useSegments();
  const total = segments.reduce((s, x) => s + x.trafficVolume, 0);

  return (
    <>
      <PageTitle
        title="Topology overview"
        note="Each tile is a monitored segment. Tile area tracks share of traffic; colour tracks current risk state."
      />

      <div className="grid gap-5 lg:grid-cols-[minmax(0,1.5fr)_minmax(0,1fr)]">
        <HeroPanel title="Monitored segments" state="critical">
          <div className="flex flex-wrap gap-2">
            {segments.map((s) => (
              <button
                key={s.name}
                onClick={() => navigate({ to: "/app/network" })}
                className="rounded-[10px] border p-4 text-left transition-colors hover:brightness-125"
                style={{
                  flexBasis: `${Math.max(22, (s.trafficVolume / (total || 1)) * 260)}%`,
                  minHeight: 96 + s.trafficVolume * 2,
                  borderColor: `color-mix(in oklab, ${stateColorVar[s.state]} 40%, transparent)`,
                  background: `color-mix(in oklab, ${stateColorVar[s.state]} 14%, transparent)`,
                }}
              >
                <p className="mono">{s.name}</p>
                <p className="mt-1 text-[12px] text-fog">
                  {s.hosts} hosts · {s.trafficVolume}% of traffic
                </p>
                <div className="mt-3">
                  <RiskBadge state={s.state} />
                </div>
              </button>
            ))}
          </div>
        </HeroPanel>

        <FlatPanel title="Segment list" bodyClassName="p-0">
          <table className="w-full text-left">
            <thead className="text-[12px] text-fog">
              <tr className="border-b border-fog-deep/60">
                <th className="px-5 py-2.5 font-medium">Segment</th>
                <th className="px-5 py-2.5 text-right font-medium">Hosts</th>
                <th className="px-5 py-2.5 text-right font-medium">Alerts</th>
                <th className="px-5 py-2.5 font-medium">Last incident</th>
              </tr>
            </thead>
            <tbody>
              {segments.map((s) => (
                <tr
                  key={s.name}
                  className="border-b border-fog-deep/40 last:border-0 hover:bg-paper/4"
                >
                  <td className="mono px-5 py-2.5">
                    <Link to="/app/network" className="hover:text-teal">
                      {s.name}
                    </Link>
                  </td>
                  <td className="mono px-5 py-2.5 text-right">{s.hosts}</td>
                  <td className="mono px-5 py-2.5 text-right">{s.activeAlerts}</td>
                  <td className="mono px-5 py-2.5 text-fog">{s.lastIncident}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </FlatPanel>
      </div>
    </>
  );
}
