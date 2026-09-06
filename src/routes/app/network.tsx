import { useState } from "react";
import { createFileRoute, Link } from "@tanstack/react-router";
import { X } from "lucide-react";
import { HeroPanel, PageTitle, RiskBadge } from "@/components/app/panels";
import { NetworkGraph, graphNodes } from "@/components/app/charts";
import { pageHead } from "@/lib/head";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/app/network")({
  head: pageHead(
    "Network state — Aegis Vantage",
    "Live host and flow graph with a time scrubber across historical and forecast network states.",
  ),
  component: NetworkState,
});

function NetworkState() {
  const [view, setView] = useState<"flow" | "packet">("flow");
  const [scrub, setScrub] = useState(100);
  const [selected, setSelected] = useState<string | null>(null);
  const node = graphNodes.find((n) => n.id === selected);

  return (
    <>
      <PageTitle
        title="Network state"
        note="Node size tracks traffic volume, colour tracks predicted risk. Drag the scrubber to move through past and forecast windows."
      />

      <div className="grid gap-5 lg:grid-cols-[220px_minmax(0,1fr)]">
        <div className="flat h-fit p-4">
          <p className="text-[13px] font-medium">View level</p>
          <div className="mt-2 flex flex-col gap-1">
            {(["flow", "packet"] as const).map((v) => (
              <button
                key={v}
                onClick={() => setView(v)}
                className={cn(
                  "rounded-md px-3 py-1.5 text-left text-[13px] font-medium",
                  view === v ? "bg-teal/12 text-teal" : "text-fog hover:text-paper",
                )}
              >
                {v === "flow" ? "Flow level" : "Packet level"}
              </button>
            ))}
          </div>
          <p className="mt-5 text-[13px] font-medium">Segment</p>
          <select className="mono mt-2 w-full rounded-md border border-fog-deep bg-void-700 px-2.5 py-1.5 outline-none">
            <option>all segments</option>
            <option>corp-core</option>
            <option>finance</option>
            <option>dmz-edge</option>
          </select>
        </div>

        <HeroPanel
          title="Host and flow graph"
          state="critical"
          control={
            <span className="mono text-fog">
              {scrub === 100 ? "now" : `t−${((100 - scrub) * 1.2).toFixed(0)}m`}
            </span>
          }
          bodyClassName="p-0"
        >
          <div className="p-5">
            <NetworkGraph
              onSelect={(id) => setSelected(id)}
              selected={selected ?? undefined}
              scrub={scrub}
            />
          </div>
          <div className="flex items-center gap-4 border-t border-[var(--glass-border)] bg-void-800/70 px-5 py-3">
            <span className="mono text-fog">10:40Z</span>
            <input
              type="range"
              min={0}
              max={100}
              value={scrub}
              onChange={(e) => setScrub(Number(e.target.value))}
              aria-label="Time scrubber"
              className="w-full accent-teal"
            />
            <span className="mono text-fog">+40m forecast</span>
          </div>
        </HeroPanel>
      </div>

      {node ? (
        <aside className="fixed inset-y-0 right-0 z-30 w-[380px] overflow-y-auto border-l border-fog-deep bg-void-800 p-5">
          <div className="flex items-start justify-between">
            <div>
              <p className="mono text-[15px]">{node.id}</p>
              <div className="mt-2">
                <RiskBadge state={node.state} />
              </div>
            </div>
            <button
              onClick={() => setSelected(null)}
              aria-label="Close host detail"
              className="text-fog hover:text-paper"
            >
              <X className="size-4" />
            </button>
          </div>

          <dl className="mt-6 space-y-3">
            {[
              ["Risk score", node.state === "critical" ? "0.88" : node.state === "watch" ? "0.54" : "0.11"],
              ["Active flows", `${node.size * 31}`],
              ["Bytes / 5m", `${(node.size * 0.42).toFixed(2)} GB`],
              ["First seen", "2026-08-14"],
            ].map(([k, v]) => (
              <div key={k} className="flex justify-between border-b border-fog-deep/40 pb-2">
                <dt className="text-[13px] text-fog">{k}</dt>
                <dd className="mono">{v}</dd>
              </div>
            ))}
          </dl>

          <p className="mt-6 text-[13px] font-medium">Recent flows</p>
          <ul className="mono mt-2 space-y-1.5 text-fog">
            <li>→ 10.24.8.14:445 1.28 MB</li>
            <li>→ 10.24.8.19:445 0.91 MB</li>
            <li>→ 10.24.8.22:445 0.88 MB</li>
          </ul>

          <Link
            to="/app/explainability"
            className="mt-6 inline-block text-[13px] text-teal"
          >
            View explainability
          </Link>
        </aside>
      ) : null}
    </>
  );
}
