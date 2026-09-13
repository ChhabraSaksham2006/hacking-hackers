import { Fragment, useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { FlatPanel, PageTitle } from "@/components/app/panels";
import { pageHead } from "@/lib/head";
import { useFlows } from "@/hooks/useApi";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/app/explorer")({
  head: pageHead(
    "Flow explorer — Aegis Vantage",
    "Dense flow and packet reference table with per-flow feature values and packet sequences.",
  ),
  component: Explorer,
});

const columns = [
  { key: "src", label: "Source", align: "left" },
  { key: "dst", label: "Destination", align: "left" },
  { key: "proto", label: "Proto", align: "left" },
  { key: "flags", label: "Flags", align: "left" },
  { key: "bytes", label: "Bytes", align: "right" },
  { key: "packets", label: "Packets", align: "right" },
  { key: "duration", label: "Duration", align: "right" },
  { key: "iatMean", label: "IAT mean", align: "right" },
  { key: "iatVar", label: "IAT var", align: "right" },
  { key: "iatMax", label: "IAT max", align: "right" },
  { key: "ttlVar", label: "TTL var", align: "right" },
  { key: "window", label: "Win size", align: "right" },
  { key: "retrans", label: "Retrans", align: "right" },
  { key: "score", label: "Score", align: "right" },
] as const;

function Explorer() {
  const [flaggedOnly, setFlaggedOnly] = useState(false);
  const [minScore, setMinScore] = useState(0);
  const [search, setSearch] = useState("");
  const [open, setOpen] = useState<string | null>(null);

  const { data: flowsData } = useFlows({
    page: 1,
    limit: 50,
    minScore,
    flaggedOnly,
    search,
  });

  const rows = flowsData?.data ?? [];
  const total = flowsData?.pagination.total ?? 0;

  return (
    <>
      <PageTitle
        title="Flow and packet explorer"
        note="Reference view over ingested flows. Select a row to expand its packet-level sequence."
      />

      <div className="sticky top-14 z-10 mb-4 flex flex-wrap items-center gap-3 rounded-md border border-fog-deep bg-void-800 px-4 py-3">
        <input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search IP, port or protocol"
          className="mono w-[240px] rounded-full border border-fog-deep bg-void-700 px-3.5 py-1.5 outline-none placeholder:text-fog-deep focus:border-teal"
        />
        <label className="flex items-center gap-2 rounded-full border border-fog-deep bg-void-700 px-3.5 py-1.5 text-[13px]">
          Score ≥
          <input
            type="range"
            min={0}
            max={0.9}
            step={0.05}
            value={minScore}
            onChange={(e) => setMinScore(Number(e.target.value))}
            className="w-24 accent-teal"
          />
          <span className="mono">{minScore.toFixed(2)}</span>
        </label>
        <button
          onClick={() => setFlaggedOnly((v) => !v)}
          className={cn(
            "rounded-full border px-3.5 py-1.5 text-[13px] font-medium",
            flaggedOnly
              ? "border-teal bg-teal/12 text-teal"
              : "border-fog-deep text-fog hover:text-paper",
          )}
        >
          Flagged only
        </button>
        <span className="mono ml-auto text-fog">
          {rows.length} / {total} flows
        </span>
      </div>

      <FlatPanel bodyClassName="p-0 overflow-x-auto">
        <table className="w-full min-w-[1180px] text-left">
          <thead className="text-[12px] text-fog">
            <tr className="border-b border-fog-deep/60">
              {columns.map((c) => (
                <th
                  key={c.key}
                  className={cn(
                    "px-4 py-2.5 font-medium",
                    c.align === "right" && "text-right",
                  )}
                >
                  {c.label}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((f) => (
              <Fragment key={f._id}>
                <tr
                  onClick={() => setOpen(open === f._id ? null : f._id)}
                  className="cursor-pointer border-b border-fog-deep/40 hover:bg-paper/4"
                >
                  {columns.map((c) => {
                    const v = f[c.key];
                    return (
                      <td
                        key={c.key}
                        className={cn(
                          "mono px-4 py-2.5",
                          c.align === "right" && "text-right",
                        )}
                      >
                        {typeof v === "number" && c.key === "bytes"
                          ? v.toLocaleString()
                          : v}
                      </td>
                    );
                  })}
                </tr>
                {open === f._id ? (
                  <tr className="border-b border-fog-deep/40 bg-void-700/40">
                    <td colSpan={columns.length} className="px-4 py-4">
                      <p className="mb-2 text-[13px] font-medium">
                        Packet sequence — first 6 packets
                      </p>
                      <div className="mono space-y-1 text-fog">
                        {[
                          "0.000  SYN     len 60    ttl 63  win 64240",
                          "0.041  SYN,ACK len 60    ttl 128 win 65535",
                          "0.042  ACK     len 52    ttl 63  win 64240",
                          "0.088  PSH,ACK len 1514  ttl 63  win 64240",
                          "0.131  ACK     len 52    ttl 128 win 65535",
                          "0.174  PSH,ACK len 1514  ttl 63  win 64240",
                        ].map((line) => (
                          <p key={line}>{line}</p>
                        ))}
                      </div>
                    </td>
                  </tr>
                ) : null}
              </Fragment>
            ))}
          </tbody>
        </table>
        {rows.length === 0 ? (
          <p className="px-5 py-8 text-[15px] text-fog">
            No flows match these filters. Lower the score threshold or clear the
            search term.
          </p>
        ) : null}
      </FlatPanel>
    </>
  );
}
