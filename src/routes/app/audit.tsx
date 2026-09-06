import { useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { FlatPanel, PageTitle } from "@/components/app/panels";
import { pageHead } from "@/lib/head";
import { auditEntries } from "@/lib/telemetry";

export const Route = createFileRoute("/app/audit")({
  head: pageHead(
    "Audit log — Aegis Vantage",
    "Chronological compliance record of every action taken on alerts, users and model versions.",
  ),
  component: Audit,
});

function Audit() {
  const [actor, setActor] = useState("all");
  const [action, setAction] = useState("all");

  const rows = auditEntries.filter(
    (e) =>
      (actor === "all" || e.actor === actor) &&
      (action === "all" || e.action.startsWith(action)),
  );

  return (
    <>
      <PageTitle
        title="Audit log"
        note="Entries are append-only and retained for seven years."
      />

      <div className="mb-4 flex flex-wrap gap-3">
        <select
          value={actor}
          onChange={(e) => setActor(e.target.value)}
          aria-label="Filter by actor"
          className="mono rounded-full border border-fog-deep bg-void-700 px-3.5 py-1.5 outline-none"
        >
          <option value="all">all actors</option>
          {[...new Set(auditEntries.map((e) => e.actor))].map((a) => (
            <option key={a} value={a}>
              {a}
            </option>
          ))}
        </select>
        <select
          value={action}
          onChange={(e) => setAction(e.target.value)}
          aria-label="Filter by action type"
          className="mono rounded-full border border-fog-deep bg-void-700 px-3.5 py-1.5 outline-none"
        >
          <option value="all">all actions</option>
          {["alert", "model", "export", "ingest", "user", "inference"].map((a) => (
            <option key={a} value={a}>
              {a}
            </option>
          ))}
        </select>
      </div>

      <FlatPanel bodyClassName="p-0">
        <table className="w-full text-left">
          <thead className="text-[12px] text-fog">
            <tr className="border-b border-fog-deep/60">
              <th className="px-5 py-2.5 font-medium">Timestamp</th>
              <th className="px-5 py-2.5 font-medium">Actor</th>
              <th className="px-5 py-2.5 font-medium">Action</th>
              <th className="px-5 py-2.5 font-medium">Target</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((e) => (
              <tr
                key={e.at + e.action}
                className="border-b border-fog-deep/40 last:border-0 hover:bg-paper/4"
              >
                <td className="mono px-5 py-2.5 text-fog">{e.at}</td>
                <td className="mono px-5 py-2.5">{e.actor}</td>
                <td className="mono px-5 py-2.5">{e.action}</td>
                <td className="mono px-5 py-2.5">{e.target}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {rows.length === 0 ? (
          <p className="px-5 py-8 text-[15px] text-fog">
            No entries match these filters. Widen the actor or action filter.
          </p>
        ) : null}
      </FlatPanel>
    </>
  );
}
