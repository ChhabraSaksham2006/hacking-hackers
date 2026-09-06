import { createFileRoute } from "@tanstack/react-router";
import { ActionButton, FlatPanel, PageTitle } from "@/components/app/panels";
import { Sparkline } from "@/components/app/charts";
import { pageHead } from "@/lib/head";

export const Route = createFileRoute("/app/reports")({
  head: pageHead(
    "Reports and export — Aegis Vantage",
    "Build a PDF or CSV incident report from a time window, alert or segment and preview it before export.",
  ),
  component: Reports,
});

const past = [
  { name: "weekly-fin-2026-w36.pdf", scope: "finance · 7d", at: "2026-09-06 14:02Z", size: "2.4 MB" },
  { name: "AV-4814-incident.pdf", scope: "alert AV-4814", at: "2026-09-05 18:20Z", size: "1.1 MB" },
  { name: "corp-core-flows.csv", scope: "corp-core · 24h", at: "2026-09-04 09:44Z", size: "18.9 MB" },
];

function Reports() {
  return (
    <>
      <PageTitle title="Reports and export" />

      <div className="grid gap-5 lg:grid-cols-2">
        <FlatPanel title="Report scope">
          <form className="space-y-4" onSubmit={(e) => e.preventDefault()}>
            <label className="block">
              <span className="text-[13px] font-medium">Time window</span>
              <select className="mono mt-1.5 w-full rounded-md border border-fog-deep bg-void-700 px-3 py-2.5 outline-none focus:border-teal">
                <option>last 24 hours</option>
                <option>last 7 days</option>
                <option>2026-09-06 14:00–15:00Z</option>
              </select>
            </label>
            <label className="block">
              <span className="text-[13px] font-medium">Segment or alert</span>
              <select className="mono mt-1.5 w-full rounded-md border border-fog-deep bg-void-700 px-3 py-2.5 outline-none focus:border-teal">
                <option>corp-core</option>
                <option>finance</option>
                <option>alert AV-4821</option>
              </select>
            </label>
            <fieldset>
              <legend className="text-[13px] font-medium">Format</legend>
              <div className="mt-2 flex gap-4 text-[13px]">
                <label className="flex items-center gap-2">
                  <input type="radio" name="fmt" defaultChecked className="accent-teal" />
                  PDF
                </label>
                <label className="flex items-center gap-2">
                  <input type="radio" name="fmt" className="accent-teal" />
                  CSV
                </label>
              </div>
            </fieldset>
            <ActionButton>Export report</ActionButton>
          </form>
        </FlatPanel>

        <FlatPanel title="Preview">
          <div className="rounded-md border border-fog-deep bg-void-900 p-5">
            <p className="font-display text-[20px] font-medium">
              Incident report — corp-core
            </p>
            <p className="mono mt-1 text-fog">2026-09-05 15:00Z → 2026-09-06 15:00Z</p>
            <div className="mt-4">
              <Sparkline series={[0.1, 0.24, 0.38, 0.5, 0.66, 0.8, 0.88]} />
            </div>
            <p className="mt-4 text-[13px] font-medium">Flagged flows</p>
            <div className="mono mt-1 space-y-1 text-fog">
              <p>10.24.8.31:49722 → 10.24.8.14:445 0.91</p>
              <p>10.24.1.4:51344 → 203.0.113.77:8443 0.83</p>
            </div>
            <p className="mt-4 text-[13px] font-medium">Explainability summary</p>
            <p className="mt-1 text-[13px] text-fog">
              Elevated SYN/ACK ratio with SMB session fan-out; mapped to ATT&amp;CK
              lateral movement.
            </p>
          </div>
        </FlatPanel>
      </div>

      <FlatPanel className="mt-5" title="Past exports" bodyClassName="p-0">
        <table className="w-full text-left">
          <thead className="text-[12px] text-fog">
            <tr className="border-b border-fog-deep/60">
              <th className="px-5 py-2.5 font-medium">File</th>
              <th className="px-5 py-2.5 font-medium">Scope</th>
              <th className="px-5 py-2.5 font-medium">Created</th>
              <th className="px-5 py-2.5 text-right font-medium">Size</th>
              <th className="px-5 py-2.5"></th>
            </tr>
          </thead>
          <tbody>
            {past.map((p) => (
              <tr
                key={p.name}
                className="border-b border-fog-deep/40 last:border-0 hover:bg-paper/4"
              >
                <td className="mono px-5 py-2.5">{p.name}</td>
                <td className="px-5 py-2.5 text-[13px]">{p.scope}</td>
                <td className="mono px-5 py-2.5 text-fog">{p.at}</td>
                <td className="mono px-5 py-2.5 text-right">{p.size}</td>
                <td className="px-5 py-2.5 text-right">
                  <span className="text-[13px] text-teal">Download</span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </FlatPanel>
    </>
  );
}
