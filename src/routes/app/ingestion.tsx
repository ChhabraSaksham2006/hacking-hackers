import { useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { Check, Loader2 } from "lucide-react";
import {
  ActionButton,
  FlatPanel,
  PageTitle,
  RiskBadge,
} from "@/components/app/panels";
import { pageHead } from "@/lib/head";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/app/ingestion")({
  head: pageHead(
    "Ingestion — Aegis Vantage",
    "Upload PCAP or NetFlow/IPFIX captures and follow the feature pipeline through to inference.",
  ),
  component: Ingestion,
});

const steps = [
  { name: "Parsing", status: "done" },
  { name: "Feature extraction", status: "done" },
  { name: "Normalisation", status: "running" },
  { name: "Inference", status: "pending" },
  { name: "Explanation", status: "pending" },
] as const;

const history = [
  { file: "cicids-2018-day3.pcap", set: "CIC-IDS-2018", size: "4.2 GB", at: "2026-09-06 11:59Z", ok: true },
  { file: "ctu13-scenario-9.pcap", set: "CTU-13", size: "1.1 GB", at: "2026-09-05 22:14Z", ok: true },
  { file: "corp-core-netflow.csv", set: "Custom upload", size: "184 MB", at: "2026-09-05 09:02Z", ok: true },
  { file: "dmz-edge-partial.pcap", set: "Custom upload", size: "612 MB", at: "2026-09-04 17:41Z", ok: false },
];

function Ingestion() {
  const [dataset, setDataset] = useState("CIC-IDS-2018");
  const [dragging, setDragging] = useState(false);

  return (
    <>
      <PageTitle
        title="Ingestion"
        note="Captures are parsed into per-window state features before the world model runs forward."
      />

      <div className="mb-4 inline-flex rounded-md border border-fog-deep bg-void-800 p-1">
        {["CIC-IDS-2018", "CTU-13", "Custom upload"].map((d) => (
          <button
            key={d}
            onClick={() => setDataset(d)}
            className={cn(
              "rounded-[6px] px-3.5 py-1.5 text-[13px] font-medium transition-colors",
              dataset === d ? "bg-teal text-void-900" : "text-fog hover:text-paper",
            )}
          >
            {d}
          </button>
        ))}
      </div>

      <div
        onDragOver={(e) => {
          e.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={(e) => {
          e.preventDefault();
          setDragging(false);
        }}
        className={cn(
          "flex flex-col items-start gap-2 rounded-lg border border-dashed bg-void-800 px-8 py-14 transition-colors",
          dragging ? "border-teal" : "border-fog-deep",
        )}
      >
        <p className="text-[15px]">
          Drop a capture here, or{" "}
          <span className="text-teal">choose a file</span>.
        </p>
        <p className="text-[12px] text-fog">
          PCAP or NetFlow/IPFIX CSV, up to 20 GB per upload.
        </p>
        <ActionButton className="mt-4">Start ingestion</ActionButton>
      </div>

      <FlatPanel className="mt-5" title="Pipeline progress">
        <ol className="grid gap-4 sm:grid-cols-5">
          {steps.map((s, i) => (
            <li key={s.name} className="flex items-start gap-3">
              <span className="mono w-5 shrink-0 text-fog">{i + 1}</span>
              <div>
                <p
                  className={cn(
                    "text-[13px] font-medium",
                    s.status === "pending" ? "text-fog" : "text-paper",
                  )}
                >
                  {s.name}
                </p>
                <p className="mt-1 flex items-center gap-1.5 text-[12px] text-fog">
                  {s.status === "done" && (
                    <>
                      <Check className="size-3.5 text-teal" /> done
                    </>
                  )}
                  {s.status === "running" && (
                    <>
                      <Loader2 className="size-3.5 animate-spin text-amber" />{" "}
                      running
                    </>
                  )}
                  {s.status === "pending" && "pending"}
                </p>
              </div>
            </li>
          ))}
        </ol>
      </FlatPanel>

      <FlatPanel className="mt-5" title="Upload history" bodyClassName="p-0">
        <table className="w-full text-left">
          <thead className="text-[12px] text-fog">
            <tr className="border-b border-fog-deep/60">
              <th className="px-5 py-2.5 font-medium">File</th>
              <th className="px-5 py-2.5 font-medium">Dataset</th>
              <th className="px-5 py-2.5 text-right font-medium">Size</th>
              <th className="px-5 py-2.5 font-medium">Ingested</th>
              <th className="px-5 py-2.5 font-medium">Status</th>
              <th className="px-5 py-2.5"></th>
            </tr>
          </thead>
          <tbody>
            {history.map((h) => (
              <tr
                key={h.file}
                className="border-b border-fog-deep/40 last:border-0 hover:bg-paper/4"
              >
                <td className="mono px-5 py-2.5">{h.file}</td>
                <td className="px-5 py-2.5 text-[13px]">{h.set}</td>
                <td className="mono px-5 py-2.5 text-right">{h.size}</td>
                <td className="mono px-5 py-2.5 text-fog">{h.at}</td>
                <td className="px-5 py-2.5">
                  <RiskBadge
                    state={h.ok ? "normal" : "critical"}
                    label={h.ok ? "Complete" : "Parse failed"}
                  />
                </td>
                <td className="px-5 py-2.5 text-right">
                  <span className="text-[13px] text-teal">View results</span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </FlatPanel>
    </>
  );
}
