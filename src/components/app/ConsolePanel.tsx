import { useState } from "react";
import { Terminal, X } from "lucide-react";

const transcript = [
  {
    q: "why is fin-db-02 flagged",
    a: "fin-db-02 crossed threshold at 14:38Z on lateral-movement features: 14 SMB session setups across distinct hosts in 90s, with SYN/ACK ratio 4.82.",
    refs: ["AV-4821", "10.24.8.31:49722"],
  },
];

export function ConsolePanel() {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");

  if (!open) {
    return (
      <button
        onClick={() => setOpen(true)}
        className="fixed right-6 bottom-6 z-30 flex items-center gap-2 rounded-md border border-fog-deep bg-void-800 px-3.5 py-2 text-[13px] font-medium text-paper hover:bg-void-700"
      >
        <Terminal className="size-4" strokeWidth={1.75} />
        Query telemetry
      </button>
    );
  }

  return (
    <aside className="fixed right-6 bottom-6 z-30 w-[380px] rounded-lg border border-fog-deep bg-void-800">
      <div className="flex items-center justify-between border-b border-fog-deep/60 px-4 py-3">
        <span className="text-[13px] font-medium">Telemetry console</span>
        <button
          onClick={() => setOpen(false)}
          aria-label="Close telemetry console"
          className="text-fog hover:text-paper"
        >
          <X className="size-4" />
        </button>
      </div>
      <div className="max-h-[280px] space-y-4 overflow-y-auto px-4 py-4">
        {transcript.map((t) => (
          <div key={t.q} className="space-y-2">
            <p className="mono text-teal">&gt; {t.q}</p>
            <p className="text-[15px]">{t.a}</p>
            <p className="mono text-fog">{t.refs.join("  ")}</p>
          </div>
        ))}
      </div>
      <div className="flex items-center gap-2 border-t border-fog-deep/60 px-4 py-3">
        <span className="mono text-teal">&gt;</span>
        <input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="ask about a host, flow, or alert"
          className="mono w-full bg-transparent text-paper outline-none placeholder:text-fog-deep"
        />
      </div>
    </aside>
  );
}
