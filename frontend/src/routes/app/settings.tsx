import { useState } from "react";
import { createFileRoute, Link } from "@tanstack/react-router";
import { ActionButton, FlatPanel, PageTitle, RiskBadge } from "@/components/app/panels";
import { pageHead } from "@/lib/head";
import { cn } from "@/lib/utils";
import { useAuthMe, useUpdateAlertNotifications } from "@/hooks/useApi";

export const Route = createFileRoute("/app/settings")({
  head: pageHead(
    "Settings â€” Flow दृष्टि",
    "Model configuration, data sources, notifications, integrations and team roles.",
  ),
  component: Settings,
});

const sections = [
  "Model config",
  "Data sources",
  "Notifications",
  "Integrations",
  "Team and roles",
] as const;

function Settings() {
  const [section, setSection] = useState<(typeof sections)[number]>("Model config");
  const [windowK, setWindowK] = useState(8);
  const [threshold, setThreshold] = useState(0.65);

  const { data: user } = useAuthMe();
  const updateNotifications = useUpdateAlertNotifications();

  return (
    <>
      <PageTitle title="Settings" />

      <div className="grid gap-5 lg:grid-cols-[220px_minmax(0,1fr)]">
        <nav className="flat h-fit p-2">
          {sections.map((s) => (
            <button
              key={s}
              onClick={() => setSection(s)}
              className={cn(
                "block w-full rounded-md px-3 py-2 text-left text-[13px] font-medium",
                section === s ? "bg-teal/12 text-teal" : "text-fog hover:text-paper",
              )}
            >
              {s}
            </button>
          ))}
        </nav>

        <FlatPanel title={section}>
          {section === "Model config" ? (
            <div className="max-w-[520px] space-y-6">
              <label className="block">
                <span className="flex items-center justify-between text-[13px] font-medium">
                  Forecast window K
                  <span className="mono">{windowK} steps</span>
                </span>
                <input
                  type="range"
                  min={2}
                  max={16}
                  value={windowK}
                  onChange={(e) => setWindowK(Number(e.target.value))}
                  className="mt-2 w-full accent-teal"
                />
              </label>
              <label className="block">
                <span className="flex items-center justify-between text-[13px] font-medium">
                  Alert threshold
                  <span className="mono">{threshold.toFixed(2)}</span>
                </span>
                <input
                  type="range"
                  min={0.3}
                  max={0.95}
                  step={0.01}
                  value={threshold}
                  onChange={(e) => setThreshold(Number(e.target.value))}
                  className="mt-2 w-full accent-teal"
                />
              </label>
              <label className="block">
                <span className="text-[13px] font-medium">Retraining schedule</span>
                <select className="mono mt-1.5 w-full rounded-md border border-fog-deep bg-void-700 px-3 py-2.5 outline-none focus:border-teal">
                  <option>nightly 02:00Z</option>
                  <option>weekly, Sunday 02:00Z</option>
                  <option>manual only</option>
                </select>
              </label>
              <ActionButton>Save model config</ActionButton>
            </div>
          ) : null}

          {section === "Data sources" ? (
            <ul className="max-w-[620px] divide-y divide-fog-deep/40">
              {[
                { name: "pcap-store-eu-west", ok: true, note: "S3 Â· 4.2 TB retained" },
                { name: "netflow-collector-01", ok: true, note: "IPFIX Â· 12k flows/min" },
                { name: "netflow-collector-02", ok: false, note: "no data for 41m" },
              ].map((d) => (
                <li key={d.name} className="flex items-center justify-between py-3">
                  <div>
                    <p className="mono">{d.name}</p>
                    <p className="mt-0.5 text-[12px] text-fog">{d.note}</p>
                  </div>
                  <RiskBadge
                    state={d.ok ? "normal" : "critical"}
                    label={d.ok ? "Connected" : "No data"}
                  />
                </li>
              ))}
              <li className="pt-4">
                <ActionButton variant="ghost">Add source</ActionButton>
              </li>
            </ul>
          ) : null}

          {section === "Notifications" ? (
            <div className="max-w-[520px] space-y-4">
              <label className="flex items-center justify-between border-b border-fog-deep/40 pb-3">
                <span className="text-[15px]">
                  Email me when a critical alert is triggered
                </span>
                <input
                  type="checkbox"
                  className="accent-teal"
                  checked={user?.alertNotificationsEnabled ?? true}
                  disabled={updateNotifications.isPending}
                  onChange={(e) => updateNotifications.mutate({ enabled: e.target.checked })}
                />
              </label>
              <label className="flex items-center justify-between border-b border-fog-deep/40 pb-3 opacity-50">
                <span className="text-[15px]">
                  Notify the on-call channel for critical states only (coming soon)
                </span>
                <input type="checkbox" disabled className="accent-teal" />
              </label>
              <label className="flex items-center justify-between border-b border-fog-deep/40 pb-3 opacity-50">
                <span className="text-[15px]">
                  Daily digest of watch-state segments (coming soon)
                </span>
                <input type="checkbox" disabled className="accent-teal" />
              </label>
            </div>
          ) : null}

          {section === "Integrations" ? (
            <div className="max-w-[620px] space-y-4">
              <div>
                <p className="text-[13px] font-medium">API key</p>
                <p className="mono mt-1.5 rounded-md border border-fog-deep bg-void-700 px-3 py-2.5">
                  av_live_â€¢â€¢â€¢â€¢â€¢â€¢â€¢â€¢â€¢â€¢â€¢â€¢â€¢â€¢â€¢â€¢3f9c
                </p>
              </div>
              <div>
                <p className="text-[13px] font-medium">Alert webhook</p>
                <p className="mono mt-1.5 rounded-md border border-fog-deep bg-void-700 px-3 py-2.5">
                  https://soc.northwind.example/hooks/aegis
                </p>
              </div>
              <ActionButton variant="ghost">Rotate API key</ActionButton>
            </div>
          ) : null}

          {section === "Team and roles" ? (
            <p className="max-w-[70ch] text-[15px] text-fog">
              Role membership and permissions live on the{" "}
              <Link to="/app/rbac" className="text-teal">
                roles and permissions page
              </Link>
              .
            </p>
          ) : null}
        </FlatPanel>
      </div>
    </>
  );
}
