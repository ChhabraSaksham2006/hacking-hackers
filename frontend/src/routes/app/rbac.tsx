import { useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { Check, Minus, X } from "lucide-react";
import { ActionButton, FlatPanel, PageTitle } from "@/components/app/panels";
import { pageHead } from "@/lib/head";

export const Route = createFileRoute("/app/rbac")({
  head: pageHead(
    "Roles and permissions — Flow दृष्टि",
    "Role matrix covering alert triage, inference, user management, exports and integrations.",
  ),
  component: Rbac,
});

const perms = [
  "View alerts",
  "Acknowledge / resolve",
  "Run inference / retrain",
  "Manage users",
  "Export reports",
  "Manage integrations",
];

const roles = [
  { role: "Analyst", users: 34, grants: [1, 1, 0, 0, 1, 0] },
  { role: "SOC Lead", users: 8, grants: [1, 1, 1, 0, 1, 0] },
  { role: "Admin", users: 4, grants: [1, 1, 1, 1, 1, 1] },
  { role: "Super Admin", users: 2, grants: [1, 1, 1, 1, 1, 1] },
];

const orgs = [
  { name: "Northwind Energy", hosts: 1462, model: "wm-v4.2.1", datasets: "CIC-IDS-2018, CTU-13" },
  { name: "Harbour Freight Rail", hosts: 884, model: "wm-v4.1.0", datasets: "CTU-13" },
  { name: "Meridian Health", hosts: 2210, model: "wm-v4.2.1", datasets: "CIC-IDS-2018" },
];

function Rbac() {
  const [editing, setEditing] = useState<string | null>(null);

  return (
    <>
      <PageTitle
        title="Roles and permissions"
        note="Permissions are enforced server-side on every request, not in the interface."
      />

      <FlatPanel title="Role matrix" bodyClassName="p-0 overflow-x-auto">
        <table className="w-full min-w-[640px] text-left">
          <thead className="text-[12px] text-fog">
            <tr className="border-b border-fog-deep/60">
              <th className="px-5 py-2.5 font-medium">Role</th>
              {perms.map((p) => (
                <th key={p} className="px-3 py-2.5 text-center font-medium">
                  {p}
                </th>
              ))}
              <th className="px-5 py-2.5 text-right font-medium">Users</th>
              <th className="px-5 py-2.5"></th>
            </tr>
          </thead>
          <tbody>
            {roles.map((r) => (
              <tr
                key={r.role}
                className="border-b border-fog-deep/40 last:border-0 hover:bg-paper/4"
              >
                <td className="px-5 py-3 text-[13px] font-medium">{r.role}</td>
                {r.grants.map((g, i) => (
                  <td key={i} className="px-3 py-3 text-center">
                    {g ? (
                      <Check className="mx-auto size-4 text-teal" />
                    ) : (
                      <X className="mx-auto size-4 text-fog-deep" />
                    )}
                  </td>
                ))}
                <td className="mono px-5 py-3 text-right">{r.users}</td>
                <td className="px-5 py-3 text-right">
                  <button
                    onClick={() => setEditing(r.role)}
                    className="text-[13px] text-teal"
                  >
                    Edit role
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </FlatPanel>

      <h2 className="mt-8 mb-4 font-display text-[20px] font-medium">
        Super admin console
      </h2>

      <div className="grid gap-5 lg:grid-cols-[minmax(0,1.3fr)_minmax(0,1fr)]">
        <FlatPanel title="Organisations" bodyClassName="p-0 overflow-x-auto">
          <table className="w-full min-w-[500px] text-left">
            <thead className="text-[12px] text-fog">
              <tr className="border-b border-fog-deep/60">
                <th className="px-5 py-2.5 font-medium">Organisation</th>
                <th className="px-5 py-2.5 text-right font-medium">Hosts</th>
                <th className="px-5 py-2.5 font-medium">Model</th>
                <th className="px-5 py-2.5 font-medium">Dataset access</th>
              </tr>
            </thead>
            <tbody>
              {orgs.map((o) => (
                <tr
                  key={o.name}
                  className="border-b border-fog-deep/40 last:border-0 hover:bg-paper/4"
                >
                  <td className="px-5 py-2.5 text-[13px]">{o.name}</td>
                  <td className="mono px-5 py-2.5 text-right">{o.hosts}</td>
                  <td className="mono px-5 py-2.5">{o.model}</td>
                  <td className="mono px-5 py-2.5 text-fog">{o.datasets}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </FlatPanel>

        <FlatPanel title="Global model control">
          <div className="space-y-3">
            <div className="flex items-center justify-between border-b border-fog-deep/40 pb-2">
              <span className="text-[13px] text-fog">Production version</span>
              <span className="mono">wm-v4.2.1</span>
            </div>
            <div className="flex items-center justify-between border-b border-fog-deep/40 pb-2">
              <span className="text-[13px] text-fog">Deployed</span>
              <span className="mono">2026-09-06 12:20Z</span>
            </div>
            <div className="flex items-center justify-between border-b border-fog-deep/40 pb-2">
              <span className="text-[13px] text-fog">Rollback target</span>
              <span className="mono">wm-v4.1.0</span>
            </div>
          </div>
          <div className="mt-4 flex flex-wrap gap-2">
            <ActionButton>Deploy new version</ActionButton>
            <ActionButton variant="ghost">Roll back</ActionButton>
          </div>
        </FlatPanel>
      </div>

      {editing ? (
        <>
          <div
            className="fixed inset-0 z-30 bg-void-950/60 backdrop-blur-xs sm:hidden"
            onClick={() => setEditing(null)}
          />
          <aside className="fixed inset-y-0 right-0 z-30 w-full sm:w-[380px] max-w-full overflow-y-auto border-l border-fog-deep bg-void-800 p-4 sm:p-5 shadow-2xl">
            <div className="flex items-center justify-between">
              <p className="font-display text-[20px] font-medium">{editing}</p>
              <button
                onClick={() => setEditing(null)}
                aria-label="Close role editor"
                className="text-fog hover:text-paper"
              >
                <X className="size-4" />
              </button>
            </div>
            <ul className="mt-5 space-y-2">
              {perms.map((p, i) => (
                <li
                  key={p}
                  className="flex items-center justify-between border-b border-fog-deep/40 pb-2"
                >
                  <span className="text-[13px]">{p}</span>
                  <input
                    type="checkbox"
                    defaultChecked={
                      roles.find((r) => r.role === editing)!.grants[i] === 1
                    }
                    className="accent-teal"
                  />
                </li>
              ))}
            </ul>
            <p className="mt-4 flex items-center gap-2 text-[12px] text-fog">
              <Minus className="size-3" /> Changes apply to all users in this role.
            </p>
            <ActionButton className="mt-4 w-full">Save role</ActionButton>
          </aside>
        </>
      ) : null}
    </>
  );
}
