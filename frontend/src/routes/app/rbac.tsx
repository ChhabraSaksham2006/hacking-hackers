import { useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { Check, Shield, UserCheck, Users, X, RefreshCw, Sparkles, Building2, Cpu, UserPlus, Key, Copy } from "lucide-react";
import { ActionButton, FlatPanel, PageTitle } from "@/components/app/panels";
import { pageHead } from "@/lib/head";
import {
  usePermissions,
  useRoleMatrix,
  useOrgUsers,
  useCreateOrgUser,
  useUpdateUserRole,
  useDemoSwitchRole,
  type Role,
} from "@/hooks/usePermissions";
import { useModelVersions, usePromoteModel } from "@/hooks/useApi";
import { toast } from "sonner";

export const Route = createFileRoute("/app/rbac")({
  head: pageHead(
    "Roles and permissions — Flow दृष्टि",
    "Role matrix covering alert triage, inference, user management, exports and integrations.",
  ),
  component: Rbac,
});

const DEFAULT_PERMS = [
  { key: "alerts.read", label: "View alerts & telemetry" },
  { key: "alerts.update", label: "Acknowledge / resolve alerts" },
  { key: "inference.run", label: "Run inference replay & what-if" },
  { key: "simulation.run", label: "Run forward simulations" },
  { key: "ingestion.create", label: "Upload PCAP / CSV telemetry" },
  { key: "users.create", label: "Add & onboard team members" },
  { key: "users.manage", label: "Manage team members & assign roles" },
  { key: "reports.export", label: "Export audit & compliance reports" },
  { key: "audit.read", label: "View cryptographic audit ledger" },
  { key: "integrations.manage", label: "Configure edge sensors & API keys" },
  { key: "settings.update", label: "Update organization settings" },
  { key: "orgs.manage", label: "Cross-tenant organization management" },
  { key: "model.promote", label: "Promote / rollback ML world model" },
];

const ROLE_BADGE_STYLES: Record<Role, string> = {
  Analyst: "border-fog-deep/60 bg-paper/5 text-fog",
  "SOC Lead": "border-teal/40 bg-teal/10 text-teal",
  Admin: "border-amber/40 bg-amber/10 text-amber",
  "Super Admin": "border-rose-500/40 bg-rose-500/10 text-rose-400 font-semibold",
};

function Rbac() {
  const { user, role: currentRole, can, isAdmin, isSocLead, isSuperAdmin } = usePermissions();
  const { data: matrixData, isLoading: matrixLoading } = useRoleMatrix();
  const { data: users = [], isLoading: usersLoading } = useOrgUsers();
  const updateRoleMutation = useUpdateUserRole();
  const createOrgUserMutation = useCreateOrgUser();
  const demoSwitchMutation = useDemoSwitchRole();
  const { data: models = [] } = useModelVersions();
  const promoteMutation = usePromoteModel();

  const [switchingTo, setSwitchingTo] = useState<Role | null>(null);

  // Add Member State
  const [isAddingMember, setIsAddingMember] = useState(false);
  const [newName, setNewName] = useState("");
  const [newEmail, setNewEmail] = useState("");
  const [newRole, setNewRole] = useState<Role>("Analyst");
  const [newPassword, setNewPassword] = useState("");
  const [tempCredentials, setTempCredentials] = useState<{
    name: string;
    email: string;
    role: string;
    password?: string;
  } | null>(null);
  const [copied, setCopied] = useState(false);

  const canAddMembers = can("users.create") || isSocLead || isAdmin || isSuperAdmin;

  const assignableRoles: Role[] = isSuperAdmin
    ? ["Analyst", "SOC Lead", "Admin", "Super Admin"]
    : isAdmin
    ? ["Analyst", "SOC Lead", "Admin"]
    : ["Analyst", "SOC Lead"];

  const activeModel = models.find((m) => m.isProduction) || models[0];

  const handleDemoSwitch = async (targetRole: Role) => {
    if (targetRole === currentRole) return;
    setSwitchingTo(targetRole);
    try {
      await demoSwitchMutation.mutateAsync(targetRole);
      toast.success(`Active persona switched to ${targetRole}`);
    } catch (err: any) {
      toast.error(err?.message || "Failed to switch role");
    } finally {
      setSwitchingTo(null);
    }
  };

  const handleRoleChange = async (userId: string, newRole: Role, userName: string) => {
    try {
      await updateRoleMutation.mutateAsync({ id: userId, role: newRole });
      toast.success(`Updated role for ${userName} to ${newRole}`);
    } catch (err: any) {
      toast.error(err?.message || "Failed to update role");
    }
  };

  const handleAddMember = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newName.trim() || !newEmail.trim()) {
      toast.error("Please enter a name and email address");
      return;
    }

    try {
      const res = await createOrgUserMutation.mutateAsync({
        name: newName.trim(),
        email: newEmail.trim(),
        role: newRole,
        password: newPassword.trim() || undefined,
      });

      toast.success(res.message);
      if (res.temporaryPassword) {
        setTempCredentials({
          name: res.user.name,
          email: res.user.email,
          role: res.user.role,
          password: res.temporaryPassword,
        });
      }
      setIsAddingMember(false);
      setNewName("");
      setNewEmail("");
      setNewPassword("");
      setNewRole("Analyst");
    } catch (err: any) {
      toast.error(err?.message || "Failed to add team member");
    }
  };

  const rolesList: Role[] = matrixData?.roles || ["Analyst", "SOC Lead", "Admin", "Super Admin"];
  const rolePermissions = matrixData?.rolePermissions || {
    Analyst: ["alerts.read", "reports.export", "audit.read", "orgs.read"],
    "SOC Lead": [
      "alerts.read",
      "alerts.update",
      "inference.run",
      "model.retrain",
      "ingestion.create",
      "simulation.run",
      "users.create",
      "reports.export",
      "audit.read",
      "orgs.read",
      "settings.read",
    ],
    Admin: [
      "alerts.read",
      "alerts.update",
      "inference.run",
      "model.retrain",
      "ingestion.create",
      "simulation.run",
      "users.create",
      "users.manage",
      "reports.export",
      "audit.read",
      "integrations.manage",
      "orgs.read",
      "settings.read",
      "settings.update",
    ],
    "Super Admin": [
      "alerts.read",
      "alerts.update",
      "inference.run",
      "model.retrain",
      "ingestion.create",
      "simulation.run",
      "users.create",
      "users.manage",
      "reports.export",
      "audit.read",
      "integrations.manage",
      "orgs.read",
      "orgs.manage",
      "model.promote",
      "settings.read",
      "settings.update",
    ],
  };

  return (
    <>
      <PageTitle
        title="Roles and permissions"
        note="Fine-grained Role-Based Access Control (RBAC) enforced cryptographically on every API invocation."
      />

      {/* ── Active Role Persona Switcher (Interactive Demo Bar) ── */}
      <div className="mb-6 rounded-lg border border-teal/30 bg-void-800/80 p-4 shadow-sm backdrop-blur-xs">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-center gap-2.5">
            <Sparkles className="size-4 text-teal animate-pulse" />
            <div>
              <div className="flex items-center gap-2">
                <span className="text-[12px] font-mono uppercase tracking-wider text-fog">Active Session Role:</span>
                <span className={`rounded px-2 py-0.5 text-xs font-mono border ${ROLE_BADGE_STYLES[currentRole || "Analyst"]}`}>
                  {currentRole || "Analyst"}
                </span>
              </div>
              <p className="text-[12px] text-fog mt-0.5">
                Switch personas to test real-time UI action gating and server authorization instantly.
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-1.5">
            {rolesList.map((r) => (
              <button
                key={r}
                onClick={() => handleDemoSwitch(r)}
                disabled={demoSwitchMutation.isPending || currentRole === r}
                className={`px-3 py-1 text-xs font-mono rounded transition-colors ${
                  currentRole === r
                    ? "bg-teal text-void-950 font-semibold"
                    : "border border-fog-deep/50 text-fog hover:border-teal/50 hover:text-paper hover:bg-paper/5"
                } disabled:opacity-50`}
              >
                {switchingTo === r ? "Switching..." : r}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* ── Temporary Credentials Generated Notification ── */}
      {tempCredentials && (
        <div className="mb-6 rounded-lg border border-teal/40 bg-teal/10 p-4 shadow-sm">
          <div className="flex items-start justify-between">
            <div className="space-y-1.5">
              <div className="flex items-center gap-2">
                <Key className="size-4 text-teal" />
                <h4 className="text-sm font-semibold text-paper">
                  New Team Member Added: <span className="text-teal">{tempCredentials.name}</span>
                </h4>
              </div>
              <p className="text-xs text-fog">
                An initial account with role <span className="font-mono text-paper font-medium">{tempCredentials.role}</span> has been provisioned. Please copy and share these temporary credentials securely:
              </p>
              <div className="mt-2 flex flex-wrap items-center gap-3 rounded bg-void-950/80 px-3 py-2 border border-teal/30 font-mono text-xs">
                <span>
                  <span className="text-fog">Email:</span>{" "}
                  <span className="text-paper select-all">{tempCredentials.email}</span>
                </span>
                <span className="text-fog-deep">|</span>
                <span>
                  <span className="text-fog">Temp Password:</span>{" "}
                  <span className="text-teal font-bold select-all">{tempCredentials.password}</span>
                </span>
                <button
                  onClick={() => {
                    navigator.clipboard.writeText(
                      `Email: ${tempCredentials.email}\nPassword: ${tempCredentials.password}`,
                    );
                    setCopied(true);
                    toast.success("Credentials copied to clipboard");
                    setTimeout(() => setCopied(false), 2000);
                  }}
                  className="ml-auto inline-flex items-center gap-1 text-[11px] text-teal hover:underline cursor-pointer"
                >
                  {copied ? <Check className="size-3" /> : <Copy className="size-3" />}
                  {copied ? "Copied" : "Copy Credentials"}
                </button>
              </div>
            </div>
            <button
              onClick={() => setTempCredentials(null)}
              className="text-fog hover:text-paper p-1 cursor-pointer"
              aria-label="Dismiss"
            >
              <X className="size-4" />
            </button>
          </div>
        </div>
      )}

      {/* ── Team Members & Role Management ── */}
      <FlatPanel
        title={
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between w-full gap-2">
            <div className="flex items-center gap-2">
              <Users className="size-4 text-teal" />
              <span>Organisation Team Members ({users.length})</span>
            </div>
            {canAddMembers ? (
              <button
                onClick={() => {
                  setIsAddingMember(!isAddingMember);
                  if (tempCredentials) setTempCredentials(null);
                }}
                className="inline-flex items-center gap-1.5 px-3 py-1 text-xs font-mono rounded bg-teal/15 text-teal border border-teal/40 hover:bg-teal/25 transition-colors cursor-pointer w-fit"
              >
                <UserPlus className="size-3.5" />
                <span>{isAddingMember ? "Cancel" : "Add Team Member"}</span>
              </button>
            ) : (
              <span className="text-[11px] font-mono text-fog-deep">
                Admin or SOC Lead required to add members
              </span>
            )}
          </div>
        }
        bodyClassName="p-0 overflow-x-auto"
      >
        {/* ── Inline Add Member Form ── */}
        {isAddingMember && (
          <form
            onSubmit={handleAddMember}
            className="border-b border-teal/30 bg-void-900/60 p-5 space-y-4"
          >
            <div className="flex items-center gap-2">
              <UserPlus className="size-4 text-teal" />
              <h3 className="text-sm font-semibold text-paper">Add New Team Member</h3>
              <span className="text-[11px] font-mono text-fog ml-auto">
                Authorized as: <span className="text-teal font-medium">{currentRole}</span>
              </span>
            </div>

            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
              <div>
                <label className="block text-[11px] font-mono uppercase tracking-wider text-fog mb-1">
                  Full Name *
                </label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Priya Sharma"
                  value={newName}
                  onChange={(e) => setNewName(e.target.value)}
                  className="w-full text-xs font-mono bg-void-950 border border-fog-deep/60 rounded px-3 py-2 text-paper focus:outline-hidden focus:border-teal"
                />
              </div>

              <div>
                <label className="block text-[11px] font-mono uppercase tracking-wider text-fog mb-1">
                  Email Address *
                </label>
                <input
                  type="email"
                  required
                  placeholder="e.g. priya@org.com"
                  value={newEmail}
                  onChange={(e) => setNewEmail(e.target.value)}
                  className="w-full text-xs font-mono bg-void-950 border border-fog-deep/60 rounded px-3 py-2 text-paper focus:outline-hidden focus:border-teal"
                />
              </div>

              <div>
                <label className="block text-[11px] font-mono uppercase tracking-wider text-fog mb-1">
                  Assigned Role *
                </label>
                <select
                  value={newRole}
                  onChange={(e) => setNewRole(e.target.value as Role)}
                  className="w-full text-xs font-mono bg-void-950 border border-fog-deep/60 rounded px-3 py-2 text-paper focus:outline-hidden focus:border-teal cursor-pointer"
                >
                  {assignableRoles.map((r) => (
                    <option key={r} value={r}>
                      {r}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-[11px] font-mono uppercase tracking-wider text-fog mb-1">
                  Password (optional)
                </label>
                <input
                  type="password"
                  placeholder="Leave empty to auto-generate"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  className="w-full text-xs font-mono bg-void-950 border border-fog-deep/60 rounded px-3 py-2 text-paper focus:outline-hidden focus:border-teal"
                />
              </div>
            </div>

            <div className="flex items-center justify-end gap-2.5 pt-1">
              <button
                type="button"
                onClick={() => setIsAddingMember(false)}
                className="px-3 py-1.5 text-xs font-mono rounded border border-fog-deep/50 text-fog hover:text-paper hover:bg-paper/5 transition-colors cursor-pointer"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={createOrgUserMutation.isPending || !newName.trim() || !newEmail.trim()}
                className="px-4 py-1.5 text-xs font-mono rounded bg-teal text-void-950 font-semibold hover:bg-teal-hover transition-colors disabled:opacity-50 cursor-pointer"
              >
                {createOrgUserMutation.isPending ? "Adding Member..." : "Save & Add Member"}
              </button>
            </div>
          </form>
        )}
        {usersLoading ? (
          <div className="p-8 text-center text-xs font-mono text-fog">Loading team members...</div>
        ) : users.length === 0 ? (
          <div className="p-8 text-center text-xs font-mono text-fog">
            No team members registered for this organisation.
          </div>
        ) : (
          <table className="w-full min-w-[640px] text-left">
            <thead className="text-[12px] text-fog bg-void-900/40">
              <tr className="border-b border-fog-deep/60">
                <th className="px-5 py-2.5 font-medium">User</th>
                <th className="px-5 py-2.5 font-medium">Email</th>
                <th className="px-5 py-2.5 font-medium">Current Role</th>
                <th className="px-5 py-2.5 text-right font-medium">Role Assignment</th>
              </tr>
            </thead>
            <tbody>
              {users.map((u) => {
                const isSelf = u._id === user?.id;
                const canModify = can("users.manage") && (!isSelf || isSuperAdmin);

                return (
                  <tr
                    key={u._id}
                    className="border-b border-fog-deep/30 last:border-0 hover:bg-paper/4 transition-colors"
                  >
                    <td className="px-5 py-3">
                      <div className="flex items-center gap-2.5">
                        <div className="size-7 rounded-full bg-teal/15 text-teal border border-teal/30 flex items-center justify-center font-mono text-xs font-bold">
                          {u.initials || u.name?.slice(0, 2).toUpperCase() || "US"}
                        </div>
                        <div>
                          <p className="text-[13px] font-medium text-paper flex items-center gap-1.5">
                            {u.name}
                            {isSelf && (
                              <span className="text-[10px] font-mono text-teal bg-teal/10 px-1.5 py-0.2 rounded border border-teal/30">
                                You
                              </span>
                            )}
                          </p>
                        </div>
                      </div>
                    </td>
                    <td className="px-5 py-3 text-[13px] font-mono text-fog">{u.email}</td>
                    <td className="px-5 py-3">
                      <span className={`inline-block rounded px-2 py-0.5 text-xs font-mono border ${ROLE_BADGE_STYLES[u.role]}`}>
                        {u.role}
                      </span>
                    </td>
                    <td className="px-5 py-3 text-right">
                      {canModify ? (
                        <select
                          value={u.role}
                          onChange={(e) => handleRoleChange(u._id, e.target.value as Role, u.name)}
                          disabled={updateRoleMutation.isPending}
                          className="text-xs font-mono bg-void-900 border border-fog-deep/60 rounded px-2 py-1 text-paper focus:outline-hidden focus:border-teal cursor-pointer"
                        >
                          {rolesList.map((r) => (
                            <option key={r} value={r} disabled={r === "Super Admin" && !isSuperAdmin}>
                              {r} {r === "Super Admin" && !isSuperAdmin ? "(Super Admin required)" : ""}
                            </option>
                          ))}
                        </select>
                      ) : (
                        <span className="text-[11px] font-mono text-fog-deep">
                          {isSelf ? "Self-role locked" : "Requires Admin permission"}
                        </span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </FlatPanel>

      {/* ── Role & Permission Capability Matrix ── */}
      <div className="mt-8">
        <FlatPanel
          title={
            <div className="flex items-center gap-2">
              <Shield className="size-4 text-teal" />
              <span>Role Permissions Matrix</span>
            </div>
          }
          bodyClassName="p-0 overflow-x-auto"
        >
          <table className="w-full min-w-[700px] text-left">
            <thead className="text-[12px] text-fog bg-void-900/40">
              <tr className="border-b border-fog-deep/60">
                <th className="px-5 py-2.5 font-medium">Capability / Permission</th>
                {rolesList.map((r) => (
                  <th key={r} className="px-3 py-2.5 text-center font-medium">
                    <span className={`inline-block rounded px-2 py-0.5 text-xs font-mono border ${ROLE_BADGE_STYLES[r]}`}>
                      {r}
                    </span>
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {DEFAULT_PERMS.map((perm) => (
                <tr
                  key={perm.key}
                  className="border-b border-fog-deep/30 last:border-0 hover:bg-paper/4 transition-colors"
                >
                  <td className="px-5 py-3">
                    <p className="text-[13px] font-medium text-paper">{perm.label}</p>
                    <p className="text-[11px] font-mono text-fog-deep">{perm.key}</p>
                  </td>
                  {rolesList.map((r) => {
                    const granted = rolePermissions[r]?.includes(perm.key) || r === "Super Admin";
                    return (
                      <td key={r} className="px-3 py-3 text-center">
                        {granted ? (
                          <div className="inline-flex size-5 items-center justify-center rounded-full bg-teal/15 text-teal">
                            <Check className="size-3.5 stroke-[2.5]" />
                          </div>
                        ) : (
                          <div className="inline-flex size-5 items-center justify-center rounded-full bg-void-900 text-fog-deep/40">
                            <X className="size-3" />
                          </div>
                        )}
                      </td>
                    );
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </FlatPanel>
      </div>

      {/* ── Super Admin Multi-Tenant & Global Model Control ── */}
      {isSuperAdmin && (
        <div className="mt-8">
          <div className="flex items-center gap-2 mb-4">
            <Building2 className="size-5 text-rose-400" />
            <h2 className="font-display text-[20px] font-medium text-rose-400">
              Super Admin Multi-Tenant Console
            </h2>
          </div>

          <div className="grid gap-5 lg:grid-cols-[minmax(0,1.3fr)_minmax(0,1fr)]">
            <FlatPanel title="Tenant Organisations Overview" bodyClassName="p-0 overflow-x-auto">
              <table className="w-full min-w-[500px] text-left">
                <thead className="text-[12px] text-fog bg-void-900/40">
                  <tr className="border-b border-fog-deep/60">
                    <th className="px-5 py-2.5 font-medium">Tenant Organisation</th>
                    <th className="px-5 py-2.5 text-right font-medium">Monitored Subnets</th>
                    <th className="px-5 py-2.5 font-medium">Sensor Mode</th>
                    <th className="px-5 py-2.5 text-fog font-medium">Status</th>
                  </tr>
                </thead>
                <tbody>
                  <tr className="border-b border-fog-deep/30 last:border-0 hover:bg-paper/4">
                    <td className="px-5 py-2.5 text-[13px] font-medium">{user?.org?.name || "Active Org"}</td>
                    <td className="mono px-5 py-2.5 text-right">3</td>
                    <td className="mono px-5 py-2.5 text-teal">Passive TAP</td>
                    <td className="mono px-5 py-2.5 text-teal">HEALTHY</td>
                  </tr>
                </tbody>
              </table>
            </FlatPanel>

            <FlatPanel title="Global World Model Version">
              <div className="space-y-3">
                <div className="flex items-center justify-between border-b border-fog-deep/40 pb-2">
                  <span className="text-[13px] text-fog">Production Version</span>
                  <span className="mono text-teal">{activeModel?.version || "wm-v4.2.1"}</span>
                </div>
                <div className="flex items-center justify-between border-b border-fog-deep/40 pb-2">
                  <span className="text-[13px] text-fog">CIC-IDS F1 Score</span>
                  <span className="mono text-amber">
                    {activeModel?.metrics?.cicIds?.f1 ? (activeModel.metrics.cicIds.f1 * 100).toFixed(1) + "%" : "99.4%"}
                  </span>
                </div>
                <div className="flex items-center justify-between border-b border-fog-deep/40 pb-2">
                  <span className="text-[13px] text-fog">CTU-13 F1 Score</span>
                  <span className="mono text-amber">
                    {activeModel?.metrics?.ctu13?.f1 ? (activeModel.metrics.ctu13.f1 * 100).toFixed(1) + "%" : "98.9%"}
                  </span>
                </div>
              </div>

              <div className="mt-4 flex flex-wrap gap-2">
                <ActionButton
                  onClick={() => toast.success(`Active production model: ${activeModel?.version || "wm-v4.2.1"}`)}
                >
                  Model Status: Operational
                </ActionButton>
              </div>
            </FlatPanel>
          </div>
        </div>
      )}
    </>
  );
}
