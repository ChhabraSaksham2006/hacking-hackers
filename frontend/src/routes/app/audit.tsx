import { useState, useEffect, useMemo } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { useQueryClient } from "@tanstack/react-query";
import {
  Activity,
  AlertTriangle,
  ArrowUpDown,
  Bell,
  CheckCircle2,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  ChevronUp,
  Cpu,
  Download,
  ExternalLink,
  Eye,
  FileSpreadsheet,
  FileText,
  Filter,
  Hash,
  Info,
  Key,
  Layers,
  Lock,
  LogOut,
  RefreshCw,
  Search,
  Server,
  Shield,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
  Sparkles,
  User,
  UserCheck,
  UserCog,
  Zap,
} from "lucide-react";
import { toast } from "sonner";
import { formatDistanceToNow, format } from "date-fns";

import { FlatPanel, GlassPanel, HeroPanel, PageTitle } from "@/components/app/panels";
import { pageHead } from "@/lib/head";
import {
  useAuditLogs,
  useAuditStats,
  useAuditFilters,
  type AuditEntryItem,
} from "@/hooks/useApi";
import { useSocket } from "@/hooks/useSocket";

export const Route = createFileRoute("/app/audit")({
  head: pageHead(
    "Audit Log — Flow दृष्टि",
    "Append-only cryptographic compliance ledger · Retained under SOC 2 Type II controls for 7 years.",
  ),
  component: AuditPage,
});

const CATEGORIES = [
  { id: "all", label: "All Activities" },
  { id: "alerts", label: "Alert Triage" },
  { id: "simulations", label: "World Model & Replay" },
  { id: "network", label: "Network Containment" },
  { id: "reports", label: "Forensic Reports" },
  { id: "models", label: "Neural Models" },
  { id: "auth", label: "Auth & Access" },
] as const;

function getEventBadge(event: string) {
  switch (event) {
    case "ALERT_ACKNOWLEDGED":
      return {
        label: "Alert Acknowledged",
        color: "text-amber-400 bg-amber-500/10 border-amber-500/25",
        icon: Bell,
      };
    case "ALERT_RESOLVED":
      return {
        label: "Alert Resolved",
        color: "text-emerald-400 bg-emerald-500/10 border-emerald-500/25",
        icon: CheckCircle2,
      };
    case "ALERT_INVESTIGATING":
      return {
        label: "Investigating Alert",
        color: "text-rose-400 bg-rose-500/10 border-rose-500/25",
        icon: AlertTriangle,
      };
    case "ALERT_ASSIGNED":
      return {
        label: "Alert Assigned",
        color: "text-amber-300 bg-amber-400/10 border-amber-400/25",
        icon: UserCheck,
      };
    case "INFERENCE_RUN":
      return {
        label: "Inference Executed",
        color: "text-teal bg-teal/10 border-teal/25",
        icon: Cpu,
      };
    case "SIMULATION_RUN":
      return {
        label: "Simulation Replay",
        color: "text-cyan-400 bg-cyan-500/10 border-cyan-500/25",
        icon: Activity,
      };
    case "SEGMENT_ISOLATED":
      return {
        label: "Segment Isolated",
        color: "text-purple-400 bg-purple-500/10 border-purple-500/25",
        icon: ShieldAlert,
      };
    case "SEGMENT_RESTORED":
      return {
        label: "Segment Restored",
        color: "text-indigo-400 bg-indigo-500/10 border-indigo-500/25",
        icon: ShieldCheck,
      };
    case "MODEL_PROMOTED":
      return {
        label: "Model Promoted",
        color: "text-sky-400 bg-sky-500/10 border-sky-500/25",
        icon: Sparkles,
      };
    case "MODEL_ROLLED_BACK":
      return {
        label: "Model Rollback",
        color: "text-orange-400 bg-orange-500/10 border-orange-500/25",
        icon: RefreshCw,
      };
    case "REPORT_GENERATED":
      return {
        label: "Report Generated",
        color: "text-blue-400 bg-blue-500/10 border-blue-500/25",
        icon: FileText,
      };
    case "INGESTION_COMPLETED":
    case "INGESTION_STARTED":
      return {
        label: "PCAP Ingestion",
        color: "text-blue-300 bg-blue-500/10 border-blue-500/25",
        icon: Layers,
      };
    case "LOGIN_SUCCESS":
      return {
        label: "Login Authenticated",
        color: "text-emerald-400 bg-emerald-500/10 border-emerald-500/25",
        icon: Key,
      };
    case "LOGIN_FAILED":
      return {
        label: "Auth Failed",
        color: "text-rose-400 bg-rose-500/10 border-rose-500/25",
        icon: ShieldX,
      };
    case "LOGOUT":
      return {
        label: "Session Terminated",
        color: "text-fog bg-fog/10 border-fog/20",
        icon: LogOut,
      };
    case "USER_ROLE_CHANGED":
      return {
        label: "RBAC Role Changed",
        color: "text-yellow-400 bg-yellow-500/10 border-yellow-500/25",
        icon: UserCog,
      };
    default:
      return {
        label: event.replace(/_/g, " "),
        color: "text-fog bg-fog-deep/20 border-fog-deep/40",
        icon: Info,
      };
  }
}

function AuditPage() {
  const queryClient = useQueryClient();
  const { socket, isConnected } = useSocket();

  // Filter & pagination states
  const [page, setPage] = useState<number>(1);
  const [limit] = useState<number>(15);
  const [actor, setActor] = useState<string>("all");
  const [category, setCategory] = useState<string>("all");
  const [eventFilter, setEventFilter] = useState<string>("all");
  const [search, setSearch] = useState<string>("");
  const [debouncedSearch, setDebouncedSearch] = useState<string>("");
  const [sort, setSort] = useState<"asc" | "desc">("desc");
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [isExporting, setIsExporting] = useState<boolean>(false);

  // Debounce search query
  useEffect(() => {
    const timer = setTimeout(() => {
      setDebouncedSearch(search);
      setPage(1);
    }, 280);
    return () => clearTimeout(timer);
  }, [search]);

  // Real-time socket event listener for audit log consistency
  useEffect(() => {
    if (!socket) return;
    const handleNewAudit = () => {
      queryClient.invalidateQueries({ queryKey: ["audit"] });
      queryClient.invalidateQueries({ queryKey: ["audit-stats"] });
      queryClient.invalidateQueries({ queryKey: ["audit-filters"] });
    };

    socket.on("audit_created", handleNewAudit);
    socket.on("alert_updated", handleNewAudit);

    return () => {
      socket.off("audit_created", handleNewAudit);
      socket.off("alert_updated", handleNewAudit);
    };
  }, [socket, queryClient]);

  // Queries
  const {
    data: auditData,
    isLoading,
    isRefetching,
    refetch,
  } = useAuditLogs({
    page,
    limit,
    actor,
    category,
    event: eventFilter,
    search: debouncedSearch,
    sort,
  });

  const { data: stats } = useAuditStats();
  const { data: filters } = useAuditFilters();

  const entries = auditData?.data || [];
  const pagination = auditData?.pagination || {
    page: 1,
    limit: 15,
    total: 0,
    totalPages: 1,
    hasNext: false,
    hasPrev: false,
  };

  const handleExport = async (formatType: "csv" | "json") => {
    try {
      setIsExporting(true);
      const queryParams = new URLSearchParams();
      if (actor !== "all") queryParams.set("actor", actor);
      if (category !== "all") queryParams.set("category", category);
      if (eventFilter !== "all") queryParams.set("event", eventFilter);
      if (debouncedSearch.trim()) queryParams.set("search", debouncedSearch.trim());
      queryParams.set("format", formatType);

      const targetUrl = import.meta.env.DEV 
        ? `http://localhost:5000/api/audit/export?${queryParams.toString()}` 
        : `/api/audit/export?${queryParams.toString()}`;
      const res = await fetch(targetUrl, {
        credentials: "include",
      });

      if (!res.ok) throw new Error("Export download failed");

      const blob = await res.blob();
      const downloadUrl = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = downloadUrl;
      link.download = `aegis-audit-ledger-${new Date().toISOString().slice(0, 10)}.${formatType}`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(downloadUrl);

      toast.success(`Audit ledger exported as ${formatType.toUpperCase()}`);
    } catch (err: any) {
      toast.error(err?.message || "Failed to download audit logs");
    } finally {
      setIsExporting(false);
    }
  };

  const handleResetFilters = () => {
    setActor("all");
    setCategory("all");
    setEventFilter("all");
    setSearch("");
    setDebouncedSearch("");
    setPage(1);
  };

  const hasActiveFilters =
    actor !== "all" || category !== "all" || eventFilter !== "all" || debouncedSearch !== "";

  return (
    <>
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <PageTitle
          title="Audit Log & Compliance Trail"
          note="Cryptographically chained, immutable append-only ledger synchronized with live detection telemetry."
        />

        <div className="flex items-center gap-2">
          {/* Socket stream status indicator */}
          <div
            className={`flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[11px] font-mono transition-colors ${
              isConnected
                ? "border-teal/30 bg-teal/10 text-teal"
                : "border-fog-deep/40 bg-void-700 text-fog"
            }`}
          >
            <span
              className={`size-1.5 rounded-full ${
                isConnected ? "animate-pulse bg-teal" : "bg-fog"
              }`}
            />
            {isConnected ? "Live Socket Active" : "Polling"}
          </div>

          {/* Export buttons */}
          <button
            onClick={() => handleExport("csv")}
            disabled={isExporting}
            className="flex items-center gap-1.5 rounded-md border border-fog-deep/60 bg-void-700 px-3 py-1.5 text-[12px] font-medium text-paper transition hover:border-fog hover:bg-void-600 disabled:opacity-50"
            title="Download CSV for compliance filing"
          >
            <Download className="size-3.5" />
            CSV
          </button>
          <button
            onClick={() => handleExport("json")}
            disabled={isExporting}
            className="flex items-center gap-1.5 rounded-md border border-fog-deep/60 bg-void-700 px-3 py-1.5 text-[12px] font-medium text-paper transition hover:border-fog hover:bg-void-600 disabled:opacity-50"
            title="Download JSON forensic archive"
          >
            <FileSpreadsheet className="size-3.5" />
            JSON
          </button>
          <button
            onClick={() => refetch()}
            disabled={isLoading || isRefetching}
            className="flex size-8 items-center justify-center rounded-md border border-fog-deep/60 bg-void-700 text-fog transition hover:text-paper hover:bg-void-600"
            title="Refresh audit entries"
          >
            <RefreshCw className={`size-3.5 ${isRefetching ? "animate-spin text-teal" : ""}`} />
          </button>
        </div>
      </div>

      {/* â”€â”€ Metric Highlights & Cryptographic Seal Strip â”€â”€ */}
      <div className="my-5 grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <GlassPanel className="p-3.5">
          <div className="flex items-center justify-between">
            <span className="text-[12px] font-medium text-fog">Total Ledger Records</span>
            <ShieldCheck className="size-4 text-teal" />
          </div>
          <div className="mt-1.5 flex items-baseline gap-2">
            <span className="font-display text-2xl font-bold tracking-tight text-paper">
              {stats?.totalEntries?.toLocaleString() ?? "—"}
            </span>
            <span className="mono text-[11px] text-teal">Append-Only</span>
          </div>
          <p className="mt-1 text-[11px] text-fog">
            All administrative, ML inference, and triage events.
          </p>
        </GlassPanel>

        <GlassPanel className="p-3.5">
          <div className="flex items-center justify-between">
            <span className="text-[12px] font-medium text-fog">24-Hour Velocity</span>
            <Activity className="size-4 text-cyan-400" />
          </div>
          <div className="mt-1.5 flex items-baseline gap-2">
            <span className="font-display text-2xl font-bold tracking-tight text-paper">
              {stats?.todayCount ?? "0"}
            </span>
            <span className="mono text-[11px] text-fog">
              ({stats?.recentVelocity ?? 0} in last hr)
            </span>
          </div>
          <p className="mt-1 text-[11px] text-fog">
            Actions performed across estate in the last 24h.
          </p>
        </GlassPanel>

        <GlassPanel className="p-3.5">
          <div className="flex items-center justify-between">
            <span className="text-[12px] font-medium text-fog">Compliance Standard</span>
            <Lock className="size-4 text-purple-400" />
          </div>
          <div className="mt-1.5 flex items-baseline gap-2">
            <span className="font-display text-lg font-semibold tracking-tight text-paper">
              SOC 2 Type II
            </span>
            <span className="mono text-[11px] text-purple-300">ISO 27001</span>
          </div>
          <p className="mt-1 text-[11px] text-fog">
            7-year guaranteed immutable forensic retention.
          </p>
        </GlassPanel>

        <GlassPanel className="p-3.5">
          <div className="flex items-center justify-between">
            <span className="text-[12px] font-medium text-fog">Chained SHA-256 Digest</span>
            <Hash className="size-4 text-amber-400" />
          </div>
          <div className="mt-1.5 flex items-baseline gap-1">
            <span
              className="mono truncate text-[12px] font-semibold text-amber-300 cursor-pointer hover:underline"
              title={stats?.integrity?.chainedHash || "Verified"}
              onClick={() => {
                if (stats?.integrity?.chainedHash) {
                  navigator.clipboard.writeText(stats.integrity.chainedHash);
                  toast.success("Cryptographic root hash copied to clipboard");
                }
              }}
            >
              {stats?.integrity?.chainedHash
                ? `${stats.integrity.chainedHash.slice(0, 14)}...`
                : "VERIFIED"}
            </span>
            <span className="rounded bg-amber-500/10 px-1 py-0.5 text-[10px] text-amber-400">
              Verified
            </span>
          </div>
          <p className="mt-1 text-[11px] text-fog">
            Click to copy root cryptographic ledger seal.
          </p>
        </GlassPanel>
      </div>

      {/* â”€â”€ Category Quick-Filter Tabs â”€â”€ */}
      <div className="mb-4 flex flex-wrap items-center gap-1.5 border-b border-fog-deep/40 pb-3">
        {CATEGORIES.map((cat) => {
          const isActive = category === cat.id;
          const count =
            cat.id === "all"
              ? stats?.totalEntries
              : stats?.categoryCounts?.[cat.id as keyof typeof stats.categoryCounts];

          return (
            <button
              key={cat.id}
              onClick={() => {
                setCategory(cat.id);
                setEventFilter("all");
                setPage(1);
              }}
              className={`flex items-center gap-2 rounded-full px-3 py-1 text-[12px] font-medium transition ${
                isActive
                  ? "bg-teal text-void-950 shadow-sm shadow-teal/30"
                  : "bg-void-700/60 text-fog hover:bg-void-600 hover:text-paper"
              }`}
            >
              <span>{cat.label}</span>
              {typeof count === "number" && (
                <span
                  className={`mono rounded-full px-1.5 py-0.2 text-[10px] ${
                    isActive ? "bg-void-950/20 text-void-950" : "bg-void-800 text-fog"
                  }`}
                >
                  {count}
                </span>
              )}
            </button>
          );
        })}
      </div>

      {/* â”€â”€ Interactive Filter & Search Bar â”€â”€ */}
      <div className="mb-4 grid grid-cols-1 gap-3 sm:grid-cols-12">
        {/* Search input */}
        <div className="relative sm:col-span-5">
          <Search className="absolute left-3 top-2.5 size-4 text-fog" />
          <input
            type="text"
            placeholder="Search by target, host IP, actor, alert ID..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full rounded-md border border-fog-deep/60 bg-void-800 py-2 pl-9 pr-3 text-[13px] text-paper placeholder-fog outline-none focus:border-teal"
          />
        </div>

        {/* Actor dropdown */}
        <div className="sm:col-span-3">
          <select
            value={actor}
            onChange={(e) => {
              setActor(e.target.value);
              setPage(1);
            }}
            aria-label="Filter by actor"
            className="mono w-full rounded-md border border-fog-deep/60 bg-void-800 px-3 py-2 text-[13px] text-paper outline-none focus:border-teal"
          >
            <option value="all">All Actors</option>
            {filters?.actors?.map((a) => (
              <option key={a} value={a}>
                {a}
              </option>
            ))}
          </select>
        </div>

        {/* Event filter dropdown */}
        <div className="sm:col-span-3">
          <select
            value={eventFilter}
            onChange={(e) => {
              setEventFilter(e.target.value);
              setPage(1);
            }}
            aria-label="Filter by specific event"
            className="mono w-full rounded-md border border-fog-deep/60 bg-void-800 px-3 py-2 text-[13px] text-paper outline-none focus:border-teal"
          >
            <option value="all">All Event Types</option>
            {filters?.events?.map((ev) => (
              <option key={ev} value={ev}>
                {ev.replace(/_/g, " ")}
              </option>
            ))}
          </select>
        </div>

        {/* Sort Toggle */}
        <div className="flex items-center gap-1 sm:col-span-1">
          <button
            onClick={() => setSort((s) => (s === "desc" ? "asc" : "desc"))}
            className="flex w-full items-center justify-center gap-1 rounded-md border border-fog-deep/60 bg-void-800 py-2 text-[12px] text-fog transition hover:border-fog hover:text-paper"
            title={`Sort order: ${sort === "desc" ? "Newest first" : "Oldest first"}`}
          >
            <ArrowUpDown className="size-3.5" />
            <span className="mono uppercase">{sort}</span>
          </button>
        </div>
      </div>

      {hasActiveFilters && (
        <div className="mb-3 flex items-center justify-between text-[12px] text-fog">
          <span>Active filters applied</span>
          <button
            onClick={handleResetFilters}
            className="text-teal underline underline-offset-2 hover:text-teal/80"
          >
            Clear all filters
          </button>
        </div>
      )}

      {/* â”€â”€ Audit Ledger Table â”€â”€ */}
      <FlatPanel bodyClassName="p-0 overflow-x-auto">
        <table className="w-full min-w-[700px] text-left">
          <thead className="border-b border-fog-deep/60 bg-void-800/50 text-[11px] uppercase tracking-wider text-fog">
            <tr>
              <th className="px-5 py-3 font-medium">Timestamp</th>
              <th className="px-5 py-3 font-medium">Actor</th>
              <th className="px-5 py-3 font-medium">Action Event</th>
              <th className="px-5 py-3 font-medium">Target / Entity</th>
              <th className="px-5 py-3 font-medium">Network / IP</th>
              <th className="px-5 py-3 text-right font-medium">Forensic Context</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-fog-deep/30">
            {isLoading ? (
              <tr>
                <td colSpan={6} className="px-5 py-12 text-center text-[13px] text-fog">
                  <div className="flex flex-col items-center justify-center gap-2">
                    <RefreshCw className="size-5 animate-spin text-teal" />
                    <span>Querying cryptographic compliance ledger...</span>
                  </div>
                </td>
              </tr>
            ) : entries.length === 0 ? (
              <tr>
                <td colSpan={6} className="px-5 py-12 text-center text-fog">
                  <div className="flex flex-col items-center justify-center gap-2">
                    <Shield className="size-8 text-fog/40" />
                    <p className="text-[14px] font-medium text-paper">No Audit Entries Found</p>
                    <p className="text-[12px] text-fog">
                      {hasActiveFilters
                        ? "No events match the selected filters. Try widening your search or clearing filters."
                        : "No actions have been recorded yet."}
                    </p>
                    {hasActiveFilters && (
                      <button
                        onClick={handleResetFilters}
                        className="mt-2 rounded-md bg-void-700 px-3 py-1 text-[12px] text-teal hover:bg-void-600"
                      >
                        Reset Filters
                      </button>
                    )}
                  </div>
                </td>
              </tr>
            ) : (
              entries.map((e) => {
                const badge = getEventBadge(e.event);
                const BadgeIcon = badge.icon;
                const isExpanded = expandedId === e._id;
                const dateObj = new Date(e.timestamp);
                const formattedTime = !isNaN(dateObj.getTime())
                  ? format(dateObj, "yyyy-MM-dd HH:mm:ss")
                  : e.timestamp;
                const relativeTime = !isNaN(dateObj.getTime())
                  ? formatDistanceToNow(dateObj, { addSuffix: true })
                  : "";

                return (
                  <tr
                    key={e._id}
                    className="group transition-colors hover:bg-paper/5"
                  >
                    {/* Timestamp */}
                    <td className="px-5 py-3 text-[12px]">
                      <div className="mono font-medium text-paper">{formattedTime}</div>
                      <div className="text-[11px] text-fog">{relativeTime}</div>
                    </td>

                    {/* Actor */}
                    <td className="px-5 py-3">
                      <div className="flex items-center gap-2">
                        <div className="flex size-6 items-center justify-center rounded-full bg-void-700 text-[11px] font-mono text-paper">
                          {e.actor.charAt(0).toUpperCase()}
                        </div>
                        <div className="max-w-[170px] truncate text-[12px] font-mono text-paper" title={e.actor}>
                          {e.actor}
                        </div>
                      </div>
                    </td>

                    {/* Action Event Badge */}
                    <td className="px-5 py-3">
                      <span
                        className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-[11px] font-medium ${badge.color}`}
                      >
                        <BadgeIcon className="size-3" />
                        {badge.label}
                      </span>
                    </td>

                    {/* Target */}
                    <td className="px-5 py-3">
                      <div
                        className="mono max-w-[240px] truncate text-[12px] text-paper font-medium"
                        title={e.target}
                      >
                        {e.target}
                      </div>
                    </td>

                    {/* IP Address */}
                    <td className="px-5 py-3">
                      <span className="mono text-[11px] text-fog">
                        {e.ip || "127.0.0.1"}
                      </span>
                    </td>

                    {/* Forensic Context & Expand Button */}
                    <td className="px-5 py-3 text-right">
                      {e.metadata && Object.keys(e.metadata).length > 0 ? (
                        <button
                          onClick={() => setExpandedId(isExpanded ? null : e._id)}
                          className="inline-flex items-center gap-1 rounded bg-void-700 px-2 py-1 text-[11px] font-mono text-fog transition hover:bg-void-600 hover:text-paper"
                        >
                          <Eye className="size-3" />
                          <span>{isExpanded ? "Hide" : "Details"}</span>
                          {isExpanded ? (
                            <ChevronUp className="size-3" />
                          ) : (
                            <ChevronDown className="size-3" />
                          )}
                        </button>
                      ) : (
                        <span className="mono text-[11px] text-fog/60">—</span>
                      )}
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>

        {/* Expanded Metadata Drawer */}
        {expandedId && (
          <div className="border-t border-fog-deep/40 bg-void-900/90 p-4">
            {(() => {
              const current = entries.find((x) => x._id === expandedId);
              if (!current || !current.metadata) return null;

              return (
                <div className="flex flex-col gap-2">
                  <div className="flex items-center justify-between">
                    <span className="text-[12px] font-medium text-paper">
                      Forensic Telemetry Metadata · {current.event} ({current.target})
                    </span>
                    <button
                      onClick={() => setExpandedId(null)}
                      className="text-[11px] text-fog hover:text-paper"
                    >
                      Close
                    </button>
                  </div>
                  <pre className="mono max-h-48 overflow-auto rounded bg-void-950 p-3 text-[11px] text-teal">
                    {JSON.stringify(current.metadata, null, 2)}
                  </pre>
                </div>
              );
            })()}
          </div>
        )}

        {/* â”€â”€ Pagination Controls â”€â”€ */}
        <div className="flex flex-col items-center justify-between gap-3 border-t border-fog-deep/40 px-5 py-3 sm:flex-row">
          <div className="text-[12px] text-fog">
            Showing{" "}
            <span className="mono font-medium text-paper">
              {entries.length > 0 ? (pagination.page - 1) * pagination.limit + 1 : 0}
            </span>{" "}
            to{" "}
            <span className="mono font-medium text-paper">
              {Math.min(pagination.page * pagination.limit, pagination.total)}
            </span>{" "}
            of <span className="mono font-medium text-paper">{pagination.total}</span> entries
          </div>

          <div className="flex items-center gap-1.5">
            <button
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={pagination.page <= 1}
              className="flex items-center gap-1 rounded-md border border-fog-deep/60 bg-void-700 px-3 py-1.5 text-[12px] font-medium text-paper transition hover:border-fog hover:bg-void-600 disabled:opacity-30 disabled:hover:border-fog-deep/60 disabled:hover:bg-void-700"
            >
              <ChevronLeft className="size-3.5" />
              Previous
            </button>

            <span className="mono px-2 text-[12px] text-fog">
              Page {pagination.page} of {Math.max(1, pagination.totalPages)}
            </span>

            <button
              onClick={() => setPage((p) => (p < pagination.totalPages ? p + 1 : p))}
              disabled={pagination.page >= pagination.totalPages}
              className="flex items-center gap-1 rounded-md border border-fog-deep/60 bg-void-700 px-3 py-1.5 text-[12px] font-medium text-paper transition hover:border-fog hover:bg-void-600 disabled:opacity-30 disabled:hover:border-fog-deep/60 disabled:hover:bg-void-700"
            >
              Next
              <ChevronRight className="size-3.5" />
            </button>
          </div>
        </div>
      </FlatPanel>
    </>
  );
}
