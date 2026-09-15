import { useState, useEffect } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { X, RefreshCw, Loader2, AlertCircle, ChevronLeft, ChevronRight } from "lucide-react";
import {
  ActionButton,
  HeroPanel,
  PageTitle,
  RiskBadge,
} from "@/components/app/panels";
import { ProbabilityTimeline } from "@/components/app/charts";
import { pageHead } from "@/lib/head";
import { probabilitySeries } from "@/lib/telemetry";
import { useAlerts, useUpdateAlert, type Alert } from "@/hooks/useApi";

export const Route = createFileRoute("/app/alerts")({
  head: pageHead(
    "Alerts and incident queue — Aegis Vantage",
    "Triage predicted compromises across new, acknowledged, investigating and resolved states.",
  ),
  component: AlertsQueue,
});

const COLUMNS = ["New", "Acknowledged", "Investigating", "Resolved"] as const;
const PAGE_LIMIT = 50;

function AlertsQueue() {
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState<Alert | null>(null);
  const [notes, setNotes] = useState("");

  const {
    data: paginatedData,
    isLoading,
    isError,
    refetch,
    isFetching,
  } = useAlerts({ page, limit: PAGE_LIMIT });

  const alerts = paginatedData?.data ?? [];
  const pagination = paginatedData?.pagination;
  const updateAlert = useUpdateAlert();

  // Keep selected alert panel in sync when the list refreshes
  useEffect(() => {
    if (!selected) return;
    const fresh = alerts.find((a) => a._id === selected._id);
    if (fresh) setSelected(fresh);
  }, [alerts]); // eslint-disable-line react-hooks/exhaustive-deps

  // Auto-poll every 15 seconds
  useEffect(() => {
    const id = setInterval(() => refetch(), 15_000);
    return () => clearInterval(id);
  }, [refetch]);

  function handleStatusUpdate(status: Alert["status"]) {
    if (!selected) return;
    updateAlert.mutate(
      { id: selected._id, status, notes: notes || undefined },
      { onSuccess: (updated) => setSelected(updated) },
    );
  }

  function openAlert(a: Alert) {
    setSelected(a);
    setNotes(a.notes ?? "");
  }

  return (
    <>
      <PageTitle
        title="Alerts and incident queue"
        note="Alerts appear here once a predicted probability crosses your threshold."
      />

      {/* ── Toolbar ─────────────────────────────────────── */}
      <div className="mb-4 flex items-center justify-between">
        <div className="flex items-center gap-2 text-[13px] text-fog">
          {pagination && (
            <span>
              {pagination.total} alert{pagination.total !== 1 ? "s" : ""} total
            </span>
          )}
          {isFetching && !isLoading && (
            <span className="flex items-center gap-1 text-teal">
              <Loader2 className="size-3 animate-spin" /> Refreshing…
            </span>
          )}
        </div>
        <button
          onClick={() => refetch()}
          disabled={isFetching}
          className="flex items-center gap-1.5 rounded-md border border-fog-deep bg-void-700 px-3 py-1.5 text-[13px] text-fog hover:text-paper disabled:opacity-50"
        >
          <RefreshCw className={`size-3.5 ${isFetching ? "animate-spin" : ""}`} />
          Refresh
        </button>
      </div>

      {/* ── Loading ─────────────────────────────────────── */}
      {isLoading && (
        <div className="flex h-48 items-center justify-center gap-2 text-fog">
          <Loader2 className="size-5 animate-spin" />
          <span>Loading alerts…</span>
        </div>
      )}

      {/* ── Error ───────────────────────────────────────── */}
      {isError && !isLoading && (
        <div className="flex h-48 flex-col items-center justify-center gap-3 text-fog">
          <AlertCircle className="size-6 text-red-400" />
          <p className="text-[14px]">Failed to load alerts from the server.</p>
          <button
            onClick={() => refetch()}
            className="rounded-md bg-void-700 px-3 py-1.5 text-[13px] hover:bg-void-600"
          >
            Try again
          </button>
        </div>
      )}

      {/* ── Kanban board ────────────────────────────────── */}
      {!isLoading && !isError && (
        <div className="grid gap-4 xl:grid-cols-4">
          {COLUMNS.map((col) => {
            const items = alerts.filter((a) => a.status === col);
            return (
              <div key={col} className="flat p-3">
                <div className="mb-3 flex items-center justify-between px-1">
                  <span className="text-[13px] font-medium">{col}</span>
                  <span className="mono text-fog">{items.length}</span>
                </div>
                <div className="space-y-2">
                  {items.map((a) => (
                    <button
                      key={a._id}
                      onClick={() => openAlert(a)}
                      className={`w-full rounded-md border bg-void-700 p-3 text-left transition-colors hover:bg-paper/4 ${
                        selected?._id === a._id
                          ? "border-teal/60"
                          : "border-fog-deep"
                      }`}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <RiskBadge state={a.state} />
                        <span className="mono flex size-6 items-center justify-center rounded-full bg-void-800 text-[11px] text-fog">
                          {a.assignedTo?.initials ?? "—"}
                        </span>
                      </div>
                      <p className="mono mt-2 truncate">{a.host}</p>
                      <p className="mt-1 text-[13px] text-fog">{a.stage}</p>
                      <p className="mono mt-1.5">{a.probability.toFixed(2)}</p>
                    </button>
                  ))}
                  {items.length === 0 && (
                    <p className="px-1 py-3 text-[13px] text-fog">
                      Nothing in this state.
                    </p>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* ── Pagination ──────────────────────────────────── */}
      {pagination && pagination.totalPages > 1 && (
        <div className="mt-4 flex items-center justify-center gap-3">
          <button
            onClick={() => setPage((p) => Math.max(1, p - 1))}
            disabled={page <= 1}
            className="flex items-center gap-1 rounded-md border border-fog-deep bg-void-700 px-3 py-1.5 text-[13px] text-fog hover:text-paper disabled:opacity-40"
          >
            <ChevronLeft className="size-3.5" /> Prev
          </button>
          <span className="mono text-[13px] text-fog">
            {page} / {pagination.totalPages}
          </span>
          <button
            onClick={() =>
              setPage((p) => Math.min(pagination.totalPages, p + 1))
            }
            disabled={page >= pagination.totalPages}
            className="flex items-center gap-1 rounded-md border border-fog-deep bg-void-700 px-3 py-1.5 text-[13px] text-fog hover:text-paper disabled:opacity-40"
          >
            Next <ChevronRight className="size-3.5" />
          </button>
        </div>
      )}

      {/* ── Detail side panel ───────────────────────────── */}
      {selected && (
        <aside className="fixed inset-y-0 right-0 z-30 w-[420px] overflow-y-auto p-4">
          <HeroPanel
            state={selected.state}
            className="min-h-full"
            title={selected.alertId}
            control={
              <button
                onClick={() => setSelected(null)}
                aria-label="Close alert detail"
                className="text-fog hover:text-paper"
              >
                <X className="size-4" />
              </button>
            }
          >
            <div className="flex items-center gap-3">
              <RiskBadge state={selected.state} />
              <span className="mono">{selected.host}</span>
              <span className="mono text-fog">{selected.ip}</span>
            </div>
            <p className="mt-4 text-[15px]">{selected.reason}</p>

            <div className="mt-5">
              <p className="text-[13px] font-medium">Probability trajectory</p>
              <ProbabilityTimeline
                series={probabilitySeries.slice(-16)}
                height={140}
                animate={false}
              />
            </div>

            <dl className="mt-4 space-y-2">
              {[
                ["Predicted stage", selected.stage],
                ["Probability", selected.probability.toFixed(2)],
                [
                  "Detected",
                  new Date(selected.detectedAt).toISOString().slice(11, 16) + "Z",
                ],
                ["Current status", selected.status],
                ["Assigned to", selected.assignedTo?.name || "Unassigned"],
              ].map(([k, v]) => (
                <div
                  key={k}
                  className="flex justify-between border-b border-[var(--glass-border)] pb-1.5"
                >
                  <dt className="text-[13px] text-fog">{k}</dt>
                  <dd className="mono">{v}</dd>
                </div>
              ))}
            </dl>

            <label className="mt-5 block">
              <span className="text-[13px] font-medium">Analyst notes</span>
              <textarea
                rows={3}
                value={notes}
                onChange={(e) => setNotes(e.target.value)}
                placeholder="What did you check, and what did you find?"
                className="mt-1.5 w-full rounded-md border border-fog-deep bg-void-700 px-3 py-2 text-[15px] outline-none placeholder:text-fog-deep focus:border-teal"
              />
            </label>

            {updateAlert.isError && (
              <p className="mt-2 flex items-center gap-1.5 text-[13px] text-red-400">
                <AlertCircle className="size-3.5" />
                Failed to update alert. Please try again.
              </p>
            )}

            <div className="mt-4 flex flex-wrap gap-2">
              <ActionButton
                onClick={() => handleStatusUpdate("Acknowledged")}
                disabled={
                  updateAlert.isPending || selected.status === "Acknowledged"
                }
              >
                {updateAlert.isPending ? (
                  <span className="flex items-center gap-1.5">
                    <Loader2 className="size-3.5 animate-spin" /> Saving…
                  </span>
                ) : (
                  "Acknowledge"
                )}
              </ActionButton>
              <ActionButton
                variant="ghost"
                onClick={() => handleStatusUpdate("Investigating")}
                disabled={
                  updateAlert.isPending || selected.status === "Investigating"
                }
              >
                Mark investigating
              </ActionButton>
              <ActionButton
                variant="ghost"
                onClick={() => handleStatusUpdate("Resolved")}
                disabled={
                  updateAlert.isPending || selected.status === "Resolved"
                }
              >
                Resolve
              </ActionButton>
            </div>
          </HeroPanel>
        </aside>
      )}
    </>
  );
}
