import { useState, useId } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { ActionButton, FlatPanel, PageTitle } from "@/components/app/panels";
import { Sparkline } from "@/components/app/charts";
import { pageHead } from "@/lib/head";
import {
  useReports,
  useReportPreview,
  useGenerateReport,
  useDeleteReport,
  useSegments,
  useAlerts,
  type ReportRecord,
} from "@/hooks/useApi";
import {
  FileDown,
  FileText,
  FileSpreadsheet,
  Download,
  Trash2,
  Loader2,
  CheckCircle2,
  AlertCircle,
  Calendar,
  Layers,
  ShieldAlert,
} from "lucide-react";

export const Route = createFileRoute("/app/reports")({
  head: pageHead(
    "Reports and export â€” Flow दृष्टि",
    "Build a PDF or CSV incident report from a time window, alert or segment and preview it before export.",
  ),
  component: Reports,
});

function formatBytes(bytes?: number): string {
  if (!bytes || bytes <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return `${(bytes / Math.pow(1024, i)).toFixed(1)} ${units[i]}`;
}

function formatDate(dateStr?: string | Date): string {
  if (!dateStr) return "â€”";
  const d = new Date(dateStr);
  return d.toISOString().replace("T", " ").slice(0, 16) + "Z";
}

function Reports() {
  const [timeWindow, setTimeWindow] = useState<string>("last 24 hours");
  const [segmentOrAlert, setSegmentOrAlert] = useState<string>("corp-core");
  const [format, setFormat] = useState<"PDF" | "CSV">("PDF");
  const [customName, setCustomName] = useState<string>("");
  const [customStart, setCustomStart] = useState<string>("");
  const [customEnd, setCustomEnd] = useState<string>("");
  const [downloadingId, setDownloadingId] = useState<string | null>(null);
  const [lastExported, setLastExported] = useState<ReportRecord | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  // Queries
  const { data: reportsData, isLoading: isLoadingReports, refetch: refetchReports } = useReports();
  const { data: segments = [] } = useSegments();
  const { data: alertsData } = useAlerts({ limit: 10 });
  const alerts = alertsData?.data ?? [];

  // Live preview query
  const isCustom = timeWindow === "custom";
  const {
    data: preview,
    isLoading: isLoadingPreview,
    isFetching: isFetchingPreview,
  } = useReportPreview({
    timeWindow: isCustom ? undefined : timeWindow,
    segmentOrAlert,
    startDate: isCustom && customStart ? new Date(customStart).toISOString() : undefined,
    endDate: isCustom && customEnd ? new Date(customEnd).toISOString() : undefined,
  });

  const generateReport = useGenerateReport();
  const deleteReport = useDeleteReport();

  // Export report handler
  const handleExport = async (e: React.FormEvent) => {
    e.preventDefault();
    setActionError(null);

    let start = new Date(Date.now() - 24 * 60 * 60 * 1000);
    let end = new Date();

    if (timeWindow === "last 7 days") {
      start = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
    } else if (timeWindow === "last 30 days") {
      start = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
    } else if (timeWindow.includes("2026-09-06")) {
      start = new Date("2026-09-06T14:00:00Z");
      end = new Date("2026-09-06T15:00:00Z");
    } else if (isCustom) {
      if (!customStart || !customEnd) {
        setActionError("Please select both start and end date for custom time window.");
        return;
      }
      start = new Date(customStart);
      end = new Date(customEnd);
      if (start > end) {
        setActionError("Start date cannot be after end date.");
        return;
      }
    }

    try {
      const scopeLabel = `${segmentOrAlert} Â· ${isCustom ? "custom" : timeWindow.replace("last ", "")}`;
      const res = await generateReport.mutateAsync({
        name: customName.trim() || undefined,
        scope: scopeLabel,
        format,
        timeWindow: {
          start: start.toISOString(),
          end: end.toISOString(),
        },
        segmentOrAlert,
      });

      setLastExported(res.report);
      setCustomName("");
      // Trigger instant download of the new report
      if (res.report?._id) {
        handleDownload(res.report._id, res.report.name);
      }
    } catch (err: any) {
      setActionError(err.message || "Failed to generate report");
    }
  };

  // Download handler
  const handleDownload = async (id: string, fileName: string) => {
    try {
      setDownloadingId(id);
      const res = await fetch(`/api/reports/${id}/download`, { credentials: "include" });
      if (!res.ok) {
        throw new Error("Download failed");
      }
      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = fileName;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
    } catch (err: any) {
      setActionError(err.message || "Could not download report file");
    } finally {
      setDownloadingId(null);
    }
  };

  // Delete handler
  const handleDelete = async (id: string) => {
    if (!confirm("Are you sure you want to delete this report?")) return;
    try {
      await deleteReport.mutateAsync(id);
      if (lastExported?._id === id) setLastExported(null);
    } catch (err: any) {
      setActionError(err.message || "Failed to delete report");
    }
  };

  const reportsList = reportsData?.data ?? [];

  return (
    <>
      <PageTitle title="Reports and export" />

      {actionError && (
        <div className="mb-5 flex items-center justify-between rounded-md border border-crimson/40 bg-crimson/10 px-4 py-3 text-[13px] text-crimson">
          <div className="flex items-center gap-2">
            <AlertCircle className="h-4 w-4 shrink-0" />
            <span>{actionError}</span>
          </div>
          <button
            onClick={() => setActionError(null)}
            className="text-[12px] underline opacity-80 hover:opacity-100"
          >
            Dismiss
          </button>
        </div>
      )}

      {lastExported && (
        <div className="mb-5 flex items-center justify-between rounded-md border border-teal/40 bg-teal/10 px-4 py-3 text-[13px] text-teal">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="h-4 w-4 shrink-0" />
            <span>
              Report <strong>{lastExported.name}</strong> successfully generated and downloaded!
            </span>
          </div>
          <button
            onClick={() => handleDownload(lastExported._id, lastExported.name)}
            className="flex items-center gap-1 text-[12px] font-medium underline"
          >
            <Download className="h-3 w-3" /> Re-download
          </button>
        </div>
      )}

      <div className="grid gap-5 lg:grid-cols-2">
        {/* Report Scope & Generation Form */}
        <FlatPanel title="Report scope">
          <form className="space-y-4" onSubmit={handleExport}>
            <label className="block">
              <span className="flex items-center gap-1.5 text-[13px] font-medium">
                <Calendar className="h-3.5 w-3.5 text-fog" />
                Time window
              </span>
              <select
                value={timeWindow}
                onChange={(e) => setTimeWindow(e.target.value)}
                className="mono mt-1.5 w-full rounded-md border border-fog-deep bg-void-700 px-3 py-2.5 text-[13px] outline-none transition focus:border-teal"
              >
                <option value="last 24 hours">last 24 hours</option>
                <option value="last 7 days">last 7 days</option>
                <option value="last 30 days">last 30 days</option>
                <option value="2026-09-06 14:00â€“15:00Z">2026-09-06 14:00â€“15:00Z (incident window)</option>
                <option value="custom">Custom date range...</option>
              </select>
            </label>

            {isCustom && (
              <div className="grid grid-cols-2 gap-3 rounded-md border border-fog-deep/60 bg-void-800 p-3">
                <label className="block">
                  <span className="text-[11px] text-fog">Start Date &amp; Time</span>
                  <input
                    type="datetime-local"
                    value={customStart}
                    onChange={(e) => setCustomStart(e.target.value)}
                    className="mono mt-1 w-full rounded border border-fog-deep bg-void-900 px-2 py-1.5 text-[12px] outline-none focus:border-teal"
                  />
                </label>
                <label className="block">
                  <span className="text-[11px] text-fog">End Date &amp; Time</span>
                  <input
                    type="datetime-local"
                    value={customEnd}
                    onChange={(e) => setCustomEnd(e.target.value)}
                    className="mono mt-1 w-full rounded border border-fog-deep bg-void-900 px-2 py-1.5 text-[12px] outline-none focus:border-teal"
                  />
                </label>
              </div>
            )}

            <label className="block">
              <span className="flex items-center gap-1.5 text-[13px] font-medium">
                <Layers className="h-3.5 w-3.5 text-fog" />
                Segment or alert
              </span>
              <select
                value={segmentOrAlert}
                onChange={(e) => setSegmentOrAlert(e.target.value)}
                className="mono mt-1.5 w-full rounded-md border border-fog-deep bg-void-700 px-3 py-2.5 text-[13px] outline-none transition focus:border-teal"
              >
                <optgroup label="Network Segments">
                  {segments.map((s) => (
                    <option key={s._id || s.name} value={s.name}>
                      {s.name} ({s.hosts} hosts Â· {s.trafficVolume} flows/s)
                    </option>
                  ))}
                  {segments.length === 0 && (
                    <>
                      <option value="corp-core">corp-core</option>
                      <option value="finance">finance</option>
                      <option value="dmz-edge">dmz-edge</option>
                    </>
                  )}
                </optgroup>

                {alerts.length > 0 && (
                  <optgroup label="Active Alerts">
                    {alerts.map((a) => (
                      <option key={a._id} value={`alert ${a.alertId}`}>
                        {a.alertId} â€” {a.host} ({a.stage})
                      </option>
                    ))}
                  </optgroup>
                )}
              </select>
            </label>

            <fieldset>
              <legend className="text-[13px] font-medium">Export format</legend>
              <div className="mt-2 flex gap-6 text-[13px]">
                <label className="flex cursor-pointer items-center gap-2">
                  <input
                    type="radio"
                    name="fmt"
                    value="PDF"
                    checked={format === "PDF"}
                    onChange={() => setFormat("PDF")}
                    className="accent-teal"
                  />
                  <span className="flex items-center gap-1.5">
                    <FileText className="h-3.5 w-3.5 text-teal" />
                    PDF <span className="text-[11px] text-fog">(formatted executive brief)</span>
                  </span>
                </label>
                <label className="flex cursor-pointer items-center gap-2">
                  <input
                    type="radio"
                    name="fmt"
                    value="CSV"
                    checked={format === "CSV"}
                    onChange={() => setFormat("CSV")}
                    className="accent-teal"
                  />
                  <span className="flex items-center gap-1.5">
                    <FileSpreadsheet className="h-3.5 w-3.5 text-amber" />
                    CSV <span className="text-[11px] text-fog">(raw network telemetry)</span>
                  </span>
                </label>
              </div>
            </fieldset>

            <label className="block">
              <span className="text-[12px] text-fog">Custom file name (optional)</span>
              <input
                type="text"
                value={customName}
                onChange={(e) => setCustomName(e.target.value)}
                placeholder={`incident-${segmentOrAlert.replace(/\s+/g, "-").toLowerCase()}.${format.toLowerCase()}`}
                className="mono mt-1.5 w-full rounded-md border border-fog-deep bg-void-700 px-3 py-2 text-[13px] outline-none transition placeholder:text-fog/40 focus:border-teal"
              />
            </label>

            <div className="pt-2">
              <ActionButton
                type="submit"
                disabled={generateReport.isPending}
                className="flex w-full items-center justify-center gap-2 py-2.5 font-medium"
              >
                {generateReport.isPending ? (
                  <>
                    <Loader2 className="h-4 w-4 animate-spin" />
                    Compiling report &amp; saving...
                  </>
                ) : (
                  <>
                    <FileDown className="h-4 w-4" />
                    Export report
                  </>
                )}
              </ActionButton>
            </div>
          </form>
        </FlatPanel>

        {/* Live Interactive Preview */}
        <FlatPanel
          title="Preview"
          control={
            isFetchingPreview ? (
              <span className="flex items-center gap-1 text-[11px] text-teal">
                <Loader2 className="h-3 w-3 animate-spin" /> Live syncing
              </span>
            ) : null
          }
        >
          <div className="relative rounded-md border border-fog-deep bg-void-900 p-5">
            {isLoadingPreview && !preview ? (
              <div className="flex h-64 flex-col items-center justify-center gap-2 text-fog">
                <Loader2 className="h-6 w-6 animate-spin text-teal" />
                <span className="text-[13px]">Analyzing network telemetry for preview...</span>
              </div>
            ) : (
              <>
                <div className="flex items-start justify-between">
                  <div>
                    <p className="font-display text-[18px] font-medium text-paper">
                      Incident report â€” {preview?.segmentOrAlert || segmentOrAlert}
                    </p>
                    <p className="mono mt-1 text-[12px] text-fog">
                      {formatDate(preview?.timeWindow?.start)} â†’ {formatDate(preview?.timeWindow?.end)}
                    </p>
                  </div>
                  {preview?.metrics?.riskLevel && (
                    <span
                      className={`rounded px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wider ${
                        preview.metrics.riskLevel === "CRITICAL"
                          ? "border border-crimson/40 bg-crimson/20 text-crimson"
                          : preview.metrics.riskLevel === "HIGH"
                            ? "border border-amber/40 bg-amber/20 text-amber"
                            : "border border-teal/40 bg-teal/20 text-teal"
                      }`}
                    >
                      {preview.metrics.riskLevel}
                    </span>
                  )}
                </div>

                <div className="mt-4">
                  <div className="flex items-center justify-between text-[11px] text-fog">
                    <span>Threat probability progression</span>
                    <span className="mono text-teal">
                      Peak: {preview?.metrics?.maxScore?.toFixed(2) || "0.88"}
                    </span>
                  </div>
                  <div className="mt-1">
                    <Sparkline
                      series={preview?.sparkline || [0.1, 0.24, 0.38, 0.5, 0.66, 0.8, 0.88]}
                    />
                  </div>
                </div>

                <div className="mt-4">
                  <div className="flex items-center justify-between">
                    <p className="text-[13px] font-medium text-paper">Flagged flows</p>
                    <span className="mono text-[11px] text-fog">
                      {preview?.metrics?.totalFlows || 0} total / {preview?.flaggedFlows?.length || 0} top
                    </span>
                  </div>
                  <div className="mono mt-1.5 space-y-1.5 text-[12px] text-fog">
                    {preview?.flaggedFlows && preview.flaggedFlows.length > 0 ? (
                      preview.flaggedFlows.slice(0, 3).map((f, i) => (
                        <div
                          key={`${f.src}-${f.dst}-${i}`}
                          className="flex items-center justify-between rounded bg-void-800/80 px-2 py-1"
                        >
                          <span className="truncate">
                            {f.src} â†’ {f.dst}
                          </span>
                          <span
                            className={`ml-2 font-semibold ${
                              f.score >= 0.8 ? "text-crimson" : "text-amber"
                            }`}
                          >
                            {f.score.toFixed(2)}
                          </span>
                        </div>
                      ))
                    ) : (
                      <p className="text-[12px] text-fog/60">No abnormal flows detected in this range.</p>
                    )}
                  </div>
                </div>

                <div className="mt-4 border-t border-fog-deep/40 pt-3">
                  <p className="flex items-center gap-1 text-[13px] font-medium text-paper">
                    <ShieldAlert className="h-3.5 w-3.5 text-teal" />
                    Explainability summary
                  </p>
                  <p className="mt-1 text-[12px] leading-relaxed text-fog">
                    {preview?.explainabilitySummary ||
                      "Elevated SYN/ACK ratio with SMB session fan-out; mapped to ATT&CK lateral movement."}
                  </p>
                </div>
              </>
            )}
          </div>
        </FlatPanel>
      </div>

      {/* Past Exports Table */}
      <FlatPanel className="mt-5" title="Past exports" bodyClassName="p-0">
        {isLoadingReports ? (
          <div className="flex h-32 items-center justify-center gap-2 text-fog">
            <Loader2 className="h-5 w-5 animate-spin text-teal" />
            <span className="text-[13px]">Loading export history...</span>
          </div>
        ) : reportsList.length === 0 ? (
          <div className="p-8 text-center text-fog">
            <FileDown className="mx-auto mb-2 h-8 w-8 opacity-40" />
            <p className="text-[13px] font-medium">No reports generated yet</p>
            <p className="mt-1 text-[12px] text-fog/70">
              Configure a scope above and click &ldquo;Export report&rdquo; to generate your first PDF or CSV report.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left">
              <thead className="text-[12px] text-fog">
                <tr className="border-b border-fog-deep/60 bg-void-800/40">
                  <th className="px-5 py-2.5 font-medium">File</th>
                  <th className="px-5 py-2.5 font-medium">Scope</th>
                  <th className="px-5 py-2.5 font-medium">Created</th>
                  <th className="px-5 py-2.5 font-medium">Status</th>
                  <th className="px-5 py-2.5 text-right font-medium">Size</th>
                  <th className="px-5 py-2.5 text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {reportsList.map((p) => {
                  const isCsv = p.format === "CSV" || p.name.toLowerCase().endsWith(".csv");
                  const isDownloading = downloadingId === p._id;

                  return (
                    <tr
                      key={p._id || p.name}
                      className="border-b border-fog-deep/40 last:border-0 hover:bg-paper/4"
                    >
                      <td className="mono px-5 py-2.5">
                        <div className="flex items-center gap-2">
                          {isCsv ? (
                            <FileSpreadsheet className="h-4 w-4 shrink-0 text-amber" />
                          ) : (
                            <FileText className="h-4 w-4 shrink-0 text-teal" />
                          )}
                          <span className="font-medium text-paper">{p.name}</span>
                        </div>
                      </td>
                      <td className="px-5 py-2.5 text-[13px] text-fog">{p.scope}</td>
                      <td className="mono px-5 py-2.5 text-[12px] text-fog">
                        {formatDate(p.createdAt)}
                      </td>
                      <td className="px-5 py-2.5">
                        <span
                          className={`inline-flex items-center gap-1 rounded px-2 py-0.5 text-[11px] font-medium ${
                            p.status === "complete"
                              ? "bg-teal/10 text-teal"
                              : p.status === "generating"
                                ? "animate-pulse bg-amber/10 text-amber"
                                : "bg-crimson/10 text-crimson"
                          }`}
                        >
                          {p.status || "complete"}
                        </span>
                      </td>
                      <td className="mono px-5 py-2.5 text-right text-[12px] text-fog">
                        {formatBytes(p.fileSize)}
                      </td>
                      <td className="px-5 py-2.5 text-right">
                        <div className="flex items-center justify-end gap-3">
                          <button
                            type="button"
                            onClick={() => handleDownload(p._id, p.name)}
                            disabled={isDownloading}
                            className="inline-flex items-center gap-1 text-[13px] text-teal transition hover:underline disabled:opacity-50"
                          >
                            {isDownloading ? (
                              <>
                                <Loader2 className="h-3.5 w-3.5 animate-spin" />
                                Downloading...
                              </>
                            ) : (
                              <>
                                <Download className="h-3.5 w-3.5" />
                                Download
                              </>
                            )}
                          </button>
                          <button
                            type="button"
                            onClick={() => handleDelete(p._id)}
                            className="text-fog transition hover:text-crimson"
                            title="Delete report"
                          >
                            <Trash2 className="h-3.5 w-3.5" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </FlatPanel>
    </>
  );
}
