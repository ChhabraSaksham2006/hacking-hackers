import { useState, useEffect } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { X, GripVertical, Lock } from "lucide-react";
import {
  DndContext,
  DragOverlay,
  closestCorners,
  KeyboardSensor,
  PointerSensor,
  useDroppable,
  useSensor,
  useSensors,
  type DragEndEvent,
  type DragStartEvent,
} from "@dnd-kit/core";
import {
  SortableContext,
  useSortable,
  verticalListSortingStrategy,
  sortableKeyboardCoordinates,
} from "@dnd-kit/sortable";
import { CSS } from "@dnd-kit/utilities";
import { useQueryClient } from "@tanstack/react-query";

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
import { useSocket } from "@/hooks/useSocket";
import { usePermissions } from "@/hooks/usePermissions";
import { toast } from "sonner";

export const Route = createFileRoute("/app/alerts")({
  head: pageHead(
    "Alerts and incident queue — Flow दृष्टि",
    "Triage predicted compromises across new, acknowledged, investigating and resolved states.",
  ),
  component: AlertsQueue,
});

const columns = ["New", "Acknowledged", "Investigating", "Resolved"] as const;

function DroppableColumn({ id, children, title, count }: { id: string, children: React.ReactNode, title: string, count: number }) {
  const { setNodeRef } = useDroppable({ id });
  return (
    <div ref={setNodeRef} className="flat p-3 flex flex-col">
      <div className="mb-3 flex items-center justify-between px-1">
        <span className="text-[13px] font-medium">{title}</span>
        <span className="mono text-fog">{count}</span>
      </div>
      {children}
    </div>
  );
}

function SortableAlertCard({
  alert,
  onClick,
  canUpdate,
}: {
  alert: Alert;
  onClick: () => void;
  canUpdate: boolean;
}) {
  const {
    attributes,
    listeners,
    setNodeRef,
    transform,
    transition,
    isDragging,
  } = useSortable({
    id: alert.alertId,
    data: { alert },
    disabled: !canUpdate,
  });

  const style = {
    transform: CSS.Transform.toString(transform),
    transition,
    opacity: isDragging ? 0.4 : 1,
  };

  return (
    <div
      ref={setNodeRef}
      style={style}
      className="relative mb-2 rounded-md border border-fog-deep bg-void-700 p-3 text-left hover:bg-paper/4 group/card touch-none"
    >
      <div 
        {...(canUpdate ? { ...attributes, ...listeners } : {})}
        onClick={(e) => {
          if (!canUpdate) {
            e.stopPropagation();
            toast.error("Analysts have read-only access. Only SOC Lead, Admin, or Super Admin can move or triage alerts.");
          }
        }}
        className={`absolute left-1 top-3 transition-opacity ${
          canUpdate
            ? "cursor-grab text-fog-deep hover:text-fog opacity-0 group-hover/card:opacity-100"
            : "cursor-not-allowed text-amber/70 opacity-70 hover:opacity-100"
        }`}
        title={canUpdate ? "Drag to update triage status" : "Read-only: Analysts cannot move alerts. SOC Lead or Admin required."}
      >
        {canUpdate ? <GripVertical className="size-4" /> : <Lock className="size-3.5" />}
      </div>
      <div className="pl-5 cursor-pointer" onClick={onClick}>
        <div className="flex items-center justify-between gap-2">
          <RiskBadge state={alert.state} />
          <span className="mono flex size-6 items-center justify-center rounded-full bg-void-800 text-[11px] text-fog">
            {alert.assignedTo?.initials ?? "—"}
          </span>
        </div>
        <p className="mono mt-2">{alert.host}</p>
        <p className="mt-1 text-[13px] text-fog">{alert.stage}</p>
        <p className="mono mt-1.5">{alert.probability.toFixed(2)}</p>
      </div>
    </div>
  );
}

function AlertCardOverlay({ alert }: { alert: Alert }) {
  return (
    <div className="mb-2 rounded-md border border-teal bg-void-700 p-3 text-left shadow-2xl opacity-90 pl-8">
      <div className="flex items-center justify-between gap-2">
        <RiskBadge state={alert.state} />
        <span className="mono flex size-6 items-center justify-center rounded-full bg-void-800 text-[11px] text-fog">
          {alert.assignedTo?.initials ?? "—"}
        </span>
      </div>
      <p className="mono mt-2">{alert.host}</p>
      <p className="mt-1 text-[13px] text-fog">{alert.stage}</p>
      <p className="mono mt-1.5">{alert.probability.toFixed(2)}</p>
    </div>
  );
}

function AlertsQueue() {
  const { data: paginatedData } = useAlerts();
  const alerts = paginatedData?.data ?? [];
  const updateAlert = useUpdateAlert();
  const queryClient = useQueryClient();
  const { socket } = useSocket();
  const { can } = usePermissions();
  const canUpdateAlerts = can("alerts.update");
  const [selected, setSelected] = useState<Alert | null>(null);
  
  // Local optimistic state for smooth drag and drop
  const [activeDragAlert, setActiveDragAlert] = useState<Alert | null>(null);

  // Real-time updates via Socket.io
  useEffect(() => {
    if (!socket) return;
    
    const handleUpdate = () => {
      // Invalidate the alerts query to fetch fresh data when an event is received
      queryClient.invalidateQueries({ queryKey: ["alerts"] });
    };

    socket.on("alert_created", handleUpdate);
    socket.on("alert_updated", handleUpdate);

    return () => {
      socket.off("alert_created", handleUpdate);
      socket.off("alert_updated", handleUpdate);
    };
  }, [socket, queryClient]);

  const sensors = useSensors(
    useSensor(PointerSensor, { activationConstraint: { distance: 5 } }),
    useSensor(KeyboardSensor, { coordinateGetter: sortableKeyboardCoordinates })
  );

  const handleDragStart = (event: DragStartEvent) => {
    if (!canUpdateAlerts) {
      toast.error("Analysts have read-only access. Only SOC Lead, Admin, or Super Admin can move or triage alerts.");
      return;
    }
    const { active } = event;
    const alert = alerts.find((a) => a.alertId === active.id);
    if (alert) setActiveDragAlert(alert);
  };

  const handleDragEnd = (event: DragEndEvent) => {
    setActiveDragAlert(null);
    const { active, over } = event;
    
    if (!over) return;

    if (!canUpdateAlerts) {
      toast.error("Analysts have read-only access. Only SOC Lead, Admin, or Super Admin can move or triage alerts.");
      return;
    }

    const alertId = active.id as string;
    const alert = alerts.find(a => a.alertId === alertId);
    if (!alert) return;

    // over.id can be either a column name (if dropped on empty space) or an alert alertId
    let newStatus = alert.status;
    
    if (columns.includes(over.id as any)) {
      newStatus = over.id as any;
    } else {
      const overAlert = alerts.find(a => a.alertId === over.id);
      if (overAlert) newStatus = overAlert.status;
    }

    if (alert.status !== newStatus) {
      // Optimistic update
      queryClient.setQueryData(["alerts", undefined], (old: any) => {
        if (!old) return old;
        return {
          ...old,
          data: old.data.map((a: Alert) => 
            a.alertId === alertId ? { ...a, status: newStatus } : a
          )
        };
      });

      // API call
      updateAlert.mutate({ id: alert.alertId, status: newStatus }, {
        onError: () => {
          // Revert on error
          queryClient.invalidateQueries({ queryKey: ["alerts"] });
        }
      });
    }
  };

  return (
    <>
      <PageTitle
        title="Alerts and incident queue"
        note={
          canUpdateAlerts
            ? "Alerts appear here once a predicted probability crosses your threshold. Drag cards to update triage status."
            : "Read-only triage mode for Analyst role. Switch to SOC Lead or Admin in Roles/RBAC to update alert status."
        }
      />

      <DndContext
        sensors={sensors}
        collisionDetection={closestCorners}
        onDragStart={handleDragStart}
        onDragEnd={handleDragEnd}
      >
        <div className="grid gap-4 grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 min-h-[500px]">
          {columns.map((col) => {
            const items = alerts.filter((a) => a.status === col);
            
            return (
              <DroppableColumn key={col} id={col} title={col} count={items.length}>
                {/* Column Drop Zone */}
                <SortableContext
                  id={col}
                  items={items.map(a => a.alertId)}
                  strategy={verticalListSortingStrategy}
                >
                  <div className="flex-1 space-y-2 min-h-[100px]">
                    {items.map((a) => (
                      <SortableAlertCard 
                        key={a.alertId} 
                        alert={a} 
                        onClick={() => setSelected(a)} 
                        canUpdate={canUpdateAlerts}
                      />
                    ))}
                    {items.length === 0 ? (
                      <p className="px-1 py-3 text-[13px] text-fog text-center border border-dashed border-fog-deep/50 rounded-md">
                        Drop alerts here
                      </p>
                    ) : null}
                  </div>
                </SortableContext>
              </DroppableColumn>
            );
          })}
        </div>

        <DragOverlay>
          {activeDragAlert ? (
            <AlertCardOverlay alert={activeDragAlert} />
          ) : null}
        </DragOverlay>
      </DndContext>

      {selected ? (
        <>
          <div
            className="fixed inset-0 z-30 bg-void-950/60 backdrop-blur-xs sm:hidden"
            onClick={() => setSelected(null)}
          />
          <aside className="fixed inset-y-0 right-0 z-30 w-full sm:w-[420px] max-w-full overflow-y-auto p-3 sm:p-4 bg-void-900/95 backdrop-blur-xl border-l border-fog-deep/50 shadow-2xl">
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
                ["Detected", new Date(selected.detectedAt).toISOString().slice(11, 16) + "Z"],
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
                placeholder="What did you check, and what did you find?"
                className="mt-1.5 w-full rounded-md border border-fog-deep bg-void-700 px-3 py-2 text-[15px] outline-none placeholder:text-fog-deep focus:border-teal"
              />
            </label>

            <div className="mt-4 flex flex-wrap gap-2">
              <ActionButton 
                onClick={() => {
                  if (!canUpdateAlerts) {
                    toast.error("Analysts have read-only access. Only SOC Lead, Admin, or Super Admin can acknowledge alerts.");
                    return;
                  }
                  updateAlert.mutate({ id: selected.alertId, status: "Acknowledged" });
                }}
                disabled={updateAlert.isPending}
                className={!canUpdateAlerts ? "opacity-60 cursor-not-allowed" : ""}
                title={canUpdateAlerts ? "Acknowledge alert" : "Requires SOC Lead, Admin, or Super Admin role"}
              >
                Acknowledge alert
              </ActionButton>
              <ActionButton 
                variant="ghost"
                onClick={() => {
                  if (!canUpdateAlerts) {
                    toast.error("Analysts have read-only access. Only SOC Lead, Admin, or Super Admin can mark alerts investigating.");
                    return;
                  }
                  updateAlert.mutate({ id: selected.alertId, status: "Investigating" });
                }}
                disabled={updateAlert.isPending}
                className={!canUpdateAlerts ? "opacity-60 cursor-not-allowed" : ""}
                title={canUpdateAlerts ? "Mark investigating" : "Requires SOC Lead, Admin, or Super Admin role"}
              >
                Mark investigating
              </ActionButton>
              <ActionButton 
                variant="ghost"
                onClick={() => {
                  if (!canUpdateAlerts) {
                    toast.error("Analysts have read-only access. Only SOC Lead, Admin, or Super Admin can assign alerts.");
                    return;
                  }
                }}
                className={!canUpdateAlerts ? "opacity-60 cursor-not-allowed" : ""}
                title={canUpdateAlerts ? "Assign to analyst" : "Requires SOC Lead, Admin, or Super Admin role"}
              >
                Assign to...
              </ActionButton>
            </div>
            {!canUpdateAlerts && (
              <p className="mt-3 text-xs font-mono text-amber border border-amber/30 bg-amber/10 px-2.5 py-1.5 rounded flex items-center gap-1.5">
                <Lock className="size-3.5 shrink-0" />
                <span>Read-only: Analysts cannot triage alerts. SOC Lead, Admin, or Super Admin role required.</span>
              </p>
            )}
          </HeroPanel>
        </aside>
      </>
    ) : null}
  </>
  );
}
