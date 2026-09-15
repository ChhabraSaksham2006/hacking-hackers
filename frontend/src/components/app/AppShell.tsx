import { Link, useRouterState } from "@tanstack/react-router";
import {
  Activity,
  AlertTriangle,
  ClipboardList,
  Cpu,
  FileDown,
  FileSearch,
  Gauge,
  Layers,
  Network,
  ScrollText,
  Settings as SettingsIcon,
  Share2,
  Sliders,
  Table2,
  Upload,
  Users,
  LogOut,
} from "lucide-react";
import type { ReactNode } from "react";
import { useAlerts, useAuthMe, useLogout } from "@/hooks/useApi";
import { useSocket } from "@/hooks/useSocket";
import { cn } from "@/lib/utils";
import { ConsolePanel } from "./ConsolePanel";
import { NotificationBell } from "./notifications/NotificationBell";
import { GoogleTranslate } from "@/components/common/GoogleTranslate";

const nav = [
  { to: "/app/dashboard", label: "Dashboard", icon: Gauge },
  { to: "/app/network", label: "Network state", icon: Share2 },
  { to: "/app/alerts", label: "Alerts", icon: AlertTriangle },
  { to: "/app/explainability", label: "Explainability", icon: Activity },
  { to: "/app/explorer", label: "Flow explorer", icon: Table2 },
  { to: "/app/simulation", label: "Simulation", icon: Sliders },
  { to: "/app/demonstration", label: "Inference lab", icon: FileSearch },
  { to: "/app/benchmark", label: "Benchmarks", icon: Cpu },
  { to: "/app/topology", label: "Topology", icon: Layers },
  { to: "/app/ingestion", label: "Ingestion", icon: Upload },
  { to: "/app/reports", label: "Reports", icon: FileDown },
  { to: "/app/audit", label: "Audit log", icon: ScrollText },
  { to: "/app/rbac", label: "Roles", icon: Users },
  { to: "/app/settings", label: "Settings", icon: SettingsIcon },
] as const;

export function AppShell({ children }: { children: ReactNode }) {
  const pathname = useRouterState({ select: (s) => s.location.pathname });
  const { data: alerts } = useAlerts();
  const { data: user } = useAuthMe();
  const logout = useLogout();
  const openAlerts = alerts?.data?.filter((a) => a.status !== "Resolved").length ?? 0;
  
  // Initialize global socket connection
  const { isConnected } = useSocket();

  return (
    <div className="network-field min-h-screen">
      <div className="flex min-h-screen">
        <nav
          aria-label="Primary"
          className="group/rail sticky top-0 z-20 flex h-screen w-[72px] shrink-0 flex-col border-r border-fog-deep/50 bg-void-800/80 backdrop-blur-md transition-[width] duration-200 hover:w-[220px]"
        >
          <Link
            to="/app/dashboard"
            className="flex h-14 items-center gap-3 overflow-hidden px-[26px]"
          >
            <span className="size-[18px] shrink-0 rotate-45 rounded-[4px] border-2 border-teal" />
            <span className="font-display text-[15px] font-semibold whitespace-nowrap opacity-0 transition-opacity group-hover/rail:opacity-100">
              Aegis Vantage
            </span>
          </Link>
          <ul className="flex flex-1 flex-col gap-0.5 overflow-y-auto py-2">
            {nav.map(({ to, label, icon: Icon }) => {
              const active = pathname === to;
              return (
                <li key={to}>
                  <Link
                    to={to}
                    className={cn(
                      "flex items-center gap-3 overflow-hidden border-l-2 py-2.5 pr-3 pl-[24px] text-[13px] font-medium whitespace-nowrap transition-colors",
                      active
                        ? "border-teal bg-teal/8 text-paper"
                        : "border-transparent text-fog hover:text-paper",
                    )}
                  >
                    <Icon className="size-4 shrink-0" strokeWidth={1.75} />
                    <span className="opacity-0 transition-opacity group-hover/rail:opacity-100">
                      {label}
                    </span>
                  </Link>
                </li>
              );
            })}
          </ul>
          
          <div className="border-t border-fog-deep/50 py-2">
            <button
              onClick={() => logout.mutate()}
              disabled={logout.isPending}
              className="flex w-full items-center gap-3 overflow-hidden border-l-2 border-transparent py-2.5 pr-3 pl-[24px] text-left text-[13px] font-medium text-fog whitespace-nowrap transition-colors hover:text-paper"
            >
              <LogOut className="size-4 shrink-0" strokeWidth={1.75} />
              <span className="opacity-0 transition-opacity group-hover/rail:opacity-100">
                Log out
              </span>
            </button>
          </div>
        </nav>

        <div className="flex min-w-0 flex-1 flex-col">
          <header className="sticky top-0 z-10 flex h-14 items-center justify-between gap-4 border-b border-fog-deep/50 bg-void-900/75 px-6 backdrop-blur-md">
            <div className="flex items-center gap-4 text-[13px]">
              <span className="font-medium">{user?.org?.name ?? "Northwind Energy"}</span>
              <span className="h-4 w-px bg-fog-deep" />
              <span className="text-fog">
                <span className="mono text-crimson">{openAlerts}</span> open
                alerts
              </span>
            </div>
            <div className="flex items-center gap-3 text-[13px]">
              <GoogleTranslate id="google_translate_app" />
              <div 
                className="flex items-center gap-1.5 rounded-full border border-fog-deep/50 bg-void-800 px-2 py-1 text-[11px] font-medium text-fog"
                title={isConnected ? "Real-time updates active" : "Reconnecting..."}
              >
                <span className={cn("size-1.5 rounded-full", isConnected ? "bg-teal shadow-[0_0_8px_1px_rgba(20,184,166,0.6)]" : "bg-crimson animate-pulse")} />
                {isConnected ? "Connected" : "Offline"}
              </div>
              <NotificationBell />
              <div className="flex items-center gap-3">
                <span className="text-fog">{user?.role ?? "SOC Lead"}</span>
                <span className="mono flex size-8 items-center justify-center rounded-full bg-void-700 text-[11px] text-paper">
                  {user?.initials ?? "SC"}
                </span>
              </div>
            </div>
          </header>
          <main className="flex-1 px-6 py-6">{children}</main>
        </div>
      </div>
      <ConsolePanel />
    </div>
  );
}
