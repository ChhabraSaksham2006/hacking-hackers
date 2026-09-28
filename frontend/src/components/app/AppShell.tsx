import { useState } from "react";
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
  Menu,
  Network,
  ScrollText,
  Settings as SettingsIcon,
  Share2,
  Sliders,
  Table2,
  Upload,
  Users,
  LogOut,
  X,
  Shield,
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
  const [mobileOpen, setMobileOpen] = useState(false);
  const openAlerts = alerts?.data?.filter((a) => a.status !== "Resolved").length ?? 0;
  
  // Initialize global socket connection
  const { isConnected } = useSocket();

  return (
    <div className="network-field min-h-screen">
      <div className="flex min-h-screen">
        {/* Desktop Sidebar Rail - Hidden on screens below lg */}
        <nav
          aria-label="Primary"
          className="group/rail sticky top-0 z-20 hidden lg:flex h-screen w-[72px] shrink-0 flex-col border-r border-fog-deep/50 bg-void-800/80 backdrop-blur-md transition-[width] duration-200 hover:w-[220px]"
        >
          <Link
            to="/app/dashboard"
            className="flex h-14 items-center gap-3 overflow-hidden px-[18px]"
            title="Flow दृष्टि — Dashboard"
          >
            <div className="flex size-9 shrink-0 items-center justify-center rounded-lg bg-white p-1 shadow-sm ring-1 ring-black/10 transition-transform group-hover/rail:scale-105">
              <img
                src="/flow-drishti-icon.png"
                alt="Flow दृष्टि"
                className="size-7 object-contain"
              />
            </div>
            <span className="font-display text-[15px] font-bold whitespace-nowrap opacity-0 transition-opacity duration-200 group-hover/rail:opacity-100 text-paper">
              Flow <span className="text-teal font-sans">दृष्टि</span>
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

        {/* Mobile / Tablet Navigation Backdrop & Drawer */}
        {mobileOpen && (
          <div
            className="fixed inset-0 z-50 bg-void-950/80 backdrop-blur-sm lg:hidden"
            onClick={() => setMobileOpen(false)}
          >
            <nav
              aria-label="Mobile navigation"
              className="relative flex h-full w-[280px] max-w-[85vw] flex-col border-r border-fog-deep/60 bg-void-800 shadow-2xl"
              onClick={(e) => e.stopPropagation()}
            >
              <div className="flex h-14 items-center justify-between border-b border-fog-deep/50 px-4">
                <Link
                  to="/app/dashboard"
                  onClick={() => setMobileOpen(false)}
                  className="flex items-center gap-2.5"
                >
                  <div className="flex size-8 shrink-0 items-center justify-center rounded-lg bg-white p-1">
                    <img
                      src="/flow-drishti-icon.png"
                      alt="Flow दृष्टि"
                      className="size-6 object-contain"
                    />
                  </div>
                  <span className="font-display text-[15px] font-bold text-paper">
                    Flow <span className="text-teal font-sans">दृष्टि</span>
                  </span>
                </Link>
                <button
                  type="button"
                  onClick={() => setMobileOpen(false)}
                  className="rounded-lg p-1.5 text-fog hover:bg-void-700 hover:text-paper"
                  aria-label="Close menu"
                >
                  <X className="size-5" />
                </button>
              </div>

              <ul className="flex-1 overflow-y-auto px-2 py-3 space-y-0.5">
                {nav.map(({ to, label, icon: Icon }) => {
                  const active = pathname === to;
                  return (
                    <li key={to}>
                      <Link
                        to={to}
                        onClick={() => setMobileOpen(false)}
                        className={cn(
                          "flex items-center gap-3 rounded-lg px-3 py-2 text-[13px] font-medium transition-colors",
                          active
                            ? "bg-teal/15 text-teal font-semibold"
                            : "text-fog hover:bg-void-700/60 hover:text-paper",
                        )}
                      >
                        <Icon className="size-4 shrink-0" strokeWidth={1.75} />
                        <span>{label}</span>
                      </Link>
                    </li>
                  );
                })}
              </ul>

              <div className="border-t border-fog-deep/50 p-3">
                <button
                  onClick={() => {
                    setMobileOpen(false);
                    logout.mutate();
                  }}
                  disabled={logout.isPending}
                  className="flex w-full items-center gap-3 rounded-lg px-3 py-2 text-left text-[13px] font-medium text-fog hover:bg-void-700 hover:text-paper"
                >
                  <LogOut className="size-4 shrink-0" strokeWidth={1.75} />
                  <span>Log out</span>
                </button>
              </div>
            </nav>
          </div>
        )}

        <div className="flex min-w-0 flex-1 flex-col">
          {/* Responsive Header */}
          <header className="sticky top-0 z-30 flex h-14 items-center justify-between gap-2 sm:gap-4 border-b border-fog-deep/50 bg-void-900/90 px-3 sm:px-6 backdrop-blur-md">
            <div className="flex items-center gap-2 sm:gap-3.5 text-[13px] min-w-0">
              {/* Mobile Menu Hamburger */}
              <button
                type="button"
                onClick={() => setMobileOpen(true)}
                className="flex lg:hidden size-8.5 items-center justify-center rounded-lg border border-fog-deep/60 bg-void-800 text-fog hover:text-paper hover:bg-void-700 shrink-0"
                aria-label="Open navigation menu"
              >
                <Menu className="size-4.5" />
              </button>

              {/* Mobile Branding */}
              <Link
                to="/app/dashboard"
                className="flex lg:hidden items-center gap-2 shrink-0"
              >
                <div className="flex size-7 items-center justify-center rounded-md bg-white p-0.5 shadow-sm ring-1 ring-black/10">
                  <img
                    src="/flow-drishti-icon.png"
                    alt="Flow दृष्टि"
                    className="size-5 object-contain"
                  />
                </div>
                <span className="font-display text-[14px] font-bold text-paper hidden xs:inline whitespace-nowrap">
                  Flow <span className="text-teal font-sans">दृष्टि</span>
                </span>
              </Link>

              <span className="hidden sm:inline-block h-4 w-px bg-fog-deep shrink-0" />

              <span className="font-medium truncate max-w-[100px] sm:max-w-none text-paper/90">
                {user?.org?.name || (user?.name ? `${user.name}'s Organization` : "Organization")}
              </span>

              <span className="h-4 w-px bg-fog-deep shrink-0 hidden xs:inline-block" />

              <Link
                to="/app/alerts"
                className="text-fog whitespace-nowrap hover:text-paper text-[12px] sm:text-[13px] hidden xs:flex items-center gap-1"
              >
                <span className="mono text-crimson font-semibold">{openAlerts}</span>
                <span className="hidden sm:inline"> open</span> alerts
              </Link>
            </div>

            <div className="flex items-center gap-2 sm:gap-3 text-[13px] shrink-0">
              <div className="hidden md:block">
                <GoogleTranslate id="google_translate_app" />
              </div>
              <div 
                className="flex items-center gap-1.5 rounded-full border border-fog-deep/50 bg-void-800 px-2 py-1 text-[11px] font-medium text-fog"
                title={isConnected ? "Real-time updates active" : "Reconnecting..."}
              >
                <span className={cn("size-1.5 rounded-full shrink-0", isConnected ? "bg-teal shadow-[0_0_8px_1px_rgba(20,184,166,0.6)]" : "bg-crimson animate-pulse")} />
                <span className="hidden sm:inline">{isConnected ? "Connected" : "Offline"}</span>
              </div>
              <NotificationBell />
              <div className="flex items-center gap-2">
                <Link
                  to="/app/rbac"
                  className="hidden sm:inline-flex items-center gap-1 rounded border border-teal/40 bg-teal/10 px-2 py-0.5 text-[11px] font-mono text-teal hover:border-teal/80 transition-colors"
                  title="View Role & Permissions Matrix"
                >
                  <Shield className="size-3 text-teal" />
                  <span>{user?.role ?? "Analyst"}</span>
                </Link>
                <span className="mono flex size-7 sm:size-8 items-center justify-center rounded-full bg-void-700 text-[11px] font-medium text-paper">
                  {user?.initials ?? "SC"}
                </span>
              </div>
            </div>
          </header>

          <main className="flex-1 min-w-0 px-3.5 py-4 sm:px-6 sm:py-6 overflow-x-hidden">
            <div className="mx-auto w-full max-w-7xl flex flex-col gap-6">
              {children}
            </div>
          </main>
        </div>
      </div>
      <ConsolePanel />
    </div>
  );
}
