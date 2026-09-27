import { useState, useEffect, useRef } from "react";
import { createFileRoute, Link } from "@tanstack/react-router";
import {
  Activity,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Cpu,
  Layers,
  ArrowRight,
  Terminal,
  Zap,
  CheckCircle2,
  Clock,
  Sparkles,
  ExternalLink,
  ChevronRight,
  Server,
  Lock,
  Boxes,
  Eye,
  Crosshair,
  Menu,
  X,
} from "lucide-react";
import { HeroPanel, RiskBadge } from "@/components/app/panels";
import { ProbabilityTimeline, Sparkline } from "@/components/app/charts";
import { pageHead } from "@/lib/head";
import { probabilitySeries } from "@/lib/telemetry";
import { ThreeManifold } from "@/components/landing/ThreeManifold";
import { BackgroundDotEffect } from "@/components/landing/BackgroundDotEffect";
import { MathFormula } from "@/components/common/MathFormula";
import { GoogleTranslate } from "@/components/common/GoogleTranslate";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/")({
  head: pageHead(
    "Flow दृष्टि — Cyber World Model Defense",
    "Deep hybrid world model (SparseRSSM + TFCNet) forecasting attacker lateral movement and C2 progression before kill-chain completion.",
  ),
  component: Landing,
});

type DesignStrategy = "glass" | "minimalism" | "neomorphism";
type SectionId = "hero" | "comparison" | "architecture" | "testimonials" | "cta";

const SECTIONS: { id: SectionId; label: string; number: string }[] = [
  { id: "hero", label: "Neural Horizon", number: "01" },
  { id: "comparison", label: "Detection Gap", number: "02" },
  { id: "architecture", label: "World Model", number: "03" },
  { id: "testimonials", label: "SOC Intel", number: "04" },
  { id: "cta", label: "Deployment", number: "05" },
];

function Landing() {
  const [strategy, setStrategy] = useState<DesignStrategy>("glass");
  const [activeArchTab, setActiveArchTab] = useState<"rssm" | "tfcnet" | "fusion" | "features">("rssm");
  const [activeSection, setActiveSection] = useState<SectionId>("hero");
  const [focusModeEnabled, setFocusModeEnabled] = useState<boolean>(true);
  const [mobileMenuOpen, setMobileMenuOpen] = useState<boolean>(false);

  // Dynamic styling based on design strategy + hover enlargement
  const cardStyleClass =
    strategy === "glass"
      ? "strategy-glass rounded-2xl p-4 sm:p-6 transition-all duration-400 ease-out hover:border-teal/60 hover:shadow-[0_16px_48px_rgba(45,212,191,0.18)] sm:hover:scale-[1.02] sm:hover:-translate-y-1"
      : strategy === "minimalism"
      ? "strategy-minimal rounded-lg p-4 sm:p-6 transition-all duration-300 ease-out hover:border-paper/90 hover:shadow-lg sm:hover:scale-[1.015]"
      : "strategy-neomorph rounded-2xl p-4 sm:p-6 transition-all duration-400 ease-out hover:shadow-[9px_9px_22px_#05080e,-9px_-9px_22px_#1e293f] sm:hover:scale-[1.02]";

  const buttonPrimaryClass =
    strategy === "glass"
      ? "rounded-xl bg-teal px-5 py-3 text-sm font-semibold text-void-900 shadow-lg shadow-teal/25 transition-all duration-300 hover:bg-teal/90 hover:shadow-teal/50 hover:scale-[1.04] hover:-translate-y-0.5 active:scale-[0.98]"
      : strategy === "minimalism"
      ? "rounded-none border border-teal bg-teal/10 px-5 py-3 font-mono text-sm font-bold text-teal transition-all duration-200 hover:bg-teal hover:text-void-900 hover:shadow-[0_0_20px_rgba(45,212,191,0.4)]"
      : "rounded-xl bg-void-800 px-5 py-3 font-mono text-sm font-semibold text-teal shadow-[4px_4px_10px_#070a12,-4px_-4px_10px_#1e283d] transition-all duration-300 hover:scale-[1.03] hover:shadow-[inset_3px_3px_6px_#070a12,inset_-3px_-3px_6px_#1e283d]";

  const buttonSecondaryClass =
    strategy === "glass"
      ? "rounded-xl border border-fog-deep/60 bg-void-800/60 backdrop-blur-md px-5 py-3 text-sm font-semibold text-paper transition-all duration-300 hover:bg-void-700/80 hover:border-teal/50 hover:scale-[1.03]"
      : strategy === "minimalism"
      ? "rounded-none border border-fog-deep bg-void-900 px-5 py-3 font-mono text-sm font-medium text-paper transition-all duration-200 hover:bg-void-800 hover:border-paper"
      : "rounded-xl bg-void-800 px-5 py-3 font-mono text-sm font-medium text-paper shadow-[4px_4px_10px_#070a12,-4px_-4px_10px_#1e283d] transition-all duration-300 hover:scale-[1.02] hover:shadow-[inset_2px_2px_5px_#070a12,inset_-2px_-2px_5px_#1e283d]";

  // Scroll spotlight observer: focus shifts to the section currently in view
  useEffect(() => {
    const handleScroll = () => {
      const scrollPosition = window.scrollY + window.innerHeight * 0.42;

      for (const section of SECTIONS) {
        const el = document.getElementById(section.id);
        if (el) {
          const top = el.offsetTop;
          const height = el.offsetHeight;
          if (scrollPosition >= top && scrollPosition < top + height) {
            setActiveSection(section.id);
            break;
          }
        }
      }
    };

    window.addEventListener("scroll", handleScroll, { passive: true });
    handleScroll(); // initial check
    return () => window.removeEventListener("scroll", handleScroll);
  }, []);

  const scrollToSection = (id: SectionId) => {
    const el = document.getElementById(id);
    if (el) {
      el.scrollIntoView({ behavior: "smooth", block: "center" });
    }
  };

  const getSectionFocusClass = (id: SectionId) => {
    if (!focusModeEnabled) return "transition-all duration-500";
    return activeSection === id
      ? "scroll-spotlight-active relative"
      : "scroll-spotlight-dimmed relative";
  };

  return (
    <div className="relative min-h-screen selection:bg-teal selection:text-void-900 w-full max-w-[100vw] overflow-x-hidden bg-void-900">
      {/* ── Background Dot Effect ───────────────────────── */}
      <BackgroundDotEffect
        dotColor="rgba(148, 163, 184, 0.22)"
        glowColor="rgba(45, 212, 191, 0.85)"
        spacing={30}
        dotSize={1.4}
      />

      {/* ── Floating Right Rail: Scroll Focus Navigator ──── */}
      <div className="fixed right-4 top-1/2 -translate-y-1/2 z-40 hidden xl:flex flex-col items-end gap-3 pointer-events-auto">
        <div className="flex flex-col items-center gap-2.5 rounded-full border border-teal/30 bg-void-900/85 p-2 backdrop-blur-xl shadow-2xl shadow-teal/10">
          {SECTIONS.map((sec) => {
            const isFocused = activeSection === sec.id;
            return (
              <button
                key={sec.id}
                type="button"
                onClick={() => scrollToSection(sec.id)}
                title={`${sec.number}. ${sec.label}`}
                className="group relative flex items-center justify-center p-1.5 focus:outline-none"
              >
                {/* Floating tooltip label on hover */}
                <span className="pointer-events-none absolute right-full mr-3 whitespace-nowrap rounded-md border border-teal/40 bg-void-950/90 px-2 py-0.5 font-mono text-[11px] text-paper opacity-0 shadow-lg backdrop-blur-md transition-all group-hover:opacity-100 group-hover:-translate-x-1">
                  <span className="text-teal font-bold mr-1.5">{sec.number}</span>
                  {sec.label}
                </span>

                {/* Focus dot with animated ripple */}
                <span
                  className={cn(
                    "rounded-full transition-all duration-300",
                    isFocused
                      ? "size-3 bg-teal shadow-[0_0_12px_#2dd4bf] scale-125 ring-2 ring-teal/40"
                      : "size-2 bg-fog-deep/80 group-hover:bg-paper group-hover:scale-110"
                  )}
                />
              </button>
            );
          })}
        </div>

        {/* Scroll Focus Mode Toggle Pill */}
        <button
          type="button"
          onClick={() => setFocusModeEnabled(!focusModeEnabled)}
          className={cn(
            "flex items-center gap-1.5 rounded-full border px-2.5 py-1 font-mono text-[10px] backdrop-blur-md transition-all shadow-md",
            focusModeEnabled
              ? "border-teal/50 bg-teal/15 text-teal shadow-teal/20"
              : "border-fog-deep/50 bg-void-900/80 text-fog hover:text-paper"
          )}
        >
          <Crosshair className={cn("size-3", focusModeEnabled && "animate-spin-slow text-teal")} />
          <span>Spotlight {focusModeEnabled ? "ON" : "OFF"}</span>
        </button>
      </div>

      {/* ── Top Strategy & Navigation Bar ────────────────── */}
      <header className="sticky top-0 z-50 border-b border-fog-deep/40 backdrop-blur-xl bg-void-900/90">
        <div className="mx-auto flex h-16 max-w-[1360px] items-center justify-between px-4 sm:px-6 md:px-12">
          {/* Brand Logo & Name */}
          <Link to="/" className="flex items-center gap-2.5 sm:gap-3 group shrink-0">
            <div className="flex size-8 sm:size-9 items-center justify-center rounded-lg bg-white p-1 shadow-sm ring-1 ring-black/10 transition-transform group-hover:scale-105">
              <img src="/flow-drishti-icon.png" alt="Flow दृष्टि" className="size-6 sm:size-7 object-contain" />
            </div>
            <span className="font-display text-base font-bold tracking-tight text-paper group-hover:text-teal transition-colors">
              Flow <span className="text-teal font-sans">दृष्टि</span>
            </span>
            <span className="hidden rounded-full border border-teal/40 bg-teal/10 px-2 py-0.5 font-mono text-[10px] text-teal sm:inline-block shadow-xs shadow-teal/30">
              wm-v4.2.1
            </span>
          </Link>

          {/* Center (Desktop): Google Translate & Strategy Badge */}
          <div className="hidden md:flex items-center gap-3">
            <GoogleTranslate id="google_translate_landing" />
            <div className="hidden lg:flex items-center gap-2 rounded-full border border-teal/40 bg-teal/10 px-3 py-1 backdrop-blur-xl shadow-xs shadow-teal/30">
              <span className="size-2 rounded-full bg-teal animate-pulse" />
              <span className="font-mono text-[11px] font-semibold text-teal tracking-wide">
                Cyber Glass
              </span>
            </div>
          </div>

          {/* Desktop Navigation CTA */}
          <nav className="hidden md:flex items-center gap-3">
            <Link
              to="/docs"
              className="font-mono text-[13px] text-fog hover:text-teal transition-colors px-2 py-1"
            >
              Whitepaper
            </Link>
            <Link
              to="/login"
              className="rounded-lg border border-fog-deep/60 px-3.5 py-1.5 font-mono text-[13px] text-paper hover:bg-void-700 transition-all hover:scale-105"
            >
              Log in
            </Link>
            <Link
              to="/app/dashboard"
              className="rounded-lg bg-teal px-3.5 py-1.5 font-mono text-[13px] font-semibold text-void-900 hover:bg-teal/90 transition-all shadow-md shadow-teal/30 hover:scale-105 active:scale-95"
            >
              Live Console
            </Link>
          </nav>

          {/* Mobile Right Controls: Live Console & Hamburger Menu */}
          <div className="flex md:hidden items-center gap-2">
            <Link
              to="/app/dashboard"
              className="rounded-lg bg-teal px-2.5 py-1 font-mono text-xs font-semibold text-void-900 shadow-sm"
            >
              Console
            </Link>
            <button
              type="button"
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
              className="flex size-9 items-center justify-center rounded-lg border border-fog-deep/50 bg-void-800 text-fog hover:text-paper focus:outline-none"
              aria-label="Toggle Navigation Menu"
            >
              {mobileMenuOpen ? <X className="size-5" /> : <Menu className="size-5" />}
            </button>
          </div>
        </div>

        {/* Mobile Dropdown Drawer */}
        {mobileMenuOpen && (
          <div className="md:hidden border-t border-fog-deep/40 bg-void-950/95 px-5 py-4 backdrop-blur-2xl transition-all animate-in slide-in-from-top-2 duration-200">
            <div className="flex flex-col gap-3">
              <div className="pb-2 border-b border-fog-deep/30">
                <GoogleTranslate id="google_translate_mobile" />
              </div>
              <Link
                to="/docs"
                onClick={() => setMobileMenuOpen(false)}
                className="flex items-center justify-between py-2 font-mono text-sm text-paper hover:text-teal"
              >
                <span>Whitepaper & Technical Docs</span>
                <ChevronRight className="size-4 text-fog" />
              </Link>
              <Link
                to="/login"
                onClick={() => setMobileMenuOpen(false)}
                className="flex items-center justify-between py-2 font-mono text-sm text-paper hover:text-teal"
              >
                <span>Log in to SOC Console</span>
                <ChevronRight className="size-4 text-fog" />
              </Link>
              <Link
                to="/security"
                onClick={() => setMobileMenuOpen(false)}
                className="flex items-center justify-between py-2 font-mono text-sm text-paper hover:text-teal"
              >
                <span>Security Architecture</span>
                <ChevronRight className="size-4 text-fog" />
              </Link>
              <Link
                to="/app/dashboard"
                onClick={() => setMobileMenuOpen(false)}
                className="mt-2 flex items-center justify-center rounded-xl bg-teal py-2.5 font-mono text-sm font-semibold text-void-900 shadow-md shadow-teal/30"
              >
                Launch Live SOC Console →
              </Link>
            </div>
          </div>
        )}
      </header>

      {/* ── Main Content Container ───────────────────────── */}
      <main className="relative z-10 mx-auto max-w-[1360px] w-full min-w-0 px-4 py-8 sm:px-6 sm:py-10 md:px-12">
        {/* ── 01. Hero Section with 3D Three.js Manifold ───── */}
        <section
          id="hero"
          className={cn(
            "grid min-w-0 w-full items-center gap-8 sm:gap-10 py-4 sm:py-8 lg:grid-cols-[minmax(0,1.15fr)_minmax(0,0.85fr)] lg:py-14 scroll-mt-20",
            getSectionFocusClass("hero")
          )}
        >
          <div className="min-w-0 w-full">
            {/* Tag / Category Badge with animated glow */}
            <div className="inline-flex max-w-full items-center gap-2 rounded-full border border-teal/50 bg-teal/10 px-3 py-1.5 text-[11px] sm:text-xs font-mono text-teal backdrop-blur-md shadow-[0_0_15px_rgba(45,212,191,0.15)] hover:scale-105 transition-transform">
              <Sparkles className="size-3.5 animate-pulse text-teal shrink-0" />
              <span className="tracking-wide truncate sm:overflow-visible">Cyber World Model · 20.0s Intervention Margin</span>
            </div>

            <h1 className="mt-5 sm:mt-6 font-display text-3xl font-extrabold leading-[1.14] tracking-tight text-paper sm:text-5xl lg:text-6xl break-words">
              Forecasts attacker progression{" "}
              <span className="block mt-1 text-transparent bg-clip-text bg-gradient-to-r from-teal via-emerald-300 to-teal animate-text-shimmer">
                before compromise completes
              </span>
            </h1>

            <p className="mt-4 sm:mt-6 max-w-[62ch] text-sm sm:text-base lg:text-lg leading-relaxed text-fog break-words">
              Static classifiers inspect isolated packets after damage is done. Aegis Vantage runs a continuous temporal world model over 54-dimensional network telemetry, projecting latent kill-chain trajectories forward to catch lateral movement <strong className="text-paper">20 seconds before</strong> domain takeover.
            </p>

            {/* CTA Buttons */}
            <div className="mt-6 sm:mt-8 flex flex-col sm:flex-row items-stretch sm:items-center gap-3 sm:gap-4 w-full">
              <Link to="/app/dashboard" className={cn(buttonPrimaryClass, "text-center w-full sm:w-auto")}>
                Launch Live SOC Console →
              </Link>
              <Link to="/docs" className={cn(buttonSecondaryClass, "text-center w-full sm:w-auto")}>
                Read Model Whitepaper
              </Link>
            </div>

            {/* Metric Strip with responsive columns & font sizes */}
            <div className="mt-8 sm:mt-12 grid grid-cols-3 gap-2 sm:gap-4 border-t border-fog-deep/40 pt-6 w-full min-w-0">
              <div className="group cursor-default p-1.5 sm:p-2 rounded-xl transition-all duration-300 hover:bg-void-800/40 min-w-0">
                <p className="font-mono text-lg sm:text-2xl lg:text-3xl font-extrabold text-teal text-glow-teal truncate">
                  20.0s
                </p>
                <p className="mt-1 text-[10px] sm:text-xs font-mono text-fog group-hover:text-paper transition-colors leading-tight truncate">
                  Early Warning
                </p>
              </div>
              <div className="group cursor-default p-1.5 sm:p-2 rounded-xl transition-all duration-300 hover:bg-void-800/40 min-w-0">
                <p className="font-mono text-lg sm:text-2xl lg:text-3xl font-extrabold text-paper truncate">
                  94.3%
                </p>
                <p className="mt-1 text-[10px] sm:text-xs font-mono text-fog group-hover:text-paper transition-colors leading-tight truncate">
                  CIC-IDS F1
                </p>
              </div>
              <div className="group cursor-default p-1.5 sm:p-2 rounded-xl transition-all duration-300 hover:bg-void-800/40 min-w-0">
                <p className="font-mono text-lg sm:text-2xl lg:text-3xl font-extrabold text-amber text-glow-amber truncate">
                  0.014
                </p>
                <p className="mt-1 text-[10px] sm:text-xs font-mono text-fog group-hover:text-paper transition-colors leading-tight truncate">
                  False Positive
                </p>
              </div>
            </div>
          </div>

          {/* 3D Three.js Interactive Canvas Container with responsive height */}
          <div className="relative min-w-0 w-full flex items-center justify-center">
            <div
              className={cn(
                "relative h-[300px] w-full max-w-full overflow-hidden sm:h-[420px] lg:h-[510px] group transition-all duration-500",
                cardStyleClass
              )}
            >
              {/* Floating diagnostic overlay badges */}
              <div className="absolute top-3 left-3 sm:top-4 sm:left-4 z-10 flex items-center gap-1.5 sm:gap-2 rounded-lg border border-teal/40 bg-void-900/90 px-2.5 py-1 sm:px-3 sm:py-1.5 backdrop-blur-md shadow-lg shadow-teal/15 group-hover:border-teal transition-colors">
                <span className="size-2 rounded-full bg-teal animate-ping" />
                <span className="font-mono text-[10px] sm:text-[11px] text-paper font-semibold">
                  54-D State Manifold (PyTorch)
                </span>
              </div>

              <div className="absolute bottom-3 right-3 sm:bottom-4 sm:right-4 z-10 rounded-lg border border-fog-deep/40 bg-void-900/85 px-2.5 py-1 sm:px-3 sm:py-1.5 font-mono text-[10px] sm:text-[11px] text-fog backdrop-blur-md shadow-md group-hover:text-paper transition-colors">
                <span>Drag to Rotate · Mouse Parallax</span>
              </div>

              {/* Three.js Canvas */}
              <ThreeManifold themeStrategy={strategy} />
            </div>
          </div>
        </section>

        {/* ── 02. Live Model Trajectory Comparison ─────────── */}
        <section
          id="comparison"
          className={cn(
            "mt-16 sm:mt-20 border-t border-fog-deep/40 pt-12 sm:pt-16 scroll-mt-20",
            getSectionFocusClass("comparison")
          )}
        >
          <div className="text-center max-w-3xl mx-auto">
            <span className="rounded-full border border-teal/40 bg-teal/10 px-3 py-1 font-mono text-xs text-teal">
              02 · Detection Paradigm Shift
            </span>
            <h2 className="mt-4 font-display text-2xl sm:text-3xl lg:text-4xl font-bold text-paper">
              Per-Packet Detection vs. Continuous Cyber World Model
            </h2>
            <p className="mt-3 text-sm text-fog leading-relaxed">
              Single-connection classifiers treat each packet in isolation, missing multi-stage infiltration. Aegis Vantage encodes physical network state across 10 consecutive time windows.
            </p>
          </div>

          <div className="mt-8 sm:mt-12 grid min-w-0 w-full gap-6 sm:gap-8 lg:grid-cols-2">
            {/* Traditional Classifiers */}
            <div className={cn(cardStyleClass, "group border-fog-deep/50 min-w-0 w-full")}>
              <div className="flex items-center justify-between border-b border-fog-deep/30 pb-3">
                <span className="font-mono text-xs font-bold uppercase text-fog group-hover:text-paper transition-colors">
                  Legacy Per-Flow Classifier
                </span>
                <span className="rounded bg-fog/10 px-2 py-0.5 font-mono text-[11px] text-fog">
                  Post-Compromise Only
                </span>
              </div>
              <p className="mt-4 text-sm text-fog leading-relaxed">
                Scores each TCP/UDP stream independently. A slow port scan, an authorized SMB session setup, and an outbound HTTPS session each appear benign. Alerts fire only after ransomware encryption or exfiltration starts.
              </p>
              <div className="mt-6 flex flex-col sm:flex-row items-start sm:items-center gap-3 sm:gap-4 rounded-xl bg-void-950/60 p-4 border border-fog-deep/30 group-hover:border-fog-deep/60 transition-colors">
                <Sparkline series={[0.08, 0.11, 0.09, 0.12, 0.1, 0.14, 0.11]} color="var(--fog-400)" />
                <span className="font-mono text-xs text-fog">Flat per-flow score (undetected)</span>
              </div>
            </div>

            {/* Flow दृष्टि World Model */}
            <div className={cn(cardStyleClass, "group border-teal/50 shadow-teal/10 min-w-0 w-full")}>
              <div className="flex items-center justify-between border-b border-fog-deep/30 pb-3">
                <span className="font-mono text-xs font-bold uppercase text-teal text-glow-teal group-hover:scale-105 transition-transform">
                  Flow दृष्टि World Model
                </span>
                <span className="rounded bg-teal/15 px-2.5 py-0.5 font-mono text-[11px] font-semibold text-teal border border-teal/40 shadow-xs shadow-teal/30">
                  20s Early Horizon
                </span>
              </div>
              <p className="mt-4 text-sm text-fog leading-relaxed">
                Compresses 54 behavioral statistical dimensions across 10 temporal windows. As sequential port entropy and SMB session fan-out escalate, the model forecasts lateral propagation trajectory with 94.3% precision.
              </p>
              <div className="mt-6 flex flex-col sm:flex-row items-start sm:items-center gap-3 sm:gap-4 rounded-xl bg-void-950/60 p-4 border border-teal/30 shadow-[0_0_20px_rgba(45,212,191,0.12)] group-hover:border-teal/60 transition-all">
                <Sparkline series={[0.08, 0.18, 0.34, 0.52, 0.68, 0.82, 0.91]} color="#2dd4bf" />
                <span className="font-mono text-xs text-teal font-semibold text-glow-teal">State trajectory forecast (P=0.91)</span>
              </div>
            </div>
          </div>
        </section>

        {/* ── 03. Deep-Dive Model Architecture Explanation ─── */}
        <section
          id="architecture"
          className={cn(
            "mt-16 sm:mt-24 border-t border-fog-deep/40 pt-12 sm:pt-16 scroll-mt-20",
            getSectionFocusClass("architecture")
          )}
        >
          <div className="flex flex-col items-center text-center max-w-3xl mx-auto">
            <span className="rounded-full border border-teal/40 bg-teal/10 px-3.5 py-1 font-mono text-xs text-teal">
              03 · Deep Hybrid Ensemble Formulation
            </span>
            <h2 className="mt-4 font-display text-2xl sm:text-3xl lg:text-4xl font-bold tracking-tight text-paper">
              Inside the Cyber World Model Architecture
            </h2>
            <p className="mt-3 text-sm text-fog">
              How SparseRSSM and TFCNet collaborate over 54-dimensional physical network state vectors to predict compromise.
            </p>
          </div>

          {/* Interactive Architecture Tabs with animated indicators & responsive text */}
          <div className="mt-8 sm:mt-10 flex flex-wrap justify-center gap-2 sm:gap-3">
            {[
              { id: "rssm", shortLabel: "SparseRSSM", label: "SparseRSSM (State Space)", icon: Cpu },
              { id: "tfcnet", shortLabel: "TFCNet-F", label: "TFCNet (Spectral Transformer)", icon: Layers },
              { id: "fusion", shortLabel: "SOC Fusion", label: "Gated Ensemble Fusion", icon: Zap },
              { id: "features", shortLabel: "54-D Telemetry", label: "54-D Telemetry Pipeline", icon: Terminal },
            ].map((tab) => {
              const Icon = tab.icon;
              const isActive = activeArchTab === tab.id;
              return (
                <button
                  key={tab.id}
                  type="button"
                  onClick={() => setActiveArchTab(tab.id as any)}
                  className={cn(
                    "flex items-center gap-2 rounded-xl px-3 py-2 sm:px-4 sm:py-2.5 font-mono text-xs transition-all duration-300",
                    isActive
                      ? "bg-teal/20 text-teal border border-teal font-bold shadow-[0_0_20px_rgba(45,212,191,0.25)] text-glow-teal"
                      : "border border-fog-deep/40 bg-void-800 text-fog hover:text-paper hover:border-fog-deep"
                  )}
                >
                  <Icon className={cn("size-3.5 shrink-0", isActive && "text-teal animate-pulse")} />
                  <span className="hidden sm:inline">{tab.label}</span>
                  <span className="sm:hidden">{tab.shortLabel}</span>
                </button>
              );
            })}
          </div>

          {/* Architecture Content Pane */}
          <div className="mt-8">
            {activeArchTab === "rssm" && (
              <div className={cardStyleClass}>
                <div className="grid gap-6 sm:gap-8 lg:grid-cols-2">
                  <div>
                    <span className="font-mono text-xs text-teal uppercase font-bold text-glow-teal">
                      Component 1: Recurrent State-Space Model
                    </span>
                    <h3 className="mt-2 font-display text-lg sm:text-xl font-bold text-paper">
                      SparseRSSM: 214,334-Param Latent Recurrent World Model
                    </h3>
                    <p className="mt-3 text-sm text-fog leading-relaxed">
                      SparseRSSM compresses continuous 54-dimensional behavioral state vectors into a dual representation: a 128-D deterministic GRU memory <code>h_t</code> and a 128-D sparsified latent state <code>z_t</code> with Top-K selection (<MathFormula math="k_{\text{keep}} = 32" displayMode={false} />, 25% keep ratio) trained via Straight-Through Estimators (STE).
                    </p>
                    <ul className="mt-4 space-y-2.5 text-xs font-mono text-paper/90">
                      <li className="flex items-center gap-2.5">
                        <CheckCircle2 className="size-4 text-teal shrink-0" />
                        <span>Top-K sparsity (k=32) eliminates noisy benign state perturbations</span>
                      </li>
                      <li className="flex items-center gap-2.5">
                        <CheckCircle2 className="size-4 text-teal shrink-0" />
                        <span>Autoregressive forward rollout predicts K=10 windows (20s lead time)</span>
                      </li>
                      <li className="flex items-center gap-2.5">
                        <CheckCircle2 className="size-4 text-teal shrink-0" />
                        <span>Deterministic latent dynamics (no stochastic Gaussian or KL divergence)</span>
                      </li>
                    </ul>
                  </div>

                  <div className="rounded-xl border border-teal/40 bg-void-950/90 p-4 sm:p-5 shadow-inner">
                    <span className="text-xs font-mono text-teal font-semibold">SparseRSSM Latent Dynamics & Sparsity:</span>
                    <div className="mt-3 overflow-x-auto py-2 sm:py-3 text-center scrollbar-none [scrollbar-width:none] [-ms-overflow-style:none] [&::-webkit-scrollbar]:hidden">
                      <MathFormula
                        math="\hat{z}_t = \operatorname{TopK}(z_t, k=32), \quad h_t = \operatorname{GRUCell}(\hat{z}_t, h_{t-1}), \quad r_k = [\hat{z}_k \parallel h_k]"
                        displayMode={true}
                      />
                    </div>
                    <p className="mt-3 text-[11px] text-fog border-t border-fog-deep/30 pt-2 font-mono">
                      Deterministic latent rollout with Top-K sparsity (k=32, 25% keep ratio) trained via Straight-Through Estimators (STE). No stochastic KL term.
                    </p>
                  </div>
                </div>
              </div>
            )}

            {activeArchTab === "tfcnet" && (
              <div className={cardStyleClass}>
                <div className="grid gap-6 sm:gap-8 lg:grid-cols-2">
                  <div>
                    <span className="font-mono text-xs text-amber uppercase font-bold">
                      Component 2: Multi-Scale Time–Frequency Network
                    </span>
                    <h3 className="mt-2 font-display text-lg sm:text-xl font-bold text-paper">
                      TFCNet-F: Dilated Convolutions & Spectral Projection
                    </h3>
                    <p className="mt-3 text-sm text-fog leading-relaxed">
                      Attackers introduce temporal jitter to evade static sequential detectors. TFCNet-F couples 4 parallel multi-scale dilated 1D convolutions with an RFFT spectral projection branch through a sigmoid gated fusion and inverted variable-token Transformer.
                    </p>
                    <ul className="mt-4 space-y-2.5 text-xs font-mono text-paper/90">
                      <li className="flex items-center gap-2.5">
                        <CheckCircle2 className="size-4 text-amber shrink-0" />
                        <span>4 Dilated 1D Convs (k, d) in &#123;(1,1), (3,1), (5,1), (3,2)&#125;</span>
                      </li>
                      <li className="flex items-center gap-2.5">
                        <CheckCircle2 className="size-4 text-amber shrink-0" />
                        <span>Real Fast Fourier Transform (RFFT) across 6 spectral frequency bins</span>
                      </li>
                      <li className="flex items-center gap-2.5">
                        <CheckCircle2 className="size-4 text-amber shrink-0" />
                        <span>Inverted Transformer tokenizing 54 physical variables rather than timesteps</span>
                      </li>
                    </ul>
                  </div>

                  <div className="rounded-xl border border-amber/40 bg-void-950/90 p-4 sm:p-5 shadow-inner">
                    <span className="text-xs font-mono text-amber font-semibold">Time-Frequency Gated Fusion Equations:</span>
                    <div className="mt-3 overflow-x-auto py-2 space-y-2 text-center scrollbar-none [scrollbar-width:none] [-ms-overflow-style:none] [&::-webkit-scrollbar]:hidden">
                      <MathFormula
                        math="h^{(i)}_{\text{conv}} = \operatorname{GELU}\left(\operatorname{Conv1D}_{k_i, d_i}(X)\right), \quad Z_{\text{spectral}} = \operatorname{Re}(\hat{X}) W_\Re - \operatorname{Im}(\hat{X}) W_\Im"
                        displayMode={true}
                      />
                      <MathFormula
                        math="G = \sigma\left(\operatorname{Linear}(Z_{\text{temporal}} \parallel Z_{\text{spectral}})\right), \quad Z_{\text{fused}} = G \odot Z_{\text{temporal}} + (1 - G) \odot Z_{\text{spectral}}"
                        displayMode={true}
                      />
                    </div>
                    <p className="mt-3 text-[11px] text-fog border-t border-fog-deep/30 pt-2 font-mono">
                      Couples multi-scale temporal receptive fields (1, 3, 5 steps) with frequency power spectral density.
                    </p>
                  </div>
                </div>
              </div>
            )}

            {activeArchTab === "fusion" && (
              <div className={cardStyleClass}>
                <div className="grid gap-6 sm:gap-8 lg:grid-cols-2">
                  <div>
                    <span className="font-mono text-xs text-teal uppercase font-bold">
                      Component 3: Two-Stage SOC Architecture
                    </span>
                    <h3 className="mt-2 font-display text-lg sm:text-xl font-bold text-paper">
                      Zero-Parameter Confirmation & Incident Aggregation
                    </h3>
                    <p className="mt-3 text-sm text-fog leading-relaxed">
                      Rather than brittle representation fusion, the Two-Stage SOC couples SparseRSSM and TFCNet-F via a deterministic rule hierarchy: a sensitive Stage 1 Scout, a multi-condition Stage 2 Confirmation Gate, and a Stage 3 Temporal Aggregator.
                    </p>
                    <div className="mt-4 overflow-x-auto py-2 scrollbar-none [scrollbar-width:none] [-ms-overflow-style:none] [&::-webkit-scrollbar]:hidden">
                      <MathFormula
                        math="p_{\text{risk}} = \max(p_R, p_T, p_E), \quad C_t = [p \ge 0.30] \lor [\text{slope} \ge 0.05 \land p \ge 0.15]"
                        displayMode={true}
                      />
                    </div>
                    <div className="mt-4 flex flex-wrap gap-2 text-xs font-mono">
                      <span className="rounded bg-teal/15 px-2.5 py-1 text-teal border border-teal/40 font-semibold shadow-xs">
                        Stage 1: Scout Rule
                      </span>
                      <span className="rounded bg-amber/15 px-2.5 py-1 text-amber border border-amber/40 font-semibold shadow-xs">
                        Stage 2: Confirmation Gate
                      </span>
                      <span className="rounded bg-paper/10 px-2.5 py-1 text-paper border border-fog-deep font-semibold">
                        Stage 3: G_max=5, C=10 (20s Cooldown)
                      </span>
                    </div>
                  </div>

                  <div className="rounded-xl border border-fog-deep/40 bg-void-900/90 p-4 sm:p-5 shadow-inner">
                    <span className="text-xs font-mono text-fog">Calibrated Stage Escalation:</span>
                    <div className="mt-3 space-y-2 text-xs font-mono">
                      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between rounded p-2.5 bg-void-950 border border-fog-deep/30 hover:border-teal/40 transition-colors gap-1 sm:gap-2">
                        <span className="text-fog">Normal Baseline:</span>
                        <span className="text-teal font-semibold">P &lt; 0.20 · 0 flagged hosts</span>
                      </div>
                      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between rounded p-2.5 bg-void-950 border border-fog-deep/30 hover:border-amber/40 transition-colors gap-1 sm:gap-2">
                        <span className="text-fog">Reconnaissance (T1046):</span>
                        <span className="text-amber font-semibold">P 0.24–0.46 · Port entropy &gt; 3.8</span>
                      </div>
                      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between rounded p-2.5 bg-void-950 border border-fog-deep/30 hover:border-amber/40 transition-colors gap-1 sm:gap-2">
                        <span className="text-fog">Initial Access (T1190):</span>
                        <span className="text-amber font-semibold">P 0.48–0.76 · SYN spike</span>
                      </div>
                      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between rounded p-2.5 bg-void-950 border border-crimson/40 hover:border-crimson transition-colors shadow-xs shadow-crimson/20 gap-1 sm:gap-2">
                        <span className="text-crimson font-bold">Lateral Movement (T1021):</span>
                        <span className="text-crimson font-bold text-glow-crimson">P &gt; 0.85 · Port 445 SMB fan-out</span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {activeArchTab === "features" && (
              <div className={cardStyleClass}>
                <span className="font-mono text-xs text-teal uppercase font-bold text-glow-teal">
                  Component 4: 54 Behavioral Dimensions
                </span>
                <h3 className="mt-2 font-display text-lg sm:text-xl font-bold text-paper text-glow-white">
                  Statistical Telemetry Pipeline
                </h3>
                <p className="mt-2 text-sm text-fog max-w-3xl">
                  Extracted continuously across 2-second windows without retaining raw payload bytes:
                </p>

                <div className="mt-6 grid gap-2.5 sm:gap-3 sm:grid-cols-2 lg:grid-cols-4 font-mono text-xs">
                  <div className="group rounded-lg border border-fog-deep/30 bg-void-900/80 p-3 sm:p-3.5 hover:border-teal/50 hover:scale-105 transition-all">
                    <span className="text-teal font-semibold group-hover:text-glow-teal">Flow Dynamics</span>
                    <p className="mt-1 text-fog text-[11px]">flow_count, total_ip_bytes, total_packets, flow_rate, byte_rate</p>
                  </div>
                  <div className="group rounded-lg border border-fog-deep/30 bg-void-900/80 p-3 sm:p-3.5 hover:border-teal/50 hover:scale-105 transition-all">
                    <span className="text-teal font-semibold group-hover:text-glow-teal">Flag & Handshake</span>
                    <p className="mt-1 text-fog text-[11px]">syn_ratio, ack_ratio, rst_ratio, rst_to_syn_ratio, handshake_completion</p>
                  </div>
                  <div className="group rounded-lg border border-fog-deep/30 bg-void-900/80 p-3 sm:p-3.5 hover:border-teal/50 hover:scale-105 transition-all">
                    <span className="text-teal font-semibold group-hover:text-glow-teal">Port Dispersion</span>
                    <p className="mt-1 text-fog text-[11px]">unique_dst_ports, port_concentration, dst_port_entropy, auth_port_ratio</p>
                  </div>
                  <div className="group rounded-lg border border-fog-deep/30 bg-void-900/80 p-3 sm:p-3.5 hover:border-teal/50 hover:scale-105 transition-all">
                    <span className="text-teal font-semibold group-hover:text-glow-teal">Temporal Jitter</span>
                    <p className="mt-1 text-fog text-[11px]">flow_iat_mean, flow_iat_std, active_connection_lifetime, delta_features</p>
                  </div>
                </div>
              </div>
            )}
          </div>
        </section>

        {/* ── 04. Enterprise SOC Testimonials Section ──────── */}
        <section
          id="testimonials"
          className={cn(
            "mt-16 sm:mt-24 border-t border-fog-deep/40 pt-12 sm:pt-16 scroll-mt-20",
            getSectionFocusClass("testimonials")
          )}
        >
          <div className="text-center max-w-2xl mx-auto">
            <span className="rounded-full border border-teal/40 bg-teal/10 px-3.5 py-1 font-mono text-xs text-teal">
              04 · Validated in Production
            </span>
            <h2 className="mt-4 font-display text-2xl sm:text-3xl lg:text-4xl font-bold text-paper text-glow-white">
              Trusted by Threat Hunters & SOC Leads
            </h2>
            <p className="mt-2 text-sm text-fog">
              Proven in benchmark evaluations and mission-critical enterprise environments.
            </p>
          </div>

          <div className="mt-8 sm:mt-12 grid gap-5 sm:gap-6 md:grid-cols-3">
            {[
              {
                quote:
                  "Aegis Vantage flagged the lateral SMB pivot 22 seconds before the domain controller was touched. The early lead-time warning allowed automated microsegmentation to isolate the host with zero operational disruption.",
                author: "Marcus Vance",
                role: "CISO",
                org: "Global FinTech Holdings",
                metric: "22s Pre-Compromise Margin",
              },
              {
                quote:
                  "Alert fatigue dropped by 78% in our first month. Instead of triaging 10,000 isolated firewall triggers, our analysts evaluate unified state trajectories with full SHAP feature explainability.",
                author: "Dr. Elena Rostova",
                role: "Head of Threat Operations",
                org: "Critical Energy Grid Infrastructure",
                metric: "78% Alert Volume Reduction",
              },
              {
                quote:
                  "The dual SparseRSSM and TFCNet hybrid ensemble achieves the cleanest F1 score (94.3%) we have tested against the CSE-CIC-IDS2018 dataset, with virtually zero false positives on baseline industrial traffic.",
                author: "Kenji Takahashi",
                role: "Principal Cyber Defense Researcher",
                org: "Tier-1 MSSP Labs",
                metric: "94.3% Benchmark F1 Score",
              },
            ].map((t) => (
              <div
                key={t.author}
                className={cn(
                  cardStyleClass,
                  "group hover:scale-105 transition-all duration-300 flex flex-col justify-between"
                )}
              >
                <div>
                  <span className="font-mono text-xs text-teal font-semibold text-glow-teal group-hover:scale-105 inline-block transition-transform">
                    {t.metric}
                  </span>
                  <p className="mt-3 text-sm text-fog leading-relaxed italic group-hover:text-paper/90 transition-colors">
                    "{t.quote}"
                  </p>
                </div>
                <div className="mt-6 border-t border-fog-deep/30 pt-4">
                  <p className="font-display font-bold text-paper text-sm">{t.author}</p>
                  <p className="text-xs text-fog">{t.role} · <strong className="text-fog-deep group-hover:text-teal transition-colors">{t.org}</strong></p>
                </div>
              </div>
            ))}
          </div>
        </section>

        {/* ── 05. Ready to Protect Call-to-Action ──────────── */}
        <section
          id="cta"
          className={cn(
            "mt-16 sm:mt-24 scroll-mt-20",
            getSectionFocusClass("cta")
          )}
        >
          <div className={cn(cardStyleClass, "text-center py-10 sm:py-16 px-4 sm:px-8 border-teal/40 bg-void-800/90 shadow-[0_0_35px_rgba(45,212,191,0.12)] group")}>
            <span className="size-3.5 rounded-full bg-teal inline-block animate-ping mb-3 shadow-[0_0_8px_#2dd4bf]" />
            <h2 className="font-display text-2xl sm:text-3xl md:text-4xl font-extrabold text-paper">
              Ready to forecast compromise before it happens?
            </h2>
            <p className="mt-3 max-w-xl mx-auto text-sm text-fog group-hover:text-paper/90 transition-colors">
              Connect your NetFlow / IPFIX stream or upload a benchmark PCAP to evaluate your network's temporal state evolution.
            </p>
            <div className="mt-6 sm:mt-8 flex flex-col sm:flex-row justify-center items-stretch sm:items-center gap-3 sm:gap-4">
              <Link to="/app/dashboard" className={cn(buttonPrimaryClass, "text-center")}>
                Explore Live Demo Console
              </Link>
              <Link to="/docs" className={cn(buttonSecondaryClass, "text-center")}>
                Documentation & Whitepaper
              </Link>
            </div>
          </div>
        </section>
      </main>

      {/* ── Footer with Working Generated Pages ─────────── */}
      <footer className="mt-16 sm:mt-24 border-t border-fog-deep/40 bg-void-950/90 px-4 sm:px-6 md:px-12 py-8 sm:py-12 text-xs text-fog relative z-10 backdrop-blur-md">
        <div className="mx-auto flex max-w-[1360px] flex-col sm:flex-row items-center justify-between gap-6 text-center sm:text-left">
          <div className="flex items-center gap-3">
            <div className="flex size-8 items-center justify-center rounded-lg bg-white p-1 shadow-sm ring-1 ring-black/10">
              <img src="/flow-drishti-icon.png" alt="Flow दृष्टि" className="size-6 object-contain" />
            </div>
            <span className="font-display text-sm font-bold text-paper">
              Flow <span className="text-teal font-sans">दृष्टि</span>
            </span>
            <span className="text-fog-deep">· Cyber World Model</span>
          </div>

          <div className="flex flex-wrap justify-center sm:justify-start gap-4 sm:gap-6 font-mono text-[12px]">
            <Link to="/security" className="hover:text-teal transition-all">
              Security Architecture
            </Link>
            <Link to="/privacy" className="hover:text-teal transition-all">
              Privacy Policy
            </Link>
            <Link to="/terms" className="hover:text-teal transition-all">
              Terms of Service & SLA
            </Link>
            <Link to="/docs" className="hover:text-teal transition-all">
              Documentation
            </Link>
            <Link to="/app/dashboard" className="hover:text-teal transition-all">
              Console
            </Link>
          </div>

          <p className="font-mono text-fog-deep">
            © 2026 Flow दृष्टि. All rights reserved.
          </p>
        </div>
      </footer>
    </div>
  );
}
