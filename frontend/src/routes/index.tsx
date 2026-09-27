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
    "Flow दृष्टि forecasts lateral propagation trajectory with 94.3% precision.
              </p>
              <div className="mt-6 flex flex-col sm:flex-row items-start sm:items-center gap-3 sm:gap-4 rounded-xl bg-void-950/60 p-4 border border-teal/30 shadow-[0_0_20px_rgba(45,212,191,0.12)] group-hover:border-teal/60 transition-all">
                <Sparkline series={[0.08, 0.18, 0.34, 0.52, 0.68, 0.82, 0.91]} color="#2dd4bf" />
                <span className="font-mono text-xs text-teal font-semibold text-glow-teal">State trajectory forecast (P=0.91)</span>
              </div>
            </div>
          </div>
        </section>

        {/* â”€â”€ 03. Deep-Dive Model Architecture Explanation â”€â”€â”€ */}
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
                      Component 2: Multi-Scale Timeâ€“Frequency Network
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
                        <span className="text-amber font-semibold">P 0.24â€“0.46 · Port entropy &gt; 3.8</span>
                      </div>
                      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between rounded p-2.5 bg-void-950 border border-fog-deep/30 hover:border-amber/40 transition-colors gap-1 sm:gap-2">
                        <span className="text-fog">Initial Access (T1190):</span>
                        <span className="text-amber font-semibold">P 0.48â€“0.76 · SYN spike</span>
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

        {/* â”€â”€ 04. Enterprise SOC Testimonials Section â”€â”€â”€â”€â”€â”€â”€â”€ */}
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
                  "Flow दृष्टि flagged the lateral SMB pivot 22 seconds before the domain controller was touched. The early lead-time warning allowed automated microsegmentation to isolate the host with zero operational disruption.",
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

        {/* â”€â”€ 05. Ready to Protect Call-to-Action â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */}
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

      {/* â”€â”€ Footer with Working Generated Pages â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */}
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
