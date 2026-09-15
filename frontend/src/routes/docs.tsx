import { createFileRoute, Link } from "@tanstack/react-router";
import { BookOpen, Terminal, Cpu, ArrowLeft, Layers, ShieldCheck, CheckCircle2, Zap, BarChart3, Database } from "lucide-react";
import { pageHead } from "@/lib/head";
import { MathFormula } from "@/components/common/MathFormula";
import { GoogleTranslate } from "@/components/common/GoogleTranslate";

export const Route = createFileRoute("/docs")({
  head: pageHead(
    "Technical Documentation & Architecture Whitepaper — Aegis Vantage",
    "API reference, SparseRSSM + TFCNet-F architecture specifications, mathematical formulation, and experimental benchmark record.",
  ),
  component: DocsPage,
});

export function DocsPage() {
  return (
    <div className="network-field min-h-screen selection:bg-teal selection:text-void-900 bg-void-900 text-paper">
      {/* ── Top Header ─────────────────────────────────── */}
      <header className="sticky top-0 z-50 flex h-16 items-center justify-between border-b border-fog-deep/40 px-6 md:px-12 backdrop-blur-xl bg-void-900/85">
        <Link to="/" className="flex items-center gap-2.5 text-fog hover:text-paper transition-colors">
          <ArrowLeft className="size-4 text-teal" />
          <span className="font-mono text-xs uppercase tracking-wider">Back to Aegis Vantage</span>
        </Link>
        <div className="flex items-center gap-4">
          <GoogleTranslate id="google_translate_docs" />
          <div className="hidden sm:flex items-center gap-2.5">
            <span className="size-[16px] rotate-45 rounded-[3px] border-2 border-teal shadow-xs shadow-teal/50" />
            <span className="font-display text-sm font-semibold text-paper">Research Whitepaper</span>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-[1180px] px-6 py-14 md:px-10">
        {/* ── Paper Title & Authors ───────────────────────── */}
        <div className="border-b border-fog-deep/40 pb-8">
          <div className="inline-flex items-center gap-2 rounded-full border border-teal/40 bg-teal/10 px-3.5 py-1 text-xs font-mono text-teal">
            <BookOpen className="size-3.5 text-teal" />
            Official Research Publication · Neural AI, DTU
          </div>
          <h1 className="mt-4 font-display text-3xl font-extrabold tracking-tight text-paper sm:text-4xl">
            Temporal World Modeling for Network Attack Forecasting with Latent-Recurrent and Time–Frequency Dynamics
          </h1>
          <p className="mt-3 font-mono text-xs text-teal">
            Nakshatra Yadav, Lakshay Bharti, Nidhi Jha, Saksham Chhabra, Arihant Srivastava, Soumil Srivastava · Neural AI, Delhi Technological University
          </p>
          <p className="mt-4 max-w-[84ch] text-sm text-fog leading-relaxed">
            Conventional Intrusion Detection Systems (IDS) map single traffic slices to benign/malicious labels, discarding temporal evolution. We reformulate network defense as a continuous temporal forecasting problem: traffic is encoded into 54-dimensional physical network state vectors, consumed by two complementary neural backbones (SparseRSSM + TFCNet-F) to forecast future states <MathFormula math="\hat{S}_{t+1..t+K}" displayMode={false} /> and future attack risk <MathFormula math="\hat{y}_{t+K}" displayMode={false} /> at a 20-second early horizon.
          </p>
        </div>

        {/* ── Key Metrics Strip ───────────────────────────── */}
        <div className="mt-8 grid grid-cols-2 gap-4 sm:grid-cols-4">
          <div className="rounded-xl border border-teal/30 bg-void-800/60 p-4">
            <span className="font-mono text-2xl font-bold text-teal">100%</span>
            <p className="mt-1 text-xs font-mono text-fog">Onset Recall (29/29, 7/7, 7/7)</p>
          </div>
          <div className="rounded-xl border border-teal/30 bg-void-800/60 p-4">
            <span className="font-mono text-2xl font-bold text-paper">98.41%</span>
            <p className="mt-1 text-xs font-mono text-fog">Incident F1 Score (OOD)</p>
          </div>
          <div className="rounded-xl border border-amber/30 bg-void-800/60 p-4">
            <span className="font-mono text-2xl font-bold text-amber">0.12/h</span>
            <p className="mt-1 text-xs font-mono text-fog">Incident False Alarms / Hr</p>
          </div>
          <div className="rounded-xl border border-teal/30 bg-void-800/60 p-4">
            <span className="font-mono text-2xl font-bold text-teal">20.0s</span>
            <p className="mt-1 text-xs font-mono text-fog">Lead Warning Horizon</p>
          </div>
        </div>

        {/* ── Parameter Budget & Overview ─────────────────── */}
        <div className="mt-10 grid gap-5 sm:grid-cols-3">
          <div className="rounded-xl border border-teal/30 bg-void-800/60 p-5 backdrop-blur-md">
            <div className="size-9 rounded-lg border border-teal/40 bg-teal/10 flex items-center justify-center text-teal">
              <Cpu className="size-4" />
            </div>
            <h3 className="mt-3 font-display font-semibold text-paper">SparseRSSM (214,334 params)</h3>
            <p className="mt-1 text-xs text-fog leading-relaxed">
              Deterministic latent-recurrent world model with Top-K latent sparsity (<MathFormula math="k_{\text{keep}} = 32" displayMode={false} />) trained with Straight-Through Estimators (STE).
            </p>
          </div>

          <div className="rounded-xl border border-amber/30 bg-void-800/60 p-5 backdrop-blur-md">
            <div className="size-9 rounded-lg border border-amber/40 bg-amber/10 flex items-center justify-center text-amber">
              <Layers className="size-4" />
            </div>
            <h3 className="mt-3 font-display font-semibold text-paper">TFCNet-F (400,914 params)</h3>
            <p className="mt-1 text-xs text-fog leading-relaxed">
              Multi-scale dilated 1D convolutions coupled with learned RFFT spectral projection and an inverted Transformer attending over 54 variables.
            </p>
          </div>

          <div className="rounded-xl border border-fog-deep/40 bg-void-800/60 p-5 backdrop-blur-md">
            <div className="size-9 rounded-lg border border-fog-deep/40 bg-void-700/50 flex items-center justify-center text-paper">
              <ShieldCheck className="size-4 text-teal" />
            </div>
            <h3 className="mt-3 font-display font-semibold text-paper">Two-Stage SOC (615,248 total)</h3>
            <p className="mt-1 text-xs text-fog leading-relaxed">
              Scout / Gate / Aggregator pipeline adding exactly 0 trainable parameters, collapsing ~1200/h raw alarms into 0.12/h actionable incidents.
            </p>
          </div>
        </div>

        {/* ── Architectural Specifications ────────────────── */}
        <div className="mt-14 space-y-12">
          {/* Section 1: Problem Formulation */}
          <div className="rounded-2xl border border-teal/30 bg-void-800/50 p-6 md:p-8 backdrop-blur-xl shadow-xl">
            <div className="flex items-center gap-2">
              <span className="rounded bg-teal/15 px-2.5 py-0.5 font-mono text-xs text-teal font-semibold">
                Section I
              </span>
              <h2 className="font-display text-2xl font-bold text-paper">
                Problem Formulation & 54-Dimensional Physical State
              </h2>
            </div>

            <p className="mt-4 text-sm text-fog leading-relaxed">
              Traffic is framed as a continuous temporal trajectory. The network state <MathFormula math="S_t \in \mathbb{R}^{54}" displayMode={false} /> concatenates 37 base behavioral features with their first-order temporal differences (velocity vector):
            </p>

            <div className="mt-4 rounded-xl border border-teal/30 bg-void-950/90 p-4">
              <MathFormula
                math="S_t = [x_t \parallel \Delta x_t] \in \mathbb{R}^{54}, \quad x_t \in \mathbb{R}^{37}, \quad \Delta x_t = x_t - x_{t-1} \in \mathbb{R}^{17}"
                displayMode={true}
              />
            </div>

            <p className="mt-4 text-sm text-fog leading-relaxed">
              With window duration of 10s and stride of 2s, the model consumes lookback history <MathFormula math="X_t = [S_{t-P+1}, \dots, S_t] \in \mathbb{R}^{B \times 10 \times 54}" displayMode={false} /> (<MathFormula math="P = 10" displayMode={false} />) and forecasts future trajectory over horizon <MathFormula math="K = 10" displayMode={false} /> (<MathFormula math="10 \times 2\text{s} = 20\text{s}" displayMode={false} /> lead time).
            </p>

            <div className="mt-4 rounded-xl border border-fog-deep/30 bg-void-950/90 p-4">
              <span className="text-xs font-mono text-teal font-semibold">Multi-Task Optimization Objective:</span>
              <div className="mt-2">
                <MathFormula
                  math="\min_\theta \left( \lambda_s \sum_{k=1}^K \|\hat{S}_{t+k} - S_{t+k}\|_2^2 + \lambda_a \mathcal{L}_{\text{BCE}} + \lambda_f \mathcal{L}_{\text{CE}} \right)"
                  displayMode={true}
                />
              </div>
            </div>
          </div>

          {/* Section 2: SparseRSSM */}
          <div className="rounded-2xl border border-teal/30 bg-void-800/50 p-6 md:p-8 backdrop-blur-xl shadow-xl">
            <div className="flex items-center gap-2">
              <span className="rounded bg-teal/15 px-2.5 py-0.5 font-mono text-xs text-teal font-semibold">
                Section II
              </span>
              <h2 className="font-display text-2xl font-bold text-paper">
                SparseRSSM: Deterministic Latent-Recurrent World Model (214,334 params)
              </h2>
            </div>

            <p className="mt-3 text-sm text-fog leading-relaxed">
              <em>Note on architectural provenance:</em> Unlike canonical RSSMs (e.g. Dreamer) that employ stochastic latents with a KL penalty, <strong>SparseRSSM is strictly deterministic</strong> — it utilizes a deterministic latent space regularized by Top-K sparsity with Straight-Through Estimators (STE).
            </p>

            <div className="mt-6 grid gap-4 md:grid-cols-2">
              <div className="rounded-xl border border-fog-deep/30 bg-void-950/80 p-4">
                <span className="text-xs font-mono text-teal font-semibold">1. Deterministic Latent Encoder (54 → 128):</span>
                <div className="mt-2">
                  <MathFormula
                    math="z_t = W_3 \operatorname{GELU}\big(W_2 \operatorname{GELU}(\operatorname{LN}(W_1 S_t + b_1)) + b_2\big) + b_3"
                    displayMode={true}
                  />
                </div>
              </div>

              <div className="rounded-xl border border-fog-deep/30 bg-void-950/80 p-4">
                <span className="text-xs font-mono text-teal font-semibold">2. Top-K Sparsity & STE Gradients:</span>
                <div className="mt-2">
                  <MathFormula
                    math="m_i = \mathbb{I}[|z_i| \ge |z_{\pi(\kappa)}|], \quad \hat{z} = m \odot z, \quad \frac{\partial \mathcal{L}}{\partial z} \xleftarrow{\text{STE}} m \odot \frac{\partial \mathcal{L}}{\partial \hat{z}}"
                    displayMode={true}
                  />
                </div>
              </div>
            </div>

            <div className="mt-4 rounded-xl border border-teal/30 bg-void-950/90 p-4">
              <span className="text-xs font-mono text-teal font-semibold">3. Latent Dynamics & Auto-Regressive Rollout:</span>
              <p className="mt-2 text-xs text-fog leading-relaxed">
                Recurrent memory <MathFormula math="h_t = \operatorname{GRUCell}(\hat{z}_t, h_{t-1})" displayMode={false} /> combines with latent state into <MathFormula math="r_k = [\hat{z}_k \parallel h_k] \in \mathbb{R}^{256}" displayMode={false} />:
              </p>
              <div className="mt-2 space-y-2">
                <MathFormula
                  math="z_{k+1} = W_{t2} \operatorname{GELU}(W_{t1} r_k + b_{t1}) + b_{t2} \quad (256 \to 128 \to 128)"
                  displayMode={true}
                />
                <MathFormula
                  math="\hat{S}_{t+k} = W_{d2} \operatorname{GELU}(W_{d1} z_k + b_{d1}) + b_{d2} \quad (128 \to 128 \to 54)"
                  displayMode={true}
                />
                <MathFormula
                  math="a_k = w_a^\top r_k + b_a \quad (256 \to 1), \quad f_k = W_f r_k + b_f \quad (256 \to 7)"
                  displayMode={true}
                />
              </div>
            </div>
          </div>

          {/* Section 3: TFCNet-F */}
          <div className="rounded-2xl border border-amber/30 bg-void-800/50 p-6 md:p-8 backdrop-blur-xl shadow-xl">
            <div className="flex items-center gap-2">
              <span className="rounded bg-amber/15 px-2.5 py-0.5 font-mono text-xs text-amber font-semibold">
                Section III
              </span>
              <h2 className="font-display text-2xl font-bold text-paper">
                TFCNet-F: Time–Frequency Inverted Transformer (400,914 params)
              </h2>
            </div>

            <p className="mt-4 text-sm text-fog leading-relaxed">
              TFCNet-F treats each variable <MathFormula math="j \in \{1..54\}" displayMode={false} /> as its own univariate signal, combining 4 parallel dilated convolutions with a Real Fast Fourier Transform (RFFT) spectral branch:
            </p>

            <div className="mt-4 grid gap-4 md:grid-cols-2">
              <div className="rounded-xl border border-fog-deep/30 bg-void-950/80 p-4">
                <span className="text-xs font-mono text-amber font-semibold">Temporal Multi-Scale Dilated Convolutions:</span>
                <p className="mt-1 text-[11px] text-fog">
                  Co=32 channels each, <MathFormula math="(k, d) \in \{(1,1), (3,1), (5,1), (3,2)\}" displayMode={false} />, effective receptive fields 1, 3, 5, 5 steps:
                </p>
                <div className="mt-2">
                  <MathFormula
                    math="h_j^{\text{time}} = \operatorname{GELU}(\operatorname{LN}(W_c \bar{c} + b_c)) \in \mathbb{R}^{B \times 54 \times 128}"
                    displayMode={true}
                  />
                </div>
              </div>

              <div className="rounded-xl border border-fog-deep/30 bg-void-950/80 p-4">
                <span className="text-xs font-mono text-amber font-semibold">Learned RFFT Spectral Projection:</span>
                <p className="mt-1 text-[11px] text-fog">
                  <MathFormula math="\lfloor P/2 \rfloor + 1 = 6" displayMode={false} /> frequency bins, projected via <MathFormula math="W_\Re, W_\Im \in \mathbb{R}^{6 \times 64}" displayMode={false} />:
                </p>
                <div className="mt-2">
                  <MathFormula
                    math="h_j^{\text{freq}} = \operatorname{GELU}(\operatorname{LN}(W_f [H_\Re \parallel H_\Im] + b_f)) \in \mathbb{R}^{B \times 54 \times 128}"
                    displayMode={true}
                  />
                </div>
              </div>
            </div>

            <div className="mt-4 rounded-xl border border-amber/30 bg-void-950/90 p-4">
              <span className="text-xs font-mono text-amber font-semibold">Sigmoid Gated Fusion & Variable-Token Attention:</span>
              <div className="mt-2 space-y-2">
                <MathFormula
                  math="g = \sigma(W_g [h^{\text{time}} \parallel h^{\text{freq}}]), \quad h^{\text{fus}} = g \odot h^{\text{time}} + (1 - g) \odot h^{\text{freq}}"
                  displayMode={true}
                />
                <MathFormula
                  math="\operatorname{Attention}(Q, K, V) = \operatorname{Softmax}\left(\frac{Q K^\top}{\sqrt{d_k}}\right) V, \quad \text{Tokens} = 54 \text{ Variables} \quad (H=4, d=128)"
                  displayMode={true}
                />
              </div>
            </div>
          </div>

          {/* Section 4: Two-Stage SOC Pipeline */}
          <div className="rounded-2xl border border-teal/40 bg-void-800/50 p-6 md:p-8 backdrop-blur-xl shadow-xl">
            <div className="flex items-center gap-2">
              <span className="rounded bg-teal/15 px-2.5 py-0.5 font-mono text-xs text-teal font-semibold">
                Section IV
              </span>
              <h2 className="font-display text-2xl font-bold text-paper">
                Two-Stage SOC Operational Pipeline (0 Trainable Parameters)
              </h2>
            </div>

            <p className="mt-4 text-sm text-fog leading-relaxed">
              A sensitive scout identifies early danger, a multi-path gate validates confirmation evidence, and an incident aggregator clusters alerts — adding <strong>exactly 0 trainable parameters</strong>:
            </p>

            <div className="mt-6 grid gap-4 sm:grid-cols-3">
              <div className="rounded-xl border border-fog-deep/30 bg-void-950/80 p-4">
                <span className="font-mono text-xs text-teal font-bold uppercase">Stage 1: Scout (Recall)</span>
                <p className="mt-1 text-[11px] text-fog">
                  <MathFormula math="p_{\text{risk}} = \max(p_R, p_T, p_E)" displayMode={false} /> (never mean). Risk momentum:
                </p>
                <div className="mt-2">
                  <MathFormula math="\text{slope}_t = \max(0, p_{\text{risk}}[t] - p_{\text{risk}}[t-1])" displayMode={true} />
                </div>
                <p className="mt-2 text-[11px] text-fog font-mono">
                  Rule: <MathFormula math="C_t = [p \ge 0.30] \lor [\text{slope} \ge 0.05 \land p \ge 0.15]" displayMode={false} />
                </p>
              </div>

              <div className="rounded-xl border border-fog-deep/30 bg-void-950/80 p-4">
                <span className="font-mono text-xs text-teal font-bold uppercase">Stage 2: Gate (Precision)</span>
                <p className="mt-1 text-[11px] text-fog">Logical OR of three confirmation paths:</p>
                <ul className="mt-2 space-y-1 text-[11px] font-mono text-fog">
                  <li><strong className="text-paper">High:</strong> <MathFormula math="p \ge 0.70" displayMode={false} /></li>
                  <li><strong className="text-paper">Dynamic:</strong> <MathFormula math="p \ge 0.35 \land (\delta \ge P_{65}^\delta \lor v \ge P_{65}^v)" displayMode={false} /></li>
                  <li><strong className="text-paper">Precursor:</strong> <MathFormula math="\text{slope} \ge 0.05 \land p \ge 0.15 \land \delta \ge 0.8 P_{65}^\delta" displayMode={false} /></li>
                </ul>
              </div>

              <div className="rounded-xl border border-fog-deep/30 bg-void-950/80 p-4">
                <span className="font-mono text-xs text-teal font-bold uppercase">Stage 3: Aggregator (Analyst)</span>
                <p className="mt-1 text-[11px] text-fog">Temporal clustering of confirmed windows:</p>
                <div className="mt-2">
                  <MathFormula math="t_{m+1} - t_m \le G_{\max}=5 \text{ windows}" displayMode={true} />
                </div>
                <p className="mt-2 text-[11px] text-fog font-mono">
                  Cooldown <MathFormula math="C=10" displayMode={false} /> windows (20s). Collapses ~1,200/h window alarms to <strong>0.12/h</strong> incident alarms.
                </p>
              </div>
            </div>
          </div>

          {/* Section 5: Master Experimental Benchmark Matrix */}
          <div className="rounded-2xl border border-fog-deep/40 bg-void-800/50 p-6 md:p-8 backdrop-blur-xl shadow-xl">
            <div className="flex items-center justify-between flex-wrap gap-4">
              <div className="flex items-center gap-2">
                <span className="rounded bg-teal/15 px-2.5 py-0.5 font-mono text-xs text-teal font-semibold">
                  Section V
                </span>
                <h2 className="font-display text-2xl font-bold text-paper">
                  Master Research Benchmark Evaluation Matrix (Verbatim Record)
                </h2>
              </div>
              <span className="font-mono text-xs text-fog">CSE-CIC-IDS2018 · K=10 (20s Lead)</span>
            </div>

            <p className="mt-4 text-sm text-fog leading-relaxed">
              Comparison across all models on <strong>Setting C (Zero-Day Unseen-Family OOD Holdout)</strong>, the primary test regime comprising 7 attack episodes (Infiltration & Botnet ARES) completely absent from training:
            </p>

            <div className="mt-6 overflow-x-auto rounded-xl border border-fog-deep/40 bg-void-950">
              <table className="w-full text-left text-xs font-mono">
                <thead>
                  <tr className="border-b border-fog-deep/50 bg-void-900/80 text-fog">
                    <th className="p-3">Model Architecture</th>
                    <th className="p-3 text-right">Params</th>
                    <th className="p-3 text-right">Precision</th>
                    <th className="p-3 text-right">Recall</th>
                    <th className="p-3 text-right">F1 Score</th>
                    <th className="p-3 text-right">Onset Recall</th>
                    <th className="p-3 text-right">FA/hr Inc</th>
                    <th className="p-3 text-right">State MAE</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-fog-deep/30">
                  <tr className="text-fog">
                    <td className="p-3">Persistence Baseline</td>
                    <td className="p-3 text-right">0</td>
                    <td className="p-3 text-right">99.66%</td>
                    <td className="p-3 text-right">99.66%</td>
                    <td className="p-3 text-right">99.66%</td>
                    <td className="p-3 text-right text-crimson">0.0% (0/7)</td>
                    <td className="p-3 text-right">0.00</td>
                    <td className="p-3 text-right">—</td>
                  </tr>
                  <tr className="text-fog">
                    <td className="p-3">Logistic Regression (54-D)</td>
                    <td className="p-3 text-right">55</td>
                    <td className="p-3 text-right">41.18%</td>
                    <td className="p-3 text-right">84.18%</td>
                    <td className="p-3 text-right">55.31%</td>
                    <td className="p-3 text-right text-amber">100% (7/7)</td>
                    <td className="p-3 text-right text-crimson">17.02</td>
                    <td className="p-3 text-right">—</td>
                  </tr>
                  <tr className="text-fog">
                    <td className="p-3">Random Forest (54-D)</td>
                    <td className="p-3 text-right">250,000</td>
                    <td className="p-3 text-right">40.90%</td>
                    <td className="p-3 text-right">88.79%</td>
                    <td className="p-3 text-right">56.00%</td>
                    <td className="p-3 text-right text-amber">100% (7/7)</td>
                    <td className="p-3 text-right text-crimson">4.99</td>
                    <td className="p-3 text-right">—</td>
                  </tr>
                  <tr className="text-fog">
                    <td className="p-3">Temporal GRU (10-Step Seq)</td>
                    <td className="p-3 text-right">239,517</td>
                    <td className="p-3 text-right">46.91%</td>
                    <td className="p-3 text-right">49.07%</td>
                    <td className="p-3 text-right">47.97%</td>
                    <td className="p-3 text-right text-crimson">42.9% (3/7)</td>
                    <td className="p-3 text-right text-crimson">26.02</td>
                    <td className="p-3 text-right">0.2656</td>
                  </tr>
                  <tr className="text-fog">
                    <td className="p-3">Temporal Transformer (10-Step)</td>
                    <td className="p-3 text-right">341,789</td>
                    <td className="p-3 text-right">30.87%</td>
                    <td className="p-3 text-right">16.12%</td>
                    <td className="p-3 text-right">21.18%</td>
                    <td className="p-3 text-right text-crimson">28.6% (2/7)</td>
                    <td className="p-3 text-right text-crimson">20.63</td>
                    <td className="p-3 text-right">0.2721</td>
                  </tr>
                  <tr className="text-fog">
                    <td className="p-3">SparseRSSM (Raw AR Rollout)</td>
                    <td className="p-3 text-right">214,334</td>
                    <td className="p-3 text-right">38.90%</td>
                    <td className="p-3 text-right">96.05%</td>
                    <td className="p-3 text-right">55.37%</td>
                    <td className="p-3 text-right text-amber">100% (7/7)</td>
                    <td className="p-3 text-right text-crimson">34.12</td>
                    <td className="p-3 text-right">0.3166</td>
                  </tr>
                  <tr className="text-fog">
                    <td className="p-3">TFCNet-F (Raw Spectral)</td>
                    <td className="p-3 text-right">400,914</td>
                    <td className="p-3 text-right">38.08%</td>
                    <td className="p-3 text-right">99.76%</td>
                    <td className="p-3 text-right">55.12%</td>
                    <td className="p-3 text-right text-amber">100% (7/7)</td>
                    <td className="p-3 text-right text-crimson">38.24</td>
                    <td className="p-3 text-right">0.2494</td>
                  </tr>
                  <tr className="bg-teal/10 font-bold text-paper border-t-2 border-teal/60">
                    <td className="p-3 flex items-center gap-2">
                      <span className="size-2 rounded-full bg-teal" />
                      Two-Stage Operational SOC
                    </td>
                    <td className="p-3 text-right text-teal">615,248</td>
                    <td className="p-3 text-right text-teal">96.88%</td>
                    <td className="p-3 text-right text-teal">100.0%</td>
                    <td className="p-3 text-right text-teal">98.41%</td>
                    <td className="p-3 text-right text-teal">100% (7/7)</td>
                    <td className="p-3 text-right text-teal">0.12</td>
                    <td className="p-3 text-right text-teal">0.2474</td>
                  </tr>
                </tbody>
              </table>
            </div>

            <div className="mt-4 grid gap-4 sm:grid-cols-2 text-xs font-mono text-fog">
              <div className="rounded-lg border border-fog-deep/30 bg-void-900 p-3">
                <span className="text-paper font-semibold">Setting A (Seen In-Distribution, 29 ep):</span>
                <p className="mt-1">
                  Two-Stage SOC achieves <strong className="text-teal">99.20% F1</strong>, <strong className="text-teal">100% Onset Recall (29/29)</strong>, and <strong className="text-teal">0.07 FA/hr Inc</strong>.
                </p>
              </div>
              <div className="rounded-lg border border-fog-deep/30 bg-void-900 p-3">
                <span className="text-paper font-semibold">Setting B (Mixed Generalisation, 7 ep):</span>
                <p className="mt-1">
                  Two-Stage SOC achieves <strong className="text-teal">98.41% F1</strong>, <strong className="text-teal">100% Onset Recall (7/7)</strong>, and <strong className="text-teal">0.12 FA/hr Inc</strong>.
                </p>
              </div>
            </div>
          </div>
        </div>
      </main>

      <footer className="border-t border-fog-deep/40 px-6 py-8 text-center text-xs font-mono text-fog bg-void-950/80">
        Aegis Vantage Research Publications · Neural AI DTU · Verbatim Experimental Record
      </footer>
    </div>
  );
}
