import { createFileRoute, Link } from "@tanstack/react-router";
import { BookOpen, Code2, Terminal, Cpu, ArrowLeft, Layers, CheckCircle2, Zap } from "lucide-react";
import { pageHead } from "@/lib/head";
import { MathFormula } from "@/components/common/MathFormula";

export const Route = createFileRoute("/docs")({
  head: pageHead(
    "Technical Documentation & Architecture Whitepaper — Aegis Vantage",
    "API reference, SparseRSSM + TFCNet architecture specifications, mathematical formulation, and deployment guides.",
  ),
  component: DocsPage,
});

export function DocsPage() {
  return (
    <div className="network-field min-h-screen selection:bg-teal selection:text-void-900 bg-void-900">
      <header className="sticky top-0 z-50 flex h-16 items-center justify-between border-b border-fog-deep/40 px-6 md:px-12 backdrop-blur-xl bg-void-900/85">
        <Link to="/" className="flex items-center gap-2.5 text-fog hover:text-paper transition-colors">
          <ArrowLeft className="size-4 text-teal" />
          <span className="font-mono text-xs uppercase tracking-wider">Back to Aegis Vantage</span>
        </Link>
        <div className="flex items-center gap-3">
          <span className="size-[16px] rotate-45 rounded-[3px] border-2 border-teal shadow-xs shadow-teal/50" />
          <span className="font-display text-sm font-semibold text-paper">Documentation & Whitepaper</span>
        </div>
      </header>

      <main className="mx-auto max-w-[1120px] px-6 py-14 md:px-10">
        <div className="border-b border-fog-deep/40 pb-8">
          <div className="inline-flex items-center gap-2 rounded-full border border-teal/40 bg-teal/10 px-3.5 py-1 text-xs font-mono text-teal">
            <BookOpen className="size-3.5 text-teal" />
            Cyber World Model Specification v4.2.1
          </div>
          <h1 className="mt-4 font-display text-3xl font-extrabold tracking-tight text-paper sm:text-4xl">
            Technical Documentation & Model Whitepaper
          </h1>
          <p className="mt-3 max-w-[78ch] text-base text-fog leading-relaxed">
            Rigorous mathematical specification of the Deep Hybrid Cyber World Model: combining Sparse Recurrent State-Space Models (SparseRSSM) and Dual-Domain Time-Frequency Consistency Transformers (TFCNet).
          </p>
        </div>

        {/* Quick Nav Cards */}
        <div className="mt-10 grid gap-5 sm:grid-cols-3">
          <div className="rounded-xl border border-teal/30 bg-void-800/60 p-5 backdrop-blur-md transition-all hover:border-teal/60">
            <div className="size-9 rounded-lg border border-teal/40 bg-teal/10 flex items-center justify-center text-teal">
              <Cpu className="size-4" />
            </div>
            <h3 className="mt-3 font-display font-semibold text-paper">SparseRSSM Core</h3>
            <p className="mt-1 text-xs text-fog leading-relaxed">
              256-D deterministic latent transition + stochastic Gaussian posterior with L1 sparsity regularization.
            </p>
          </div>

          <div className="rounded-xl border border-amber/30 bg-void-800/60 p-5 backdrop-blur-md transition-all hover:border-amber/60">
            <div className="size-9 rounded-lg border border-amber/40 bg-amber/10 flex items-center justify-center text-amber">
              <Layers className="size-4" />
            </div>
            <h3 className="mt-3 font-display font-semibold text-paper">TFCNet Spectral</h3>
            <p className="mt-1 text-xs text-fog leading-relaxed">
              Inverted Transformer with 4 cross-attention heads operating over FFT spectral representations.
            </p>
          </div>

          <div className="rounded-xl border border-fog-deep/40 bg-void-800/60 p-5 backdrop-blur-md transition-all hover:border-fog-deep/80">
            <div className="size-9 rounded-lg border border-fog-deep/40 bg-void-700/50 flex items-center justify-center text-paper">
              <Terminal className="size-4" />
            </div>
            <h3 className="mt-3 font-display font-semibold text-paper">REST & Telemetry API</h3>
            <p className="mt-1 text-xs text-fog leading-relaxed">
              Sub-25ms PyTorch FastAPI endpoints (<code className="text-teal">/predict/step</code>) and live Socket.io events.
            </p>
          </div>
        </div>

        {/* Mathematical Formulation Deep Dive */}
        <div className="mt-14 space-y-10">
          {/* Section 1: SparseRSSM */}
          <div className="rounded-2xl border border-teal/30 bg-void-800/50 p-6 md:p-8 backdrop-blur-xl shadow-xl">
            <div className="flex items-center gap-2">
              <span className="rounded bg-teal/15 px-2.5 py-0.5 font-mono text-xs text-teal font-semibold">
                Section 1
              </span>
              <h2 className="font-display text-2xl font-bold text-paper">
                SparseRSSM: State-Space Formulation & Optimization
              </h2>
            </div>

            <p className="mt-4 text-sm text-fog leading-relaxed">
              Let <MathFormula math="x_{1:T} = (x_1, \dots, x_T)" displayMode={false} /> denote a sequential observation trajectory where each temporal slice <MathFormula math="x_t \in \mathbb{R}^{54}" displayMode={false} /> is a normalized vector of network telemetry metrics.
              The world model factorizes the latent environment into a deterministic recurrent memory <MathFormula math="h_t \in \mathbb{R}^{128}" displayMode={false} /> and a stochastic state <MathFormula math="z_t \in \mathbb{R}^{128}" displayMode={false} />.
            </p>

            {/* Recurrent Equations */}
            <div className="mt-6 grid gap-4 md:grid-cols-2">
              <div className="rounded-xl border border-fog-deep/30 bg-void-950/80 p-4">
                <span className="text-xs font-mono text-teal font-semibold">Deterministic State Transition:</span>
                <div className="mt-3 text-paper overflow-x-auto py-2">
                  <MathFormula math="h_t = f_\theta(h_{t-1}, z_{t-1}, a_{t-1})" displayMode={true} />
                </div>
                <p className="text-[11px] text-fog mt-2">
                  Parameterized via an expanded GRU cell with recurrent hidden dimension 128.
                </p>
              </div>

              <div className="rounded-xl border border-fog-deep/30 bg-void-950/80 p-4">
                <span className="text-xs font-mono text-teal font-semibold">Stochastic Posterior Distribution:</span>
                <div className="mt-3 text-paper overflow-x-auto py-2">
                  <MathFormula math="q_\phi(z_t \mid h_t, x_t) = \mathcal{N}\big(\mu_\phi(h_t, x_t),\, \operatorname{diag}(\sigma_\phi^2(h_t, x_t))\big)" displayMode={true} />
                </div>
                <p className="text-[11px] text-fog mt-2">
                  Diagonal Gaussian reparameterized with <MathFormula math="z_t = \mu + \sigma \odot \epsilon" displayMode={false} />, <MathFormula math="\epsilon \sim \mathcal{N}(0, I)" displayMode={false} />.
                </p>
              </div>
            </div>

            {/* Full SparseRSSM Objective Equation */}
            <div className="mt-6 rounded-xl border border-teal/40 bg-void-950/90 p-5 shadow-lg shadow-teal/5">
              <span className="font-mono text-xs text-teal font-semibold uppercase tracking-wider">
                Full SparseRSSM Variational Objective (ELBO + L1 Sparsity):
              </span>
              <div className="mt-4 overflow-x-auto py-3 text-center">
                <MathFormula
                  math="\mathcal{L}_{\text{RSSM}}(\theta, \phi) = \mathbb{E}_{q_\phi} \left[ \sum_{t=1}^T \Big( -\log p_\theta(x_t \mid h_t, z_t) + \beta \, D_{\mathrm{KL}}\big(q_\phi(z_t \mid h_t, x_t) \,\|\, p_\theta(z_t \mid h_t)\big) \Big) \right] + \lambda_1 \|W_{\text{sparse}}\|_1"
                  displayMode={true}
                />
              </div>
              <div className="mt-3 grid gap-3 sm:grid-cols-3 text-[11px] font-mono border-t border-fog-deep/30 pt-3 text-fog">
                <div>
                  <strong className="text-paper">Reconstruction:</strong> <MathFormula math="-\log p_\theta(x_t \mid h_t, z_t)" displayMode={false} /> evaluates state reconstruction fidelity.
                </div>
                <div>
                  <strong className="text-paper">KL Divergence:</strong> <MathFormula math="D_{\mathrm{KL}}(q_\phi \| p_\theta)" displayMode={false} /> aligns posterior inference with recurrent prior.
                </div>
                <div>
                  <strong className="text-paper">L1 Regularization:</strong> <MathFormula math="\lambda_1 \|W\|_1" displayMode={false} /> induces sparsity (<MathFormula math="\lambda_1 = 1.0" displayMode={false} />) against benign noise.
                </div>
              </div>
            </div>
          </div>

          {/* Section 2: TFCNet */}
          <div className="rounded-2xl border border-amber/30 bg-void-800/50 p-6 md:p-8 backdrop-blur-xl shadow-xl">
            <div className="flex items-center gap-2">
              <span className="rounded bg-amber/15 px-2.5 py-0.5 font-mono text-xs text-amber font-semibold">
                Section 2
              </span>
              <h2 className="font-display text-2xl font-bold text-paper">
                TFCNet: Time-Frequency Cross-Domain Attention
              </h2>
            </div>

            <p className="mt-4 text-sm text-fog leading-relaxed">
              Adversary beaconing often introduces temporal jitter to evade standard sequential detectors. TFCNet transforms the temporal telemetry window into the spectral domain using discrete 1D Fast Fourier Transforms (FFT):
            </p>

            <div className="mt-6 grid gap-4 md:grid-cols-2">
              <div className="rounded-xl border border-fog-deep/30 bg-void-950/80 p-4">
                <span className="text-xs font-mono text-amber font-semibold">Discrete Fourier Representation:</span>
                <div className="mt-3 text-paper overflow-x-auto py-2">
                  <MathFormula math="X_{\text{freq}}(k) = \sum_{n=0}^{N-1} x(n) \cdot e^{-i 2\pi k n / N}" displayMode={true} />
                </div>
                <p className="text-[11px] text-fog mt-2">
                  Extracts power spectral density across 10-step rolling temporal windows.
                </p>
              </div>

              <div className="rounded-xl border border-fog-deep/30 bg-void-950/80 p-4">
                <span className="text-xs font-mono text-amber font-semibold">Cross-Attention Formulation:</span>
                <div className="mt-3 text-paper overflow-x-auto py-2">
                  <MathFormula math="\operatorname{Attn}(Q, K, V) = \operatorname{Softmax}\left(\frac{Q_{\text{temp}} K_{\text{freq}}^\top}{\sqrt{d_k}}\right) V_{\text{freq}}" displayMode={true} />
                </div>
                <p className="text-[11px] text-fog mt-2">
                  Multi-head cross-attention (<MathFormula math="h=4" displayMode={false} />, <MathFormula math="d_k=32" displayMode={false} />) aligns temporal bursts with periodic spectral spikes.
                </p>
              </div>
            </div>

            {/* TFCNet Loss */}
            <div className="mt-6 rounded-xl border border-amber/40 bg-void-950/90 p-5 shadow-lg shadow-amber/5">
              <span className="font-mono text-xs text-amber font-semibold uppercase tracking-wider">
                Cross-Domain Spectral Consistency Loss:
              </span>
              <div className="mt-4 overflow-x-auto py-3 text-center">
                <MathFormula
                  math="\mathcal{L}_{\text{TFC}} = 1 - \frac{Z_{\text{temporal}} \cdot Z_{\text{spectral}}}{\|Z_{\text{temporal}}\|_2 \, \|Z_{\text{spectral}}\|_2} + \lambda_{\text{align}} \, \|Z_{\text{temporal}} - Z_{\text{spectral}}\|_2^2"
                  displayMode={true}
                />
              </div>
              <p className="text-[11px] font-mono text-fog mt-2 border-t border-fog-deep/30 pt-2">
                Enforces representational invariance between time-domain burst sequences and frequency-domain beaconing signatures.
              </p>
            </div>
          </div>

          {/* Section 3: Gated Ensemble Fusion */}
          <div className="rounded-2xl border border-fog-deep/40 bg-void-800/50 p-6 md:p-8 backdrop-blur-xl shadow-xl">
            <div className="flex items-center gap-2">
              <span className="rounded bg-paper/15 px-2.5 py-0.5 font-mono text-xs text-paper font-semibold">
                Section 3
              </span>
              <h2 className="font-display text-2xl font-bold text-paper">
                Gated Ensemble Fusion & Early Horizon Derivation
              </h2>
            </div>

            <p className="mt-4 text-sm text-fog leading-relaxed">
              The calibrated infiltration probability <MathFormula math="\hat{y}_t \in [0, 1]" displayMode={false} /> is calculated by a parameterized gating network fusing temporal state logits with spectral transformer representations:
            </p>

            <div className="mt-6 rounded-xl border border-fog-deep/30 bg-void-950/90 p-5 text-center overflow-x-auto">
              <MathFormula
                math="\hat{y}_t = \sigma\Big( w_{\text{gate}} \cdot \hat{y}_{\text{RSSM}}(h_t, z_t) + (1 - w_{\text{gate}}) \cdot \hat{y}_{\text{TFCNet}}(Z_{\text{cross}}) \Big), \quad w_{\text{gate}} = 0.60"
                displayMode={true}
              />
            </div>

            <div className="mt-6 grid gap-4 sm:grid-cols-2 text-xs font-mono">
              <div className="rounded-lg border border-fog-deep/30 bg-void-900 p-4">
                <span className="text-teal font-semibold">Decision Boundary Calibration:</span>
                <p className="mt-2 text-fog">
                  <MathFormula math="\text{Alert State} = \begin{cases} \text{CRITICAL (Lateral Movement)}, & \hat{y}_t \ge 0.85 \\ \text{HIGH (Initial Access)}, & 0.48 \le \hat{y}_t < 0.85 \\ \text{WATCH (Reconnaissance)}, & 0.24 \le \hat{y}_t < 0.48 \\ \text{CALM (Normal Baseline)}, & \hat{y}_t < 0.24 \end{cases}" displayMode={true} />
                </p>
              </div>

              <div className="rounded-lg border border-fog-deep/30 bg-void-900 p-4">
                <span className="text-teal font-semibold">Early Intervention Margin Formulation:</span>
                <div className="mt-3">
                  <MathFormula math="\Delta \tau_{\text{lead}} = t_{\text{domain\_compromise}} - \min \{ t \mid \hat{y}_t \ge 0.85 \}" displayMode={true} />
                </div>
                <p className="mt-3 text-[11px] text-fog">
                  Evaluated across CSE-CIC-IDS2018 Thursday test sequences, yielding a mean lead time of <strong className="text-teal">20.0 seconds</strong>.
                </p>
              </div>
            </div>
          </div>

          {/* Section 4: REST API & Integration */}
          <div className="rounded-2xl border border-fog-deep/40 bg-void-800/50 p-6 md:p-8 backdrop-blur-xl">
            <h2 className="font-display text-xl font-bold text-paper">4. REST Inference Microservice Endpoint API</h2>
            <p className="mt-2 text-sm text-fog">
              The model microservice exposes low-latency PyTorch inference over HTTP POST:
            </p>
            <div className="mt-4 rounded-xl bg-void-950 p-4 font-mono text-xs text-teal border border-fog-deep/30 overflow-x-auto shadow-inner">
              <pre>
{`curl -X POST "http://localhost:7860/predict/step" \\
  -H "Content-Type: application/json" \\
  -d '{"step_index": 47}'`}
              </pre>
            </div>
            <div className="mt-4 text-xs font-mono text-fog">
              Returns JSON payload containing calibrated probability, SparseRSSM hidden state norm, TFCNet attention weights, lead time (s), and top 5 physical flow predictions.
            </div>
          </div>
        </div>
      </main>

      <footer className="border-t border-fog-deep/40 px-6 py-8 text-center text-xs font-mono text-fog bg-void-950/80">
        Aegis Vantage Research Publications · NeurIPS / IEEE S&P Cyber Defense Benchmark Series
      </footer>
    </div>
  );
}
