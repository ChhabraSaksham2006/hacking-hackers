import { createFileRoute, Link } from "@tanstack/react-router";
import { BookOpen, Code2, Terminal, Cpu, ArrowLeft, Layers, CheckCircle2 } from "lucide-react";
import { pageHead } from "@/lib/head";

export const Route = createFileRoute("/docs")({
  head: pageHead(
    "Technical Documentation & Architecture Whitepaper — Aegis Vantage",
    "API reference, SparseRSSM + TFCNet architecture specifications, mathematical formulation, and deployment guides.",
  ),
  component: DocsPage,
});

function DocsPage() {
  return (
    <div className="network-field min-h-screen">
      <header className="flex h-16 items-center justify-between border-b border-fog-deep/40 px-6 md:px-12 backdrop-blur-md bg-void-900/80">
        <Link to="/" className="flex items-center gap-2.5 text-fog hover:text-paper transition-colors">
          <ArrowLeft className="size-4 text-teal" />
          <span className="font-mono text-xs uppercase tracking-wider">Back to Aegis Vantage</span>
        </Link>
        <div className="flex items-center gap-3">
          <span className="size-[16px] rotate-45 rounded-[3px] border-2 border-teal" />
          <span className="font-display text-sm font-semibold text-paper">Documentation & Whitepaper</span>
        </div>
      </header>

      <main className="mx-auto max-w-[1080px] px-6 py-14 md:px-10">
        <div className="border-b border-fog-deep/40 pb-8">
          <div className="inline-flex items-center gap-2 rounded-full border border-teal/40 bg-teal/10 px-3 py-1 text-xs font-mono text-teal">
            <BookOpen className="size-3.5" />
            Cyber World Model Specification
          </div>
          <h1 className="mt-4 font-display text-3xl font-bold tracking-tight text-paper sm:text-4xl">
            Technical Documentation & Model Whitepaper
          </h1>
          <p className="mt-3 max-w-[75ch] text-base text-fog">
            Complete technical guide to the Deep Hybrid Architecture combining Sparse Recurrent State-Space Models (SparseRSSM) and Time-Frequency Consistency Transformers (TFCNet).
          </p>
        </div>

        {/* Quick Nav Cards */}
        <div className="mt-10 grid gap-5 sm:grid-cols-3">
          <div className="rounded-xl border border-fog-deep/40 bg-void-800/80 p-5">
            <div className="size-9 rounded-lg border border-teal/40 bg-teal/10 flex items-center justify-center text-teal">
              <Cpu className="size-4" />
            </div>
            <h3 className="mt-3 font-display font-semibold text-paper">SparseRSSM Core</h3>
            <p className="mt-1 text-xs text-fog">
              256-D deterministic latent transition + stochastic posterior with L1 sparsity enforcement.
            </p>
          </div>

          <div className="rounded-xl border border-fog-deep/40 bg-void-800/80 p-5">
            <div className="size-9 rounded-lg border border-teal/40 bg-teal/10 flex items-center justify-center text-teal">
              <Layers className="size-4" />
            </div>
            <h3 className="mt-3 font-display font-semibold text-paper">TFCNet Spectral</h3>
            <p className="mt-1 text-xs text-fog">
              Dual-branch time-frequency consistency transformer resolving cross-window periodic anomalies.
            </p>
          </div>

          <div className="rounded-xl border border-fog-deep/40 bg-void-800/80 p-5">
            <div className="size-9 rounded-lg border border-teal/40 bg-teal/10 flex items-center justify-center text-teal">
              <Terminal className="size-4" />
            </div>
            <h3 className="mt-3 font-display font-semibold text-paper">REST & WebSocket API</h3>
            <p className="mt-1 text-xs text-fog">
              FastAPI endpoints (`/predict`, `/predict/step`, `/predict/init`) and Socket.io live streams.
            </p>
          </div>
        </div>

        {/* Architecture Formulation Deep Dive */}
        <div className="mt-12 space-y-8">
          <div className="rounded-2xl border border-fog-deep/40 bg-void-800/50 p-6 md:p-8">
            <h2 className="font-display text-xl font-bold text-paper">1. Mathematical Formulation & Latent Dynamics</h2>
            <p className="mt-3 text-sm text-fog leading-relaxed">
              Given a sequence of network telemetry state vectors <span className="font-mono text-teal">x_1:T ∈ R^(T × 54)</span>, the SparseRSSM maintains a recurrent deterministic state <span className="font-mono text-teal">h_t = f(h_(t-1), z_(t-1), a_(t-1))</span> and a stochastic posterior <span className="font-mono text-teal">z_t ~ q(z_t | h_t, x_t)</span> parameterized as a diagonal Gaussian.
            </p>
            <div className="mt-4 rounded-lg bg-void-900 p-4 font-mono text-xs text-paper border border-fog-deep/30 overflow-x-auto">
              <code>
                {`L_RSSM = E_q [ sum_{t=1}^T ( -log p(x_t | h_t, z_t) + KL(q(z_t | h_t, x_t) || p(z_t | h_t)) + λ_sparse ||W_sparse||_1 ) ]`}
              </code>
            </div>
          </div>

          <div className="rounded-2xl border border-fog-deep/40 bg-void-800/50 p-6 md:p-8">
            <h2 className="font-display text-xl font-bold text-paper">2. REST Inference Endpoint API</h2>
            <p className="mt-2 text-sm text-fog">
              The model microservice exposes real-time inference over HTTP POST:
            </p>
            <div className="mt-4 rounded-lg bg-void-900 p-4 font-mono text-xs text-teal border border-fog-deep/30 overflow-x-auto">
              <code>
                {`curl -X POST "http://localhost:7860/predict/step" \\
  -H "Content-Type: application/json" \\
  -d '{"step_index": 47}'`}
              </code>
            </div>
            <div className="mt-3 text-xs font-mono text-fog">
              Response returns calibrated probability, SparseRSSM raw logit, TFCNet logit, lead time (s), and physical flow predictions.
            </div>
          </div>
        </div>
      </main>

      <footer className="border-t border-fog-deep/40 px-6 py-8 text-center text-xs text-fog">
        Aegis Vantage Research Publications · NeurIPS / IEEE S&P Cyber Defense Benchmark Series
      </footer>
    </div>
  );
}
