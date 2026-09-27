import { createFileRoute, Link } from "@tanstack/react-router";
import { FileText, ArrowLeft, ShieldAlert, CheckCircle2 } from "lucide-react";
import { pageHead } from "@/lib/head";

export const Route = createFileRoute("/terms")({
  head: pageHead(
    "Terms of Service & Enterprise SLA â€” Flow दृष्टि",
    "Terms of service, enterprise SLA, software licensing, and operational support guarantees.",
  ),
  component: TermsPage,
});

function TermsPage() {
  return (
    <div className="network-field min-h-screen">
      <header className="flex h-16 items-center justify-between border-b border-fog-deep/40 px-6 md:px-12 backdrop-blur-md bg-void-900/80">
        <Link to="/" className="flex items-center gap-2.5 text-fog hover:text-paper transition-colors">
          <ArrowLeft className="size-4 text-teal" />
          <span className="font-mono text-xs uppercase tracking-wider">Back to Flow दृष्टि</span>
        </Link>
        <div className="flex items-center gap-3">
          <span className="size-[16px] rotate-45 rounded-[3px] border-2 border-teal" />
          <span className="font-display text-sm font-semibold text-paper">Terms of Service</span>
        </div>
      </header>

      <main className="mx-auto max-w-[880px] px-6 py-14 md:px-10">
        <div className="border-b border-fog-deep/40 pb-8">
          <div className="inline-flex items-center gap-2 rounded-full border border-teal/40 bg-teal/10 px-3 py-1 text-xs font-mono text-teal">
            <FileText className="size-3.5" />
            Enterprise Licensing & SLA
          </div>
          <h1 className="mt-4 font-display text-3xl font-bold tracking-tight text-paper sm:text-4xl">
            Terms of Service & Service Level Agreement
          </h1>
          <p className="mt-2 text-xs font-mono text-fog">Last Revised: September 2026</p>
        </div>

        <div className="mt-10 space-y-10 text-sm text-fog">
          <section>
            <h2 className="font-display text-lg font-semibold text-paper">1. Enterprise Deployment & Licensing</h2>
            <p className="mt-2 leading-relaxed">
              Flow दृष्टि is licensed on an enterprise node and throughput basis. Authorized organizations are granted a non-exclusive, worldwide license to deploy the cyber world model, microservices, and management console across their infrastructure.
            </p>
          </section>

          <section>
            <h2 className="font-display text-lg font-semibold text-paper">2. Service Level Agreement (SLA) Guarantees</h2>
            <p className="mt-2 leading-relaxed">
              For Enterprise Tier deployments, Flow दृष्टि guarantees a 99.95% uptime availability for the neural inference engine and alert delivery systems. Inference latency is committed to under 250ms per 10-window sequence.
            </p>
          </section>

          <section>
            <h2 className="font-display text-lg font-semibold text-paper">3. Autonomous Actions & Human-in-the-Loop</h2>
            <p className="mt-2 leading-relaxed">
              While Flow दृष्टि provides automated zero-trust microsegmentation quarantine mechanisms, our platform adheres to strict Human-in-the-Loop (HITL) principles. SOC operators retain sovereign control to approve, modify, or override isolation policies.
            </p>
          </section>

          <section>
            <h2 className="font-display text-lg font-semibold text-paper">4. Intellectual Property & Model Weights</h2>
            <p className="mt-2 leading-relaxed">
              All pre-trained neural network architectures (SparseRSSM, TFCNet) and benchmark weights remain the exclusive intellectual property of the Flow दृष्टि engineering team. Any proprietary organizational models fine-tuned on your internal telemetry remain 100% your property.
            </p>
          </section>

          <section>
            <h2 className="font-display text-lg font-semibold text-paper">5. Enterprise Support & Incident Escalation</h2>
            <p className="mt-2 leading-relaxed">
              24/7/365 Tier-3 security engineering support is available for mission-critical deployments. Inquiries can be escalated through your dedicated technical account manager or via <span className="font-mono text-teal">support@aegis-vantage.internal</span>.
            </p>
          </section>
        </div>
      </main>

      <footer className="border-t border-fog-deep/40 px-6 py-8 text-center text-xs text-fog">
        Flow दृष्टि Legal & Compliance Â· Legal entity Northwind Enterprise Defense LLC
      </footer>
    </div>
  );
}
