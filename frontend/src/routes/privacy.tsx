import { createFileRoute, Link } from "@tanstack/react-router";
import { Shield, EyeOff, Database, FileCheck, ArrowLeft } from "lucide-react";
import { pageHead } from "@/lib/head";

export const Route = createFileRoute("/privacy")({
  head: pageHead(
    "Privacy Policy & Data Sovereignty — Flow दृष्टि",
    "Detailed privacy disclosures covering zero payload retention, telemetry feature distillation, and global data sovereignty.",
  ),
  component: PrivacyPage,
});

function PrivacyPage() {
  return (
    <div className="network-field min-h-screen">
      <header className="flex h-16 items-center justify-between border-b border-fog-deep/40 px-6 md:px-12 backdrop-blur-md bg-void-900/80">
        <Link to="/" className="flex items-center gap-2.5 text-fog hover:text-paper transition-colors">
          <ArrowLeft className="size-4 text-teal" />
          <span className="font-mono text-xs uppercase tracking-wider">Back to Flow दृष्टि</span>
        </Link>
        <div className="flex items-center gap-3">
          <span className="size-[16px] rotate-45 rounded-[3px] border-2 border-teal" />
          <span className="font-display text-sm font-semibold text-paper">Privacy Policy</span>
        </div>
      </header>

      <main className="mx-auto max-w-[880px] px-6 py-14 md:px-10">
        <div className="border-b border-fog-deep/40 pb-8">
          <div className="inline-flex items-center gap-2 rounded-full border border-teal/40 bg-teal/10 px-3 py-1 text-xs font-mono text-teal">
            <EyeOff className="size-3.5" />
            Data Protection by Design
          </div>
          <h1 className="mt-4 font-display text-3xl font-bold tracking-tight text-paper sm:text-4xl">
            Privacy Policy & Data Sovereignty
          </h1>
          <p className="mt-2 text-xs font-mono text-fog">Effective Date: September 15, 2026</p>
          <p className="mt-4 text-sm text-fog leading-relaxed">
            At Flow दृष्टि, we believe that advanced threat detection must never compromise personal privacy or confidential network communications. Our system operates on a strict zero-retention telemetry architecture.
          </p>
        </div>

        <div className="mt-10 space-y-10 text-sm text-fog">
          <section>
            <h2 className="font-display text-lg font-semibold text-paper">1. Statistical Feature Distillation (No Raw Payloads)</h2>
            <p className="mt-2 leading-relaxed">
              When network captures (PCAP, IPFIX, NetFlow) enter the Flow दृष्टि ingestion pipeline, our Deep Packet Inspection engine converts network events into 54 non-invertible behavioral statistical features (such as flow inter-arrival variance, destination port entropy, and flag ratios). Raw packet payloads and user data are never persisted.
            </p>
          </section>

          <section>
            <h2 className="font-display text-lg font-semibold text-paper">2. Localized Model Inference</h2>
            <p className="mt-2 leading-relaxed">
              Inference is conducted locally within your private perimeter. The neural models (SparseRSSM and TFCNet) execute inside your dedicated deployment, ensuring that behavioral telemetry never leaves your sovereignty boundary.
            </p>
          </section>

          <section>
            <h2 className="font-display text-lg font-semibold text-paper">3. GDPR, CCPA, and Regulatory Compliance</h2>
            <p className="mt-2 leading-relaxed">
              Because Flow दृष्टि does not collect, track, or monetize personal identifying information (PII), our architecture adheres to GDPR (Articles 25 & 32), the California Consumer Privacy Act (CCPA), and global data protection standards.
            </p>
          </section>

          <section>
            <h2 className="font-display text-lg font-semibold text-paper">4. Retention and Erasure</h2>
            <p className="mt-2 leading-relaxed">
              Forensic alert timelines and audit entries are retained strictly according to your organization's configured data lifecycle policies (defaulting to 30, 60, or 90 days), with immediate cryptographic purge upon retention expiration.
            </p>
          </section>

          <section>
            <h2 className="font-display text-lg font-semibold text-paper">5. Contact Our Privacy Officer</h2>
            <p className="mt-2 leading-relaxed">
              For privacy audits, compliance inquiries, or Data Protection Agreements (DPAs), contact <span className="font-mono text-teal">privacy@aegis-vantage.internal</span>.
            </p>
          </section>
        </div>
      </main>

      <footer className="border-t border-fog-deep/40 px-6 py-8 text-center text-xs text-fog">
        Flow दृष्टि Privacy Office · ISO/IEC 27701 Privacy Information Management Certified
      </footer>
    </div>
  );
}
