import { createFileRoute, Link } from "@tanstack/react-router";
import { Shield, Lock, CheckCircle2, Server, Key, FileText, ArrowLeft } from "lucide-react";
import { pageHead } from "@/lib/head";

export const Route = createFileRoute("/security")({
  head: pageHead(
    "Security Architecture & Compliance — Aegis Vantage",
    "Zero-trust telemetry ingestion, local on-premise neural inference, SOC2 Type II, ISO27001 compliance and cryptographic data safeguards.",
  ),
  component: SecurityPage,
});

function SecurityPage() {
  return (
    <div className="network-field min-h-screen">
      {/* Top Navigation */}
      <header className="flex h-16 items-center justify-between border-b border-fog-deep/40 px-6 md:px-12 backdrop-blur-md bg-void-900/80">
        <Link to="/" className="flex items-center gap-2.5 text-fog hover:text-paper transition-colors">
          <ArrowLeft className="size-4 text-teal" />
          <span className="font-mono text-xs uppercase tracking-wider">Back to Aegis Vantage</span>
        </Link>
        <div className="flex items-center gap-3">
          <span className="size-[16px] rotate-45 rounded-[3px] border-2 border-teal" />
          <span className="font-display text-sm font-semibold text-paper">Security Architecture</span>
        </div>
      </header>

      <main className="mx-auto max-w-[1020px] px-6 py-14 md:px-10">
        <div className="border-b border-fog-deep/40 pb-8">
          <div className="inline-flex items-center gap-2 rounded-full border border-teal/40 bg-teal/10 px-3 py-1 text-xs font-mono text-teal">
            <Shield className="size-3.5" />
            Enterprise Defense Assurance
          </div>
          <h1 className="mt-4 font-display text-3xl font-bold tracking-tight text-paper sm:text-4xl">
            Security Architecture & Zero-Trust Telemetry
          </h1>
          <p className="mt-3 max-w-[70ch] text-base text-fog">
            Aegis Vantage is engineered from the ground up to operate in high-assurance government, defense, and Tier-1 financial environments where sensitive PCAP payloads never cross trust boundaries.
          </p>
        </div>

        {/* 4 Pillars Grid */}
        <div className="mt-12 grid gap-6 sm:grid-cols-2">
          <div className="rounded-xl border border-fog-deep/40 bg-void-800/80 p-6 backdrop-blur-sm">
            <div className="size-10 rounded-lg border border-teal/40 bg-teal/10 flex items-center justify-center text-teal">
              <Server className="size-5" />
            </div>
            <h3 className="mt-4 font-display text-lg font-semibold text-paper">Local & On-Premise Inference</h3>
            <p className="mt-2 text-sm text-fog leading-relaxed">
              The SparseRSSM and TFCNet model microservice executes locally on your isolated Kubernetes cluster or on-premise GPU nodes. Raw packet captures and decrypted session contents never leave your network boundary.
            </p>
          </div>

          <div className="rounded-xl border border-fog-deep/40 bg-void-800/80 p-6 backdrop-blur-sm">
            <div className="size-10 rounded-lg border border-teal/40 bg-teal/10 flex items-center justify-center text-teal">
              <Lock className="size-5" />
            </div>
            <h3 className="mt-4 font-display text-lg font-semibold text-paper">Zero Payload Retention</h3>
            <p className="mt-2 text-sm text-fog leading-relaxed">
              DPI dissectors parse headers into 54-dimensional statistical behavioral tensors and immediately discard packet payloads from ephemeral memory. No sensitive customer PII or encrypted payloads are stored on disk.
            </p>
          </div>

          <div className="rounded-xl border border-fog-deep/40 bg-void-800/80 p-6 backdrop-blur-sm">
            <div className="size-10 rounded-lg border border-teal/40 bg-teal/10 flex items-center justify-center text-teal">
              <Key className="size-5" />
            </div>
            <h3 className="mt-4 font-display text-lg font-semibold text-paper">Hardware-Backed CMEK Encryption</h3>
            <p className="mt-2 text-sm text-fog leading-relaxed">
              All telemetry metadata, forensic alerts, and audit logs are encrypted in transit via mTLS 1.3 with ChaCha20-Poly1305 and at rest via AES-256 using customer-managed KMS keys (AWS KMS, GCP Cloud KMS, or HashiCorp Vault).
            </p>
          </div>

          <div className="rounded-xl border border-fog-deep/40 bg-void-800/80 p-6 backdrop-blur-sm">
            <div className="size-10 rounded-lg border border-teal/40 bg-teal/10 flex items-center justify-center text-teal">
              <CheckCircle2 className="size-5" />
            </div>
            <h3 className="mt-4 font-display text-lg font-semibold text-paper">Compliance Certifications</h3>
            <p className="mt-2 text-sm text-fog leading-relaxed">
              Aegis Vantage is independently audited under SOC 2 Type II (Security, Confidentiality, Availability) and certified against ISO/IEC 27001:2022 standards. Full audit logs are immutable and cryptographically chained.
            </p>
          </div>
        </div>

        {/* Cryptographic Assurance Details */}
        <div className="mt-14 rounded-2xl border border-fog-deep/40 bg-void-800/50 p-8">
          <h2 className="font-display text-xl font-semibold text-paper">Role-Based Access Control (RBAC) & Immutable Audit</h2>
          <p className="mt-2 text-sm text-fog">
            Granular access controls enforce strict least-privilege policies across all SOC tiers: Analyst, SOC Lead, and Admin. Every mitigation action—including automated segment quarantine—is recorded with actor identity, timestamp, and client TLS fingerprints.
          </p>

          <div className="mt-6 flex flex-wrap gap-4 font-mono text-xs">
            <span className="rounded-md border border-fog-deep bg-void-900 px-3 py-1.5 text-paper">SOC 2 Type II</span>
            <span className="rounded-md border border-fog-deep bg-void-900 px-3 py-1.5 text-paper">ISO/IEC 27001:2022</span>
            <span className="rounded-md border border-fog-deep bg-void-900 px-3 py-1.5 text-paper">FIPS 140-3 Cryptography</span>
            <span className="rounded-md border border-fog-deep bg-void-900 px-3 py-1.5 text-paper">HIPAA / HITECH Compliant</span>
          </div>
        </div>
      </main>

      <footer className="border-t border-fog-deep/40 px-6 py-8 text-center text-xs text-fog">
        Aegis Vantage Security Office · security@aegis-vantage.internal · PGP Key Fingerprint: 4F92 B109 82E1 773C
      </footer>
    </div>
  );
}
