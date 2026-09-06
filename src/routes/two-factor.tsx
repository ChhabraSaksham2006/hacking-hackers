import { createFileRoute, Link } from "@tanstack/react-router";
import { AuthShell } from "@/components/app/AuthShell";
import { pageHead } from "@/lib/head";

export const Route = createFileRoute("/two-factor")({
  head: pageHead(
    "Verification — Aegis Vantage",
    "Enter your six-digit verification code to reach the Aegis Vantage console.",
  ),
  component: TwoFactorPage,
});

function TwoFactorPage() {
  return (
    <AuthShell
      title="Verification code"
      note="Enter the six-digit code from your authenticator app."
      footer={<span>Lost your device? Use a backup code.</span>}
    >
      <div className="flex gap-2.5">
        {Array.from({ length: 6 }).map((_, i) => (
          <input
            key={i}
            inputMode="numeric"
            maxLength={1}
            aria-label={`Digit ${i + 1}`}
            className="mono size-12 rounded-md border border-fog-deep bg-void-700 text-center text-[18px] outline-none focus:border-teal"
          />
        ))}
      </div>
      <p className="mt-3 text-[12px] text-fog">Resend available in 0:42</p>
      <Link
        to="/app/dashboard"
        className="mt-6 block rounded-md bg-teal px-4 py-2.5 text-center text-[13px] font-medium text-void-900 hover:bg-teal/85"
      >
        Verify and open console
      </Link>
    </AuthShell>
  );
}
