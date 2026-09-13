import { useState } from "react";
import { createFileRoute, Link, useRouter, useLocation } from "@tanstack/react-router";
import { AuthShell, Field } from "@/components/app/AuthShell";
import { pageHead } from "@/lib/head";
import { useVerify2FA } from "@/hooks/useApi";

export const Route = createFileRoute("/two-factor")({
  head: pageHead(
    "Verification — Aegis Vantage",
    "Enter your six-digit verification code to reach the Aegis Vantage console.",
  ),
  validateSearch: (search: Record<string, unknown>): { challengeId?: string | undefined } => ({
    challengeId: search['challengeId'] as string | undefined,
  }),
  component: TwoFactorPage,
});

function TwoFactorPage() {
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);

  const verify = useVerify2FA();
  const router = useRouter();

  const { challengeId } = Route.useSearch();

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!challengeId) {
      setError("No active 2FA challenge found. Please log in again.");
      return;
    }
    if (code.length !== 6) {
      setError("Please enter a 6-digit code.");
      return;
    }
    
    setError(null);
    verify.mutate(
      { challengeId, code },
      {
        onSuccess: () => {
          router.navigate({ to: "/app/dashboard" });
        },
        onError: (err) => {
          setError(err.message || "Failed to verify 2FA code");
        },
      }
    );
  };

  return (
    <AuthShell
      title="Verification code"
      note="Enter the six-digit code from your authenticator app."
      footer={<span>Lost your device? Use a backup code.</span>}
    >
      <form onSubmit={handleSubmit}>
        {error ? (
          <div className="mb-4 rounded-md bg-crimson/10 p-3 text-[13px] text-crimson">
            {error}
          </div>
        ) : null}
        
        <Field
          label="6-digit code"
          type="text"
          inputMode="numeric"
          maxLength={6}
          placeholder="000000"
          value={code}
          onChange={(e) => setCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
          autoFocus
          required
        />
        <p className="mt-3 text-[12px] text-fog">Resend available in 0:42</p>
        <button
          type="submit"
          disabled={verify.isPending}
          className="mt-6 block w-full rounded-md bg-teal px-4 py-2.5 text-center text-[13px] font-medium text-void-900 hover:bg-teal/85 disabled:opacity-50"
        >
          {verify.isPending ? "Verifying..." : "Verify and open console"}
        </button>
      </form>
    </AuthShell>
  );
}
