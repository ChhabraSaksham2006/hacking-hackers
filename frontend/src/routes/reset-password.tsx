import { useState } from "react";
import { createFileRoute, Link, useRouter } from "@tanstack/react-router";
import { AuthShell, Field } from "@/components/app/AuthShell";
import { pageHead } from "@/lib/head";
import { useResetPassword } from "@/hooks/useApi";

export const Route = createFileRoute("/reset-password")({
  head: pageHead(
    "Reset Password — Aegis Vantage",
    "Choose a new password for your account."
  ),
  validateSearch: (search: Record<string, unknown>): { token?: string } => {
    const token = search['token'] as string | undefined;
    return token !== undefined ? { token } : {};
  },
  component: ResetPasswordPage,
});

function ResetPasswordPage() {
  const { token } = Route.useSearch();
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);

  const resetPassword = useResetPassword();
  const router = useRouter();

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!token) {
      setError("Invalid or missing reset token.");
      return;
    }
    if (password !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }
    setError(null);
    resetPassword.mutate(
      { token, password },
      {
        onSuccess: () => {
          setSuccess(true);
        },
        onError: (err) => {
          setError(err.message || "Failed to reset password.");
        },
      }
    );
  };

  if (!token) {
    return (
      <AuthShell title="Invalid Link">
        <div className="rounded-md bg-crimson/10 p-4 text-[14px] text-crimson text-center mb-6">
          The password reset link is invalid or missing.
        </div>
        <Link
          to="/login"
          className="block w-full rounded-md bg-void-800 border border-void-700 px-4 py-2.5 text-center text-[13px] font-medium text-paper hover:bg-void-700"
        >
          Back to log in
        </Link>
      </AuthShell>
    );
  }

  if (success) {
    return (
      <AuthShell title="Password Reset" note="Your password has been changed.">
        <div className="rounded-md bg-teal/10 p-4 text-[14px] text-teal">
          Password reset successfully. You can now log in.
        </div>
        <Link
          to="/login"
          className="mt-6 block rounded-md bg-teal px-4 py-2.5 text-center text-[13px] font-medium text-void-900 hover:bg-teal/85"
        >
          Go to log in
        </Link>
      </AuthShell>
    );
  }

  return (
    <AuthShell
      title="Reset Password"
      note="Choose a strong new password."
    >
      <form className="space-y-4" onSubmit={handleSubmit}>
        {error ? (
          <div className="rounded-md bg-crimson/10 p-3 text-[13px] text-crimson">
            {error}
          </div>
        ) : null}
        <Field
          label="New Password"
          type="password"
          placeholder="••••••••••"
          hint="12 characters minimum, checked against known breach corpora."
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
        />
        <Field
          label="Confirm Password"
          type="password"
          placeholder="••••••••••"
          value={confirmPassword}
          onChange={(e) => setConfirmPassword(e.target.value)}
          required
        />
        <button
          type="submit"
          disabled={resetPassword.isPending}
          className="mt-2 block w-full rounded-md bg-teal px-4 py-2.5 text-center text-[13px] font-medium text-void-900 hover:bg-teal/85 disabled:opacity-50"
        >
          {resetPassword.isPending ? "Resetting..." : "Reset Password"}
        </button>
      </form>
    </AuthShell>
  );
}
