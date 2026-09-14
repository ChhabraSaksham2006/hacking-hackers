import { useState } from "react";
import { createFileRoute, Link } from "@tanstack/react-router";
import { AuthShell, Field } from "@/components/app/AuthShell";
import { pageHead } from "@/lib/head";
import { useForgotPassword } from "@/hooks/useApi";

export const Route = createFileRoute("/forgot-password")({
  head: pageHead(
    "Forgot Password — Aegis Vantage",
    "Request a password reset link."
  ),
  component: ForgotPasswordPage,
});

function ForgotPasswordPage() {
  const [email, setEmail] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);

  const forgotPassword = useForgotPassword();

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    forgotPassword.mutate(
      { email },
      {
        onSuccess: () => {
          setSuccess(true);
        },
        onError: (err) => {
          setError(err.message || "Failed to request password reset");
        },
      }
    );
  };

  if (success) {
    return (
      <AuthShell title="Check your email" note="Password reset requested.">
        <div className="rounded-md bg-teal/10 p-4 text-[14px] text-teal">
          If that email is registered, a password reset link has been sent.
        </div>
        <Link
          to="/login"
          className="mt-6 block rounded-md bg-teal px-4 py-2.5 text-center text-[13px] font-medium text-void-900 hover:bg-teal/85"
        >
          Back to log in
        </Link>
      </AuthShell>
    );
  }

  return (
    <AuthShell
      title="Forgot Password"
      note="Enter your email to receive a reset link."
      footer={
        <span>
          Remember your password?{" "}
          <Link to="/login" className="text-teal">
            Log in
          </Link>
        </span>
      }
    >
      <form className="space-y-4" onSubmit={handleSubmit}>
        {error ? (
          <div className="rounded-md bg-crimson/10 p-3 text-[13px] text-crimson">
            {error}
          </div>
        ) : null}
        <Field
          label="Work email"
          type="email"
          placeholder="analyst@company.com"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          required
        />
        <button
          type="submit"
          disabled={forgotPassword.isPending}
          className="mt-2 block w-full rounded-md bg-teal px-4 py-2.5 text-center text-[13px] font-medium text-void-900 hover:bg-teal/85 disabled:opacity-50"
        >
          {forgotPassword.isPending ? "Sending link..." : "Send reset link"}
        </button>
      </form>
    </AuthShell>
  );
}
