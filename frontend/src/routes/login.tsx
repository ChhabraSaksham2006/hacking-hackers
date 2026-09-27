import { useState } from "react";
import { createFileRoute, Link, useRouter } from "@tanstack/react-router";
import { AuthShell, Field } from "@/components/app/AuthShell";
import { pageHead } from "@/lib/head";
import { useLogin, useResendVerification } from "@/hooks/useApi";

export const Route = createFileRoute("/login")({
  head: pageHead(
    "Log in â€” Flow दृष्टि",
    "Sign in to the Flow दृष्टि predictive cyber-defence console.",
  ),
  component: LoginPage,
});

function LoginPage() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [unverifiedEmail, setUnverifiedEmail] = useState<string | null>(null);
  const [resendSuccess, setResendSuccess] = useState(false);
  
  const login = useLogin();
  const resend = useResendVerification();
  const router = useRouter();

  const handleResend = () => {
    if (!unverifiedEmail) return;
    setResendSuccess(false);
    resend.mutate(
      { email: unverifiedEmail },
      {
        onSuccess: () => setResendSuccess(true),
        onError: (err) => setError(err.message || "Failed to resend verification email"),
      }
    );
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    login.mutate(
      { email, password },
      {
        onSuccess: (data) => {
          if (data.requiresTwoFactor) {
            router.navigate({
              to: "/two-factor",
              search: { challengeId: data.challengeId },
            });
          } else {
            router.navigate({ to: "/app/dashboard" });
          }
        },
        onError: (err) => {
          if (err.message && err.message.includes("verify your email")) {
            setUnverifiedEmail(email);
          }
          setError(err.message || "Failed to log in");
        },
      }
    );
  };

  return (
    <AuthShell
      title="Log in"
      note="Access is scoped to your organisation and role."
      footer={
        <span>
          No account yet?{" "}
          <Link to="/signup" className="text-teal">
            Request access
          </Link>
        </span>
      }
    >
      <form className="space-y-4" onSubmit={handleSubmit}>
        {error ? (
          <div className="rounded-md bg-crimson/10 p-3 text-[13px] text-crimson">
            {error}
            {unverifiedEmail && (
              <div className="mt-2">
                <button
                  type="button"
                  onClick={handleResend}
                  disabled={resend.isPending}
                  className="text-teal hover:underline disabled:opacity-50"
                >
                  {resend.isPending ? "Sending..." : "Resend verification email"}
                </button>
              </div>
            )}
          </div>
        ) : null}
        {resendSuccess ? (
          <div className="rounded-md bg-teal/10 p-3 text-[13px] text-teal">
            Verification email sent. Please check your inbox.
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
        <Field
          label="Password"
          type="password"
          placeholder="â€¢â€¢â€¢â€¢â€¢â€¢â€¢â€¢â€¢â€¢"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
        />
        <div className="flex items-center justify-between pt-1">
          <Link to="/forgot-password" className="text-[13px] text-fog hover:text-paper">
            Forgot password?
          </Link>
        </div>
        <button
          type="submit"
          disabled={login.isPending}
          className="mt-2 block w-full rounded-md bg-teal px-4 py-2.5 text-center text-[13px] font-medium text-void-900 hover:bg-teal/85 disabled:opacity-50"
        >
          {login.isPending ? "Logging in..." : "Continue"}
        </button>
      </form>
    </AuthShell>
  );
}
