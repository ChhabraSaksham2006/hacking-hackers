import { useEffect, useState, useRef } from "react";
import { createFileRoute, Link, useRouter } from "@tanstack/react-router";
import { AuthShell } from "@/components/app/AuthShell";
import { pageHead } from "@/lib/head";
import { useVerifyEmail } from "@/hooks/useApi";

export const Route = createFileRoute("/verify-email")({
  head: pageHead(
    "Verify Email — Flow दृष्टि",
    "Verifying your email address."
  ),
  validateSearch: (search: Record<string, unknown>): { token?: string } => {
    const token = search['token'] as string | undefined;
    return token !== undefined ? { token } : {};
  },
  component: VerifyEmailPage,
});

function VerifyEmailPage() {
  const { token } = Route.useSearch();
  const verify = useVerifyEmail();
  const [status, setStatus] = useState<"loading" | "success" | "error">("loading");
  const [message, setMessage] = useState("Verifying your email...");
  
  // Use a ref to prevent strict mode double-firing from causing an error
  // since the token is single-use and deleted upon verification.
  const hasAttempted = useRef(false);

  useEffect(() => {
    if (!token) {
      setStatus("error");
      setMessage("Verification link is invalid or missing.");
      return;
    }

    if (!hasAttempted.current) {
      hasAttempted.current = true;
      verify.mutate(token, {
        onSuccess: (data) => {
          setStatus("success");
          setMessage(data.message || "Email verified successfully.");
        },
        onError: (err) => {
          setStatus("error");
          setMessage(err.message || "Failed to verify email. The link may have expired.");
        },
      });
    }
  }, [token, verify]);

  return (
    <AuthShell title="Email Verification">
      {status === "loading" && (
        <div className="rounded-md bg-fog/10 p-4 text-[14px] text-fog text-center">
          {message}
        </div>
      )}
      
      {status === "success" && (
        <>
          <div className="rounded-md bg-teal/10 p-4 text-[14px] text-teal text-center mb-6">
            {message}
          </div>
          <Link
            to="/login"
            className="block w-full rounded-md bg-teal px-4 py-2.5 text-center text-[13px] font-medium text-void-900 hover:bg-teal/85"
          >
            Go to log in
          </Link>
        </>
      )}

      {status === "error" && (
        <>
          <div className="rounded-md bg-crimson/10 p-4 text-[14px] text-crimson text-center mb-6">
            {message}
          </div>
          <Link
            to="/login"
            className="block w-full rounded-md bg-void-800 border border-void-700 px-4 py-2.5 text-center text-[13px] font-medium text-paper hover:bg-void-700"
          >
            Back to log in
          </Link>
        </>
      )}
    </AuthShell>
  );
}
