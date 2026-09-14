import { useState } from "react";
import { createFileRoute, Link, useRouter } from "@tanstack/react-router";
import { AuthShell, Field } from "@/components/app/AuthShell";
import { pageHead } from "@/lib/head";
import { useRegister } from "@/hooks/useApi";

export const Route = createFileRoute("/signup")({
  head: pageHead(
    "Sign up — Aegis Vantage",
    "Create an Aegis Vantage workspace for your security operations team.",
  ),
  component: SignupPage,
});

function SignupPage() {
  const [orgName, setOrgName] = useState("");
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);

  const register = useRegister();
  const router = useRouter();

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    register.mutate(
      { orgName, name, email, password },
      {
        onSuccess: () => {
          setSuccess(true);
        },
        onError: (err) => {
          setError(err.message || "Failed to register");
        },
      }
    );
  };

  if (success) {
    return (
      <AuthShell title="Check your email" note="Your workspace has been requested.">
        <div className="rounded-md bg-teal/10 p-4 text-[14px] text-teal">
          Registration successful. Check your email to verify your account before logging in.
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
      title="Sign up"
      note="Enterprise workspaces are provisioned after your domain is verified."
      footer={
        <span>
          Already provisioned?{" "}
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
          label="Organisation name"
          placeholder="Northwind Energy"
          value={orgName}
          onChange={(e) => setOrgName(e.target.value)}
          required
        />
        <Field
          label="Your name"
          placeholder="Jane Doe"
          value={name}
          onChange={(e) => setName(e.target.value)}
          required
        />
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
          placeholder="••••••••••"
          hint="12 characters minimum, checked against known breach corpora."
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
        />
        <button
          type="submit"
          disabled={register.isPending}
          className="mt-2 block w-full rounded-md bg-teal px-4 py-2.5 text-center text-[13px] font-medium text-void-900 hover:bg-teal/85 disabled:opacity-50"
        >
          {register.isPending ? "Requesting access..." : "Request access"}
        </button>
      </form>
    </AuthShell>
  );
}
