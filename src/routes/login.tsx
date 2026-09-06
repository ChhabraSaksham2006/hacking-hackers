import { createFileRoute, Link } from "@tanstack/react-router";
import { AuthShell, Field } from "@/components/app/AuthShell";
import { pageHead } from "@/lib/head";

export const Route = createFileRoute("/login")({
  head: pageHead(
    "Log in — Aegis Vantage",
    "Sign in to the Aegis Vantage predictive cyber-defence console.",
  ),
  component: LoginPage,
});

function LoginPage() {
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
      <form
        className="space-y-4"
        onSubmit={(e) => e.preventDefault()}
      >
        <Field label="Work email" type="email" placeholder="analyst@company.com" />
        <Field label="Password" type="password" placeholder="••••••••••" />
        <div className="flex items-center justify-between pt-1">
          <Link to="/two-factor" className="text-[13px] text-fog hover:text-paper">
            Forgot password
          </Link>
        </div>
        <Link
          to="/two-factor"
          className="mt-2 block rounded-md bg-teal px-4 py-2.5 text-center text-[13px] font-medium text-void-900 hover:bg-teal/85"
        >
          Continue to verification
        </Link>
      </form>
    </AuthShell>
  );
}
