import { createFileRoute, Link } from "@tanstack/react-router";
import { AuthShell, Field } from "@/components/app/AuthShell";
import { pageHead } from "@/lib/head";

export const Route = createFileRoute("/signup")({
  head: pageHead(
    "Sign up — Aegis Vantage",
    "Create an Aegis Vantage workspace for your security operations team.",
  ),
  component: SignupPage,
});

function SignupPage() {
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
      <form className="space-y-4" onSubmit={(e) => e.preventDefault()}>
        <Field label="Organisation name" placeholder="Northwind Energy" />
        <Field label="Work email" type="email" placeholder="analyst@company.com" />
        <Field
          label="Password"
          type="password"
          placeholder="••••••••••"
          hint="12 characters minimum, checked against known breach corpora."
        />
        <label className="block">
          <span className="text-[13px] font-medium">Requested role</span>
          <select className="mt-1.5 w-full rounded-md border border-fog-deep bg-void-700 px-3 py-2.5 text-[15px] outline-none focus:border-teal">
            <option>Analyst</option>
            <option>SOC Lead</option>
            <option>Admin</option>
          </select>
        </label>
        <Link
          to="/two-factor"
          className="mt-2 block rounded-md bg-teal px-4 py-2.5 text-center text-[13px] font-medium text-void-900 hover:bg-teal/85"
        >
          Request access
        </Link>
      </form>
    </AuthShell>
  );
}
