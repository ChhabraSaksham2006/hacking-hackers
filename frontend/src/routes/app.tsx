import { createFileRoute, Outlet, Navigate } from "@tanstack/react-router";
import { AppShell } from "@/components/app/AppShell";
import { useAuthMe } from "@/hooks/useApi";

export const Route = createFileRoute("/app")({
  component: AppLayout,
});

function AppLayout() {
  const { data: user, isLoading, isError } = useAuthMe();

  if (isLoading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-void-900">
        <div className="size-8 animate-spin rounded-full border-2 border-teal border-t-transparent" />
      </div>
    );
  }

  if (isError || !user) {
    return <Navigate to="/login" replace />;
  }

  return (
    <AppShell>
      <Outlet />
    </AppShell>
  );
}
