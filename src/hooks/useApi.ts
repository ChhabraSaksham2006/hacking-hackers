import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiFetch } from "../lib/api";
import type { RiskState } from "../lib/telemetry"; // RiskState is still normal/watch/critical

export interface Alert {
  _id: string;
  alertId: string;
  host: string;
  ip: string;
  stage: string;
  probability: number;
  state: RiskState;
  reason: string;
  detectedAt: string;
  status: "New" | "Acknowledged" | "Investigating" | "Resolved";
  assignedTo?: {
    _id: string;
    name: string;
    initials: string;
    email: string;
  };
  notes?: string;
}

export interface Flow {
  _id: string;
  src: string;
  dst: string;
  proto: string;
  flags: string;
  bytes: number;
  packets: number;
  duration: number;
  iatMean: number;
  iatVar: number;
  iatMax: number;
  ttlVar: number;
  window: number;
  retrans: number;
  score: number;
  timestamp: string;
}

export interface DashboardSummary {
  currentProbability: number;
  activeFlows: number;
  flaggedHosts: number;
  modelConfidence: number;
}

export interface DashboardTimeline {
  series: number[];
  windowStart: string;
  windowEnd: string;
}

export interface DashboardStage {
  stage: string;
  probability: number;
  confidence: number;
}

export interface AuthUser {
  id: string;
  email: string;
  name: string;
  initials: string;
  role: string;
  twoFactorEnabled?: boolean;
  org?: { id: string; name: string };
  permissions: string[];
}

export function useAuthMe() {
  return useQuery({
    queryKey: ["auth", "me"],
    queryFn: () => apiFetch<AuthUser>("/api/auth/me"),
    retry: false, // Don't retry on 401s
    staleTime: 5 * 60 * 1000,
  });
}

export function useLogin() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: { email: string; password: string }) =>
      apiFetch<{ requiresTwoFactor: boolean; challengeId?: string; user?: AuthUser }>("/api/auth/login", {
        method: "POST",
        body: JSON.stringify(data),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["auth", "me"] });
    },
  });
}

export function useRegister() {
  return useMutation({
    mutationFn: (data: { orgName: string; email: string; password: string; name: string }) =>
      apiFetch<{ message: string; user: { id: string; email: string; name: string; role: string } }>("/api/auth/register", {
        method: "POST",
        body: JSON.stringify(data),
      }),
  });
}

export function useVerify2FA() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: { challengeId: string; code: string }) =>
      apiFetch<{ requiresTwoFactor: false; user: AuthUser }>("/api/auth/verify-2fa", {
        method: "POST",
        body: JSON.stringify(data),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["auth", "me"] });
    },
  });
}

export function useLogout() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () =>
      apiFetch("/api/auth/logout", { method: "POST" }),
    onSuccess: () => {
      queryClient.clear();
      window.location.href = "/login";
    },
  });
}

export function useDashboardSummary() {
  return useQuery({
    queryKey: ["dashboard", "summary"],
    queryFn: () => apiFetch<DashboardSummary>("/api/dashboard/summary"),
  });
}

export function useDashboardTimeline() {
  return useQuery({
    queryKey: ["dashboard", "timeline"],
    queryFn: () => apiFetch<DashboardTimeline>("/api/dashboard/timeline"),
  });
}

export function useDashboardStage() {
  return useQuery({
    queryKey: ["dashboard", "stage"],
    queryFn: () => apiFetch<DashboardStage>("/api/dashboard/stage"),
  });
}

export interface AlertsPaginated {
  data: Alert[];
  pagination: { page: number; limit: number; total: number; totalPages: number };
}

export function useAlerts(filters?: { status?: string; state?: string; page?: number; limit?: number }) {
  const query = new URLSearchParams();
  if (filters?.status) query.set("status", filters.status);
  if (filters?.state) query.set("state", filters.state);
  if (filters?.page) query.set("page", filters.page.toString());
  if (filters?.limit) query.set("limit", filters.limit.toString());
  const qs = query.toString();
  return useQuery({
    queryKey: ["alerts", filters],
    queryFn: () => apiFetch<AlertsPaginated>(`/api/alerts${qs ? `?${qs}` : ""}`),
  });
}

export function useAlert(id: string) {
  return useQuery({
    queryKey: ["alerts", id],
    queryFn: () => apiFetch<Alert>(`/api/alerts/${id}`),
    enabled: !!id,
  });
}

export function useUpdateAlert() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ id, ...data }: { id: string; status?: string; assignedTo?: string }) =>
      apiFetch<Alert>(`/api/alerts/${id}`, {
        method: "PATCH",
        body: JSON.stringify(data),
      }),
    onSuccess: (_, variables) => {
      queryClient.invalidateQueries({ queryKey: ["alerts"] });
      queryClient.invalidateQueries({ queryKey: ["alerts", variables.id] });
    },
  });
}

export interface FlowPaginated {
  data: Flow[];
  pagination: { page: number; limit: number; total: number; totalPages: number };
}

export function useFlows(filters: { page: number; limit: number; minScore?: number; flaggedOnly?: boolean; search?: string }) {
  const query = new URLSearchParams();
  query.set("page", filters.page.toString());
  query.set("limit", filters.limit.toString());
  if (filters.minScore !== undefined) query.set("minScore", filters.minScore.toString());
  if (filters.flaggedOnly) query.set("flaggedOnly", "true");
  if (filters.search) query.set("search", filters.search);

  return useQuery({
    queryKey: ["flows", filters],
    queryFn: () => apiFetch<FlowPaginated>(`/api/flows?${query.toString()}`),
  });
}

export function useNetworkGraph() {
  return useQuery({
    queryKey: ["network", "graph"],
    queryFn: () =>
      apiFetch<{
        nodes: Array<{ id: string; size: number; state: RiskState; flows: number }>;
        edges: Array<{ source: string; target: string; bytes: number; score: number }>;
      }>("/api/network/graph"),
  });
}

export function useHostDetails(id: string) {
  return useQuery({
    queryKey: ["network", "hosts", id],
    queryFn: () =>
      apiFetch<{
        id: string;
        state: RiskState;
        riskScore: number;
        activeFlows: number;
        totalBytes: number;
        recentFlows: Array<{ dst: string; bytes: number; score: number }>;
      }>(`/api/network/hosts/${encodeURIComponent(id)}`),
    enabled: !!id,
  });
}

export function useSegments() {
  return useQuery({
    queryKey: ["segments"],
    queryFn: () =>
      apiFetch<
        Array<{
          _id: string;
          name: string;
          hosts: number;
          activeAlerts: number;
          trafficVolume: number;
          state: RiskState;
          lastIncident: string;
        }>
      >("/api/segments"),
  });
}
