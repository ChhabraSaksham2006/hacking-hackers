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

export interface PacketFrame {
  frameNumber: number;
  offsetSeconds: number;
  timeFormatted: string;
  source: string;
  destination: string;
  direction: 'inbound' | 'outbound';
  protocol: string;
  flags?: string;
  length: number;
  ttl: number;
  winSize?: number;
  seq?: number;
  ack?: number;
  info: string;
  layers: string[];
  hexDump: string[];
  payloadAscii?: string;
}

export interface Flow {
  _id: string;
  src: string;
  dst: string;
  proto: string;
  service?: string;
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
  riskState?: 'normal' | 'watch' | 'critical';
  mitreTactic?: string;
  mitreTechnique?: string;
  timestamp: string;
  packetSequence?: PacketFrame[];
}

export interface DashboardSummary {
  currentProbability: number;
  activeFlows: number;
  flaggedHosts: number;
  modelConfidence: number;
  replay?: {
    dataset: string;
    targetEpisode: string;
    sourceFile?: string;
    currentWindow: number;
    startIndex?: number;
    attackOnsetInterval?: number;
    endIndex?: number;
    phase: string;
    stage: string;
    probability: number;
    confidence: number;
    riskState: string;
    isAttack: number;
    leadTimeSeconds: number;
  };
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
  emailVerified?: boolean;
  alertNotificationsEnabled?: boolean;
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

export function useVerifyEmail() {
  return useMutation({
    mutationFn: (token: string) =>
      apiFetch<{ message: string; email: string }>(`/api/auth/verify-email?token=${encodeURIComponent(token)}`),
  });
}

export function useResendVerification() {
  return useMutation({
    mutationFn: (data: { email: string }) =>
      apiFetch<{ message: string }>("/api/auth/resend-verification", {
        method: "POST",
        body: JSON.stringify(data),
      }),
  });
}

export function useForgotPassword() {
  return useMutation({
    mutationFn: (data: { email: string }) =>
      apiFetch<{ message: string }>("/api/auth/forgot-password", {
        method: "POST",
        body: JSON.stringify(data),
      }),
  });
}

export function useResetPassword() {
  return useMutation({
    mutationFn: (data: { token: string; password: string }) =>
      apiFetch<{ message: string }>("/api/auth/reset-password", {
        method: "POST",
        body: JSON.stringify(data),
      }),
  });
}

export function useSend2FAEmail() {
  return useMutation({
    mutationFn: (data: { challengeId: string }) =>
      apiFetch<{ message: string }>("/api/auth/send-2fa-email", {
        method: "POST",
        body: JSON.stringify(data),
      }),
  });
}

export function useUpdateAlertNotifications() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: { enabled: boolean }) =>
      apiFetch<{ alertNotificationsEnabled: boolean }>("/api/auth/alert-notifications", {
        method: "PATCH",
        body: JSON.stringify(data),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["auth", "me"] });
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
  isLive?: boolean | undefined;
  activeLiveWindowIndex?: number | undefined;
  windowIndex?: number | undefined;
  timestampStart?: string | undefined;
  phase?: string | undefined;
  stage?: string | undefined;
  probability?: number | undefined;
  data: Flow[];
  pagination: { page: number; limit: number; total: number; totalPages: number };
  summary?: {
    totalFlows: number;
    threatFlows: number;
    totalBytes: number;
    totalPackets: number;
    topService: string;
  } | undefined;
}

export interface UseFlowsFilters {
  page: number;
  limit: number;
  minScore?: number | undefined;
  flaggedOnly?: boolean | undefined;
  search?: string | undefined;
  windowIndex?: number | undefined;
  scrub?: number | undefined;
  live?: boolean | undefined;
  proto?: string | undefined;
  service?: string | undefined;
}

export function useFlows(filters: UseFlowsFilters) {
  const isLive = filters.live ?? (filters.windowIndex === undefined && filters.scrub === undefined);
  const query = new URLSearchParams();
  query.set("page", filters.page.toString());
  query.set("limit", filters.limit.toString());
  if (filters.minScore !== undefined) query.set("minScore", filters.minScore.toString());
  if (filters.flaggedOnly) query.set("flaggedOnly", "true");
  if (filters.search) query.set("search", filters.search);
  if (isLive) query.set("live", "true");
  else if (filters.windowIndex !== undefined) query.set("windowIndex", filters.windowIndex.toString());
  else if (filters.scrub !== undefined) query.set("scrub", filters.scrub.toString());
  if (filters.proto) query.set("proto", filters.proto);
  if (filters.service) query.set("service", filters.service);

  return useQuery({
    queryKey: ["flows", filters, isLive],
    queryFn: () => apiFetch<FlowPaginated>(`/api/flows?${query.toString()}`),
    refetchInterval: isLive ? 2500 : false,
  });
}

export interface NetworkGraphResponse {
  windowIndex: number;
  timestamp: string;
  phase: string;
  probability: number;
  scrub: number;
  nodes: Array<{
    id: string;
    hostname?: string;
    segment?: string;
    role?: string;
    x: number;
    y: number;
    size: number;
    state: RiskState;
    flows: number;
    bytes: number;
    firstSeen?: string;
  }>;
  edges: Array<{
    source: string;
    target: string;
    proto?: string;
    port?: number;
    bytes: number;
    score: number;
  }>;
}

export function useNetworkGraph(options?: { scrub?: number | undefined; live?: boolean | undefined } | number) {
  const scrub = typeof options === 'number' ? options : options?.scrub;
  const isLive = typeof options === 'object' && options?.live !== undefined ? options.live : (scrub === undefined || scrub === 100);

  return useQuery({
    queryKey: ["network", "graph", scrub, isLive],
    queryFn: () => {
      const params = new URLSearchParams();
      if (isLive) params.set("live", "true");
      else if (scrub !== undefined) params.set("scrub", scrub.toString());
      const qs = params.toString();
      const url = qs ? `/api/network/graph?${qs}` : "/api/network/graph";
      return apiFetch<NetworkGraphResponse>(url);
    },
    refetchInterval: isLive ? 2500 : false,
  });
}

export function useHostDetails(id: string, scrub?: number | undefined) {
  return useQuery({
    queryKey: ["network", "hosts", id, scrub],
    queryFn: () => {
      const qs = scrub !== undefined ? `?scrub=${scrub}` : "";
      return apiFetch<{
        id: string;
        state: RiskState;
        riskScore: number;
        activeFlows: number;
        totalBytes: number;
        hostname?: string;
        role?: string;
        segment?: string;
        firstSeen?: string;
        recentFlows: Array<{ src?: string; dst: string; proto?: string; bytes: number | string; score: number }>;
      }>(`/api/network/hosts/${encodeURIComponent(id)}${qs}`);
    },
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

export function useRunInference() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (params?: { action?: string; windowIndex?: number; step?: number }) =>
      apiFetch<{ message: string; replay: any; prediction: any }>("/api/predictions/run", {
        method: "POST",
        body: JSON.stringify(params || {}),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["dashboard"] });
      queryClient.invalidateQueries({ queryKey: ["alerts"] });
      queryClient.invalidateQueries({ queryKey: ["flows"] });
      queryClient.invalidateQueries({ queryKey: ["predictions"] });
      queryClient.invalidateQueries({ queryKey: ["explainability"] });
    },
  });
}

export interface ExplainabilityResponse {
  windowIndex: number;
  timestampStart: string;
  timestampEnd: string;
  phase: string;
  stage: string;
  probability: number;
  confidence: number;
  riskState: RiskState;
  isAttack: number;
  leadTimeSeconds: number;
  mitre: {
    techniqueId: string | null;
    techniqueName: string | null;
    tactic: string;
  };
  summary: string;
  reason: string;
  featureContributions: Array<{
    feature: string;
    label: string;
    category: string;
    description: string;
    value: string;
    weight: number;
    direction: "elevates_threat" | "mitigates_threat";
  }>;
  featureCategories: Array<{
    id: string;
    name: string;
    description: string;
    features: Array<{
      key: string;
      label: string;
      value: number;
      formattedValue: string;
      unit: string;
      isAnomaly: boolean;
      anomalyDirection?: "elevated" | "depressed";
      attributionWeight?: number;
    }>;
  }>;
  rawFeaturesCount: number;
  modelEnsemble: {
    architecture: string;
    sparseRssmWeight: number;
    tfcnetWeight: number;
    latentDimensions: number;
    timeFrequencyHeads: number;
    f1Threshold: number;
    dataset: string;
    targetEpisode: string;
  };
  timelineBounds: {
    min: number;
    max: number;
    current: number;
    attackOnset: number;
  };
  presets: Array<{
    label: string;
    windowIndex: number;
    scrub: number;
    stage: string;
  }>;
}

export function useExplainability(params?: { windowIndex?: number | undefined; scrub?: number | undefined; live?: boolean | undefined }) {
  const isLive = params?.live ?? (params?.windowIndex === undefined && params?.scrub === undefined);
  const qs = new URLSearchParams();
  if (isLive) qs.set("live", "true");
  else if (params?.windowIndex !== undefined) qs.set("windowIndex", params.windowIndex.toString());
  else if (params?.scrub !== undefined) qs.set("scrub", params.scrub.toString());
  const queryStr = qs.toString();

  return useQuery({
    queryKey: ["explainability", params?.windowIndex, params?.scrub, isLive],
    queryFn: () => apiFetch<ExplainabilityResponse>(`/api/explainability${queryStr ? `?${queryStr}` : ""}`),
    refetchInterval: isLive ? 2500 : false,
  });
}

// ── Notifications ──────────────────────────────────────────

export interface AppNotification {
  _id: string;
  orgId: string;
  userId?: string;
  type: string;
  title: string;
  message: string;
  severity: "info" | "warning" | "critical";
  alertId?: string;
  isRead: boolean;
  createdAt: string;
  updatedAt: string;
}

export function useNotifications() {
  return useQuery({
    queryKey: ["notifications"],
    queryFn: () => apiFetch<AppNotification[]>("/api/notifications"),
  });
}

export function useMarkNotificationRead() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: string) =>
      apiFetch(`/api/notifications/${id}/read`, { method: "PATCH" }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["notifications"] });
    },
  });
}

export function useMarkAllNotificationsRead() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () =>
      apiFetch("/api/notifications/mark-all-read", { method: "POST" }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["notifications"] });
    },
  });
}

// ── Telemetry AI Copilot (RAG) ─────────────────────────────

export interface ChatQueryRequest {
  query: string;
  windowIndex?: number | undefined;
  live?: boolean | undefined;
  contextHint?: string | undefined;
}

export interface ChatQueryResponse {
  answer: string;
  references: string[];
  suggestedQueries: string[];
  context: {
    windowIndex: number;
    timestamp: string;
    stage: string;
    probability: number;
    riskLevel: string;
    confidence: number;
    leadTimeSeconds: number;
    provider: string;
  };
}

export interface SuggestedQueriesResponse {
  suggestedQueries: string[];
  liveState: {
    windowIndex: number;
    timestamp: string;
    stage: string;
    probability: number;
    riskLevel: string;
    leadTimeSeconds: number;
  };
}

export function useChatQuery() {
  return useMutation({
    mutationFn: (data: ChatQueryRequest) =>
      apiFetch<ChatQueryResponse>("/api/chat/query", {
        method: "POST",
        body: JSON.stringify(data),
      }),
  });
}

export function useSuggestedQueries(windowIndex?: number | undefined) {
  const qs = windowIndex !== undefined ? `?windowIndex=${windowIndex}` : "";
  return useQuery({
    queryKey: ["chat-suggested", windowIndex],
    queryFn: () => apiFetch<SuggestedQueriesResponse>(`/api/chat/suggested${qs}`),
    refetchInterval: 2500,
    staleTime: 2000,
  });
}

