/**
 * dashboardApi.ts
 * ===============
 * API client and Server-Sent Events (SSE) streaming subscriber for Flow दृष्टि Dashboard.
 */

import { onPageActivityChange } from '@/lib/pageActivity';
import { apiFetch } from '@/lib/api';

export interface DashboardSummary {
  infiltrationProbability: number;
  infiltrationProbabilityPct: string;
  activeFlows: string;
  flaggedHosts: string;
  modelConfidence: string;
  leadTimeSeconds: number;
  currentStage: string;
  riskLevel: 'normal' | 'watch' | 'critical';
  threshold: number;
}

export interface MitreStage {
  id: string;
  label: string;
  active: boolean;
}

export interface DashboardAlert {
  id: number;
  level: 'normal' | 'watch' | 'critical';
  host: string;
  stage: string;
  ts: string;
  reason: string;
}

export interface DashboardFlow {
  src: string;
  dst: string;
  proto: string;
  flags: string;
  bytes: string;
  prob: number;
}

export interface FullDashboardState {
  isLive?: boolean;
  isDemo?: boolean;
  selectedSensor?: string;
  activeSensorsCount?: number;
  step_index: number;
  actual_window_index: number;
  timestamp: string;
  latest_probability: number;
  summary: DashboardSummary;
  stages: MitreStage[];
  recentAlerts: DashboardAlert[];
  recentFlows: DashboardFlow[];
  timeline: number[];
}

export async function fetchFullDashboardState(sensor?: string): Promise<FullDashboardState> {
  const url = sensor && sensor !== 'all' ? `/api/dashboard?sensor=${encodeURIComponent(sensor)}` : '/api/dashboard';
  return apiFetch<FullDashboardState>(url);
}

export async function fetchDashboardSummary(): Promise<any> {
  return apiFetch<any>('/api/dashboard/summary');
}

export async function fetchDashboardTimeline(): Promise<{ series: number[]; windowStart: string; windowEnd: string }> {
  return apiFetch<{ series: number[]; windowStart: string; windowEnd: string }>('/api/dashboard/timeline');
}

export async function fetchDashboardStages(): Promise<any> {
  return apiFetch<any>('/api/dashboard/stages');
}

export async function stepDashboard(): Promise<any> {
  return apiFetch<any>('/api/dashboard/step', {
    method: 'POST',
  });
}

export async function resetDashboard(): Promise<any> {
  return apiFetch<any>('/api/dashboard/reset', {
    method: 'POST',
  });
}

export async function jumpDashboard(): Promise<any> {
  return apiFetch<any>('/api/dashboard/jump', {
    method: 'POST',
  });
}

/**
 * Subscribes to the live SSE stream (/api/dashboard/stream).
 * Returns an unsubscribe callback function that cleanly terminates the EventSource.
 */
export function subscribeDashboardStream(
  onUpdate: (state: FullDashboardState) => void,
  onError?: (err: Event) => void,
  sensor?: string,
): () => void {
  let eventSource: EventSource | null = null;
  let isClosed = false;
  const baseUrl = import.meta.env.DEV ? 'http://localhost:5000' : (import.meta.env['VITE_API_URL'] || 'https://flow-drishti-server.onrender.com').trim().replace(/\/$/, '');
  const url = baseUrl + (sensor && sensor !== 'all' ? `/api/dashboard/stream?sensor=${encodeURIComponent(sensor)}` : '/api/dashboard/stream');

  const open = () => {
    if (isClosed || eventSource) return;
    try {
      eventSource = new EventSource(url, { withCredentials: true });

      eventSource.onmessage = (event) => {
        if (isClosed || !event.data) return;
        try {
          const payload = JSON.parse(event.data) as FullDashboardState;
          onUpdate(payload);
        } catch (err) {
          console.error('Failed to parse SSE payload:', err);
        }
      };

      eventSource.onerror = (err) => {
        if (onError && !isClosed) {
          onError(err);
        }
      };
    } catch (e) {
      console.error('Error establishing SSE stream:', e);
    }
  };

  const close = () => {
    if (eventSource) {
      eventSource.close();
      eventSource = null;
    }
  };

  open();

  // Only keep the stream open while the tab is actively viewed — an open stream
  // keeps the backend replay ticker running for this org.
  const stopActivityWatch = onPageActivityChange(open, close);

  return () => {
    isClosed = true;
    stopActivityWatch();
    close();
  };
}
