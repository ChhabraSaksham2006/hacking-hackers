/**
 * sensorsApi.ts
 * =============
 * API client for managing edge sensors, onboarding setup, and API keys.
 */

import { apiFetch } from '@/lib/api';

export interface ActiveSensorInfo {
  sensorId: string;
  window_idx: number;
  timestamp: string;
  probability: number;
  stage: string;
  risk_level: string;
  confidence: string;
  activeFlows: number;
  bytes: number;
  packets: number;
  receivedAt: number;
}

export interface SensorsConfigResponse {
  sensorApiKey: string;
  sensorSetupCompleted: boolean;
  monitoredSubnets: string[];
  environmentType: string;
  activeSensors: ActiveSensorInfo[];
  activeSensorsCount: number;
  isLive: boolean;
  upstreamUrl: string;
  exampleCommand: string;
  kafkaActive?: boolean;
}

export async function fetchSensorsConfig(): Promise<SensorsConfigResponse> {
  return apiFetch<SensorsConfigResponse>('/api/sensors');
}

export async function saveSensorSetup(data: {
  monitoredSubnets: string[];
  environmentType: string;
  sensorSetupCompleted?: boolean;
}): Promise<any> {
  return apiFetch<any>('/api/sensors/setup', {
    method: 'POST',
    body: JSON.stringify(data),
  });
}

export async function regenerateSensorKey(): Promise<{ sensorApiKey: string }> {
  return apiFetch<{ sensorApiKey: string }>('/api/sensors/key/regenerate', {
    method: 'POST',
  });
}
