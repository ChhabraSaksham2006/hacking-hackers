/**
 * sensorsApi.ts
 * =============
 * API client for managing edge sensors, onboarding setup, and API keys.
 */

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
  const res = await fetch('/api/sensors', { credentials: 'include' });
  if (!res.ok) throw new Error('Failed to fetch sensor configuration');
  return res.json();
}

export async function saveSensorSetup(data: {
  monitoredSubnets: string[];
  environmentType: string;
  sensorSetupCompleted?: boolean;
}): Promise<any> {
  const res = await fetch('/api/sensors/setup', {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  if (!res.ok) throw new Error('Failed to save sensor setup');
  return res.json();
}

export async function regenerateSensorKey(): Promise<{ sensorApiKey: string }> {
  const res = await fetch('/api/sensors/key/regenerate', {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
  });
  if (!res.ok) throw new Error('Failed to regenerate sensor API key');
  return res.json();
}
