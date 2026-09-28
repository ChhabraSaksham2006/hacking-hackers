import type { Request, Response } from 'express';
import { dashboardStore } from '../models/dashboardModel.js';

export function getSummary(req: Request, res: Response): void {
  const orgId = req.user?.orgId?.toString();
  res.json(dashboardStore.getSummary(orgId));
}

export function getTimeline(req: Request, res: Response): void {
  const orgId = req.user?.orgId?.toString();
  res.json(dashboardStore.getTimeline(orgId));
}

export function getStages(req: Request, res: Response): void {
  const orgId = req.user?.orgId?.toString();
  res.json(dashboardStore.getStages(orgId));
}

export function getAlerts(req: Request, res: Response): void {
  const orgId = req.user?.orgId?.toString();
  res.json(dashboardStore.getAlerts(orgId));
}

export function getFlows(req: Request, res: Response): void {
  const orgId = req.user?.orgId?.toString();
  res.json(dashboardStore.getFlows(orgId));
}

export function getFullState(req: Request, res: Response): void {
  const orgId = req.user?.orgId?.toString();
  const sensor = req.query.sensor as string | undefined;
  res.json(dashboardStore.getState(orgId, sensor));
}

import { applyWindowToDatabase } from '../services/replayService.js';
import { logAuditEvent } from '../services/auditService.js';

export async function stepForward(req: Request, res: Response): Promise<void> {
  const state = await dashboardStore.stepForward();
  try {
    await applyWindowToDatabase(req.user!.orgId.toString(), state.actual_window_index);
  } catch (err) {
    console.error('[DashboardController] Failed to sync step to database:', err);
  }
  await logAuditEvent(
    'INFERENCE_RUN',
    `Replay Step: Window W#${state.actual_window_index} (${state.summary?.currentStage || 'Lateral Movement'})`,
    req,
    {
      action: 'step',
      windowIndex: state.actual_window_index,
      currentStage: state.summary?.currentStage,
      probability: state.summary?.infiltrationProbability,
      riskLevel: state.summary?.riskLevel,
      leadTimeSeconds: state.summary?.leadTimeSeconds,
    },
  );
  res.json({ message: 'Stepped forward', state });
}

export async function resetBaseline(req: Request, res: Response): Promise<void> {
  const state = await dashboardStore.reset(0);
  try {
    await applyWindowToDatabase(req.user!.orgId.toString(), state.actual_window_index);
  } catch (err) {
    console.error('[DashboardController] Failed to sync reset to database:', err);
  }
  await logAuditEvent(
    'SIMULATION_RUN',
    'Replay Baseline Reset (Window W#0 — Benign Baseline)',
    req,
    {
      action: 'reset',
      windowIndex: 0,
      currentStage: 'Normal',
      probability: state.summary?.infiltrationProbability ?? 0.08,
    },
  );
  res.json({ message: 'Reset to benign baseline', state });
}

export async function jumpAttack(req: Request, res: Response): Promise<void> {
  const state = await dashboardStore.jumpAttack();
  try {
    await applyWindowToDatabase(req.user!.orgId.toString(), state.actual_window_index);
  } catch (err) {
    console.error('[DashboardController] Failed to sync jump to database:', err);
  }
  await logAuditEvent(
    'SIMULATION_RUN',
    `Replay Infiltration Jump: Window W#${state.actual_window_index} (Onset Lead-Time 20.0s)`,
    req,
    {
      action: 'jump_attack',
      windowIndex: state.actual_window_index,
      currentStage: state.summary?.currentStage || 'Lateral Movement',
      probability: state.summary?.infiltrationProbability ?? 0.91,
    },
  );
  res.json({ message: 'Jumped to infiltration onset', state });
}

export function streamDashboard(req: Request, res: Response): void {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');

  const orgId = req.user?.orgId?.toString();
  const sensor = req.query.sensor as string | undefined;

  // Send immediate initial state
  res.write(`data: ${JSON.stringify(dashboardStore.getState(orgId, sensor))}\n\n`);

  const onTick = (state: unknown) => {
    if (res.writableEnded || !res.writable) {
      if (orgId) dashboardStore.off(`tick:${orgId}`, onTick);
      dashboardStore.off('tick', onTick);
      return;
    }
    res.write(`data: ${JSON.stringify(state)}\n\n`);
  };

  if (orgId) {
    dashboardStore.on(`tick:${orgId}`, onTick);
  }
  dashboardStore.on('tick', onTick);

  // Heartbeat to keep connection active across proxies
  const heartbeatTimer = setInterval(() => {
    if (res.writableEnded || !res.writable) {
      clearInterval(heartbeatTimer);
      if (orgId) dashboardStore.off(`tick:${orgId}`, onTick);
      dashboardStore.off('tick', onTick);
      return;
    }
    res.write(': keepalive\n\n');
  }, 15000);

  req.on('close', () => {
    clearInterval(heartbeatTimer);
    if (orgId) dashboardStore.off(`tick:${orgId}`, onTick);
    dashboardStore.off('tick', onTick);
  });
}
