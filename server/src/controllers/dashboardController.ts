import type { Request, Response } from 'express';
import { dashboardStore } from '../models/dashboardModel.js';

export function getSummary(_req: Request, res: Response): void {
  res.json(dashboardStore.getSummary());
}

export function getTimeline(_req: Request, res: Response): void {
  res.json(dashboardStore.getTimeline());
}

export function getStages(_req: Request, res: Response): void {
  res.json(dashboardStore.getStages());
}

export function getAlerts(_req: Request, res: Response): void {
  res.json(dashboardStore.getAlerts());
}

export function getFlows(_req: Request, res: Response): void {
  res.json(dashboardStore.getFlows());
}

export function getFullState(_req: Request, res: Response): void {
  res.json(dashboardStore.getState());
}

export async function stepForward(_req: Request, res: Response): Promise<void> {
  const state = await dashboardStore.stepForward();
  res.json({ message: 'Stepped forward', state });
}

export async function resetBaseline(_req: Request, res: Response): Promise<void> {
  const state = await dashboardStore.reset(0);
  res.json({ message: 'Reset to benign baseline', state });
}

export async function jumpAttack(_req: Request, res: Response): Promise<void> {
  const state = await dashboardStore.jumpAttack();
  res.json({ message: 'Jumped to infiltration onset', state });
}

export function streamDashboard(req: Request, res: Response): void {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');

  // Send immediate initial state
  res.write(`data: ${JSON.stringify(dashboardStore.getState())}\n\n`);

  const onTick = (state: unknown) => {
    if (res.writableEnded || !res.writable) {
      dashboardStore.off('tick', onTick);
      return;
    }
    res.write(`data: ${JSON.stringify(state)}\n\n`);
  };

  dashboardStore.on('tick', onTick);

  // Heartbeat to keep connection active across proxies
  const heartbeatTimer = setInterval(() => {
    if (res.writableEnded || !res.writable) {
      clearInterval(heartbeatTimer);
      dashboardStore.off('tick', onTick);
      return;
    }
    res.write(': keepalive\n\n');
  }, 15000);

  req.on('close', () => {
    clearInterval(heartbeatTimer);
    dashboardStore.off('tick', onTick);
  });
}
