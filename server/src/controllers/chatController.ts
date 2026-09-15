/**
 * chatController.ts
 * ==================
 * Express controller for Aegis Vantage AI Telemetry Copilot RAG queries.
 */

import type { Request, Response, NextFunction } from 'express';
import { answerTelemetryQuery, getSuggestedQueries } from '../services/ragService.js';
import { dashboardStore } from '../models/dashboardModel.js';

export async function queryTelemetry(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const { query, windowIndex, contextHint } = req.body;

    if (!query || typeof query !== 'string' || query.trim().length === 0) {
      res.status(400).json({ error: 'Query is required and must be a non-empty string.' });
      return;
    }

    const parsedWindow = typeof windowIndex === 'number' ? windowIndex : undefined;
    const result = await answerTelemetryQuery(query.trim(), {
      windowIndex: parsedWindow,
      contextHint: typeof contextHint === 'string' ? contextHint : undefined,
    });

    res.json(result);
  } catch (err) {
    next(err);
  }
}

export async function getSuggestedPrompts(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const rawWindow = req.query.windowIndex;
    const windowIndex = rawWindow !== undefined && rawWindow !== '' ? Number(rawWindow) : undefined;

    const suggestedQueries = getSuggestedQueries(windowIndex);
    const liveState = dashboardStore.getState();

    res.json({
      suggestedQueries,
      liveState: {
        windowIndex: liveState.actual_window_index,
        timestamp: liveState.timestamp,
        stage: liveState.summary.currentStage,
        probability: liveState.summary.infiltrationProbability,
        riskLevel: liveState.summary.riskLevel,
        leadTimeSeconds: liveState.summary.leadTimeSeconds,
      },
    });
  } catch (err) {
    next(err);
  }
}
