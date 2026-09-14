import type { Request, Response, NextFunction } from 'express';
import crypto from 'crypto';
import { Prediction } from '../models/Prediction.js';
import { logAuditEvent } from '../services/auditService.js';
import {
  stepReplay,
  resetReplay,
  jumpToAttack,
  applyWindowToDatabase,
} from '../services/replayService.js';

// ── GET /api/predictions/latest ─────────────────────────
export async function getLatestPrediction(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const prediction = await Prediction.findOne({ orgId: req.user!.orgId })
      .sort({ windowEnd: -1 })
      .lean();

    if (!prediction) {
      res.status(404).json({ error: 'No predictions found' });
      return;
    }
    res.json(prediction);
  } catch (err) {
    next(err);
  }
}

// ── GET /api/predictions/:id/explain ────────────────────
export async function explainPrediction(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const prediction = await Prediction.findOne({
      _id: req.params.id,
      orgId: req.user!.orgId,
    }).lean();

    if (!prediction) {
      res.status(404).json({ error: 'Prediction not found' });
      return;
    }

    res.json({
      windowStart: prediction.windowStart,
      windowEnd: prediction.windowEnd,
      probability: prediction.probability,
      stage: prediction.stage,
      confidence: prediction.confidence,
      featureContributions: prediction.featureContributions,
      summary: prediction.summary,
      modelVersion: prediction.modelVersion,
    });
  } catch (err) {
    next(err);
  }
}

// ── POST /api/predictions/run ───────────────────────────
export async function runInference(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const { action, windowIndex, step = 1 } = req.body || {};
    const orgId = req.user!.orgId.toString();

    let result;
    if (action === 'reset') {
      result = await resetReplay(orgId);
    } else if (action === 'jump_attack') {
      result = await jumpToAttack(orgId);
    } else if (typeof windowIndex === 'number') {
      result = await applyWindowToDatabase(orgId, windowIndex);
    } else {
      result = await stepReplay(orgId, Number(step) || 1);
    }

    const jobId = crypto.randomUUID();
    await logAuditEvent('INFERENCE_RUN', jobId, req, {
      trigger: 'manual',
      windowIndex: result.window.windowIndex,
      phase: result.window.phase,
      probability: result.window.probability,
    });

    res.status(200).json({
      message: 'Inference executed successfully',
      status: 'completed',
      jobId,
      replay: result.replayStatus,
      prediction: result.prediction,
    });
  } catch (err) {
    next(err);
  }
}
