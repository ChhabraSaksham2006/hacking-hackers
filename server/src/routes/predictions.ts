import { Router } from 'express';
import { authenticate } from '../middleware/auth.js';
import { requirePermission } from '../middleware/rbac.js';
import { Prediction } from '../models/Prediction.js';
import { logAuditEvent } from '../services/auditService.js';
import { z } from 'zod';
import { validate } from '../middleware/validate.js';
import crypto from 'crypto';

const router = Router();

router.use(authenticate);

// ── GET /api/predictions/latest ─────────────────────────

router.get(
  '/latest',
  requirePermission('alerts.read'),
  async (req, res, next) => {
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
  },
);

// ── GET /api/predictions/:id/explain ────────────────────

const predictionIdSchema = z.object({
  id: z.string().regex(/^[0-9a-fA-F]{24}$/, 'Invalid prediction ID'),
});

router.get(
  '/:id/explain',
  requirePermission('alerts.read'),
  validate({ params: predictionIdSchema }),
  async (req, res, next) => {
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
  },
);

// ── POST /api/predictions/run ───────────────────────────

router.post(
  '/run',
  requirePermission('inference.run'),
  async (req, res, next) => {
    try {
      // In production this dispatches to the ML worker via BullMQ.
      const mockJobId = crypto.randomUUID();
      // await inferenceQueue.add('run-inference', { orgId: req.user!.orgId }, { jobId: mockJobId });

      await logAuditEvent('INFERENCE_RUN', mockJobId, req, { trigger: 'manual' });

      res.status(202).json({
        message: 'Inference run queued',
        status: 'queued',
        jobId: mockJobId,
      });
    } catch (err) {
      next(err);
    }
  },
);

export default router;
