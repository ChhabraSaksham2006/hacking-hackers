import { Router } from 'express';
import { z } from 'zod';
import { authenticate } from '../middleware/auth.js';
import { requirePermission } from '../middleware/rbac.js';
import { validate } from '../middleware/validate.js';
import {
  getLatestPrediction,
  explainPrediction,
  runInference,
} from '../controllers/predictionsController.js';

const router = Router();

router.use(authenticate);

// ── GET /api/predictions/latest ─────────────────────────
router.get(
  '/latest',
  requirePermission('alerts.read'),
  getLatestPrediction,
);

// ── GET /api/predictions/:id/explain ────────────────────
const predictionIdSchema = z.object({
  id: z.string().regex(/^[0-9a-fA-F]{24}$/, 'Invalid prediction ID'),
});

router.get(
  '/:id/explain',
  requirePermission('alerts.read'),
  validate({ params: predictionIdSchema }),
  explainPrediction,
);

// ── POST /api/predictions/run ───────────────────────────
router.post(
  '/run',
  requirePermission('inference.run'),
  runInference,
);

export default router;

