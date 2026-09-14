import { Router } from 'express';
import { z } from 'zod';
import { authenticate } from '../middleware/auth.js';
import { requirePermission } from '../middleware/rbac.js';
import { validate } from '../middleware/validate.js';
import { paginationSchema } from '../utils/pagination.js';
import { listFlows, getFlowById } from '../controllers/flowsController.js';

const router = Router();

router.use(authenticate, requirePermission('alerts.read'));

// ── GET /api/flows ──────────────────────────────────────
const listFlowsSchema = paginationSchema.extend({
  minScore: z.coerce.number().min(0).max(1).optional(),
  flaggedOnly: z.enum(['true', 'false']).optional().transform((v) => v === 'true'),
  search: z.string().optional(),
});

router.get(
  '/',
  validate({ query: listFlowsSchema }),
  listFlows,
);

// ── GET /api/flows/:id ──────────────────────────────────
const flowIdSchema = z.object({
  id: z.string().regex(/^[0-9a-fA-F]{24}$/, 'Invalid flow ID'),
});

router.get(
  '/:id',
  validate({ params: flowIdSchema }),
  getFlowById,
);

export default router;

