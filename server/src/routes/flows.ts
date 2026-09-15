import { Router } from 'express';
import { z } from 'zod';
import { verifyAccessToken } from '../utils/jwt.js';
import { validate } from '../middleware/validate.js';
import { paginationSchema } from '../utils/pagination.js';
import { listFlows, getFlowById } from '../controllers/flowsController.js';

const router = Router();

// Optional authentication middleware for flows & packet explorer access
router.use((req, _res, next) => {
  const token = req.cookies?.access_token as string | undefined;
  if (token) {
    try {
      req.user = verifyAccessToken(token);
    } catch {
      // ignore invalid token for explorer viewer
    }
  }
  next();
});

// ── GET /api/flows ──────────────────────────────────────
const listFlowsSchema = paginationSchema.extend({
  minScore: z.coerce.number().min(0).max(1).optional(),
  flaggedOnly: z.enum(['true', 'false']).optional().transform((v) => v === 'true'),
  search: z.string().optional(),
  windowIndex: z.coerce.number().optional(),
  scrub: z.coerce.number().optional(),
  live: z.string().optional(),
  proto: z.string().optional(),
  service: z.string().optional(),
});

router.get(
  '/',
  validate({ query: listFlowsSchema }),
  listFlows,
);

// ── GET /api/flows/:id ──────────────────────────────────
const flowIdSchema = z.object({
  id: z.string().min(1, 'Invalid flow ID'),
});

router.get(
  '/:id',
  validate({ params: flowIdSchema }),
  getFlowById,
);

export default router;
