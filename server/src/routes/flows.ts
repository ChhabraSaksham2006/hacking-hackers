import { Router } from 'express';
import { z } from 'zod';
import { authenticate } from '../middleware/auth.js';
import { requirePermission } from '../middleware/rbac.js';
import { validate } from '../middleware/validate.js';
import { Flow } from '../models/Flow.js';
import { Settings } from '../models/Settings.js';
import { paginationSchema, paginateQuery, paginatedResponse } from '../utils/pagination.js';

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
  async (req, res, next) => {
    try {
      const { page, limit, minScore, flaggedOnly, search } = req.query as unknown as z.infer<typeof listFlowsSchema>;
      const filter: Record<string, unknown> = { orgId: req.user!.orgId };

      if (minScore !== undefined) {
        filter.score = { $gte: minScore };
      }
      if (flaggedOnly) {
        const settings = await Settings.findOne({ orgId: req.user!.orgId }).lean();
        const threshold = settings?.modelConfig?.alertThreshold ?? 0.65;
        filter.score = { ...(filter.score as object || {}), $gte: threshold };
      }
      if (search) {
        filter.$or = [
          { src: { $regex: search, $options: 'i' } },
          { dst: { $regex: search, $options: 'i' } },
          { proto: { $regex: search, $options: 'i' } },
        ];
      }

      const { skip } = paginateQuery({ page, limit });
      const [flows, total] = await Promise.all([
        Flow.find(filter).sort({ score: -1 }).skip(skip).limit(limit).lean(),
        Flow.countDocuments(filter),
      ]);

      res.json(paginatedResponse(flows, total, { page, limit }));
    } catch (err) {
      next(err);
    }
  },
);

// ── GET /api/flows/:id ──────────────────────────────────

const flowIdSchema = z.object({
  id: z.string().regex(/^[0-9a-fA-F]{24}$/, 'Invalid flow ID'),
});

router.get(
  '/:id',
  validate({ params: flowIdSchema }),
  async (req, res, next) => {
  try {
    const flow = await Flow.findOne({
      _id: req.params.id,
      orgId: req.user!.orgId,
    }).lean();

    if (!flow) {
      res.status(404).json({ error: 'Flow not found' });
      return;
    }
    res.json(flow);
  } catch (err) {
    next(err);
  }
});

export default router;
