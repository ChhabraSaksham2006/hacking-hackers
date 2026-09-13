import { Router } from 'express';
import { authenticate } from '../middleware/auth.js';
import { requirePermission } from '../middleware/rbac.js';
import { Segment } from '../models/Segment.js';
import { z } from 'zod';
import { validate } from '../middleware/validate.js';

const router = Router();

router.use(authenticate, requirePermission('alerts.read'));

// ── GET /api/segments ───────────────────────────────────

router.get('/', async (req, res, next) => {
  try {
    const segments = await Segment.find({ orgId: req.user!.orgId })
      .sort({ trafficVolume: -1 })
      .lean();

    res.json(segments);
  } catch (err) {
    next(err);
  }
});

const segmentNameSchema = z.object({
  name: z.string().min(1).max(100),
});

router.get(
  '/:name',
  validate({ params: segmentNameSchema }),
  async (req, res, next) => {
  try {
    const segment = await Segment.findOne({
      orgId: req.user!.orgId,
      name: req.params.name,
    }).lean();

    if (!segment) {
      res.status(404).json({ error: 'Segment not found' });
      return;
    }

    res.json(segment);
  } catch (err) {
    next(err);
  }
});

export default router;
