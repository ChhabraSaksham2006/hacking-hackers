import { Router } from 'express';
import { authenticate } from '../middleware/auth.js';
import { requirePermission } from '../middleware/rbac.js';
import { AuditEntry } from '../models/AuditEntry.js';
import { validate } from '../middleware/validate.js';
import { paginationSchema, paginateQuery, paginatedResponse } from '../utils/pagination.js';

const router = Router();
router.use(authenticate, requirePermission('audit.read'));

// ── GET /api/audit ──────────────────────────────────────

router.get(
  '/',
  validate({ query: paginationSchema }),
  async (req, res, next) => {
    try {
      const { page, limit } = req.query as any;
      const { skip } = paginateQuery({ page, limit });

      const [entries, total] = await Promise.all([
        AuditEntry.find({ orgId: req.user!.orgId })
          .sort({ timestamp: -1 })
          .skip(skip)
          .limit(limit)
          .lean(),
        AuditEntry.countDocuments({ orgId: req.user!.orgId }),
      ]);

      res.json(paginatedResponse(entries, total, { page, limit }));
    } catch (err) {
      next(err);
    }
  },
);

export default router;
