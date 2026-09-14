import { Router } from 'express';
import { z } from 'zod';
import { authenticate } from '../middleware/auth.js';
import { requirePermission } from '../middleware/rbac.js';
import { validate } from '../middleware/validate.js';
import { paginationSchema } from '../utils/pagination.js';
import { listAlerts, getAlertById, updateAlert } from '../controllers/alertsController.js';

const router = Router();

router.use(authenticate);

// ── GET /api/alerts ─────────────────────────────────────
const listAlertsSchema = z.object({
  status: z.enum(['New', 'Acknowledged', 'Investigating', 'Resolved']).optional(),
  state: z.enum(['normal', 'watch', 'critical']).optional(),
  host: z.string().optional(),
}).merge(paginationSchema);

router.get(
  '/',
  requirePermission('alerts.read'),
  validate({ query: listAlertsSchema }),
  listAlerts,
);

// ── GET /api/alerts/:id ─────────────────────────────────
router.get(
  '/:id',
  requirePermission('alerts.read'),
  getAlertById,
);

// ── PATCH /api/alerts/:id ───────────────────────────────
const updateAlertSchema = z.object({
  status: z.enum(['New', 'Acknowledged', 'Investigating', 'Resolved']).optional(),
  assignedTo: z.string().regex(/^[0-9a-fA-F]{24}$/, 'Invalid user ID').nullable().optional(),
  notes: z.string().optional(),
});

router.patch(
  '/:id',
  requirePermission('alerts.update'),
  validate({ body: updateAlertSchema }),
  updateAlert,
);

export default router;

