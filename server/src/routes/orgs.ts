import { Router } from 'express';
import { authenticate } from '../middleware/auth.js';
import { requirePermission } from '../middleware/rbac.js';
import { Organisation } from '../models/Organisation.js';

const router = Router();
router.use(authenticate, requirePermission('orgs.read'));

// ── GET /api/orgs/current ───────────────────────────────

router.get('/current', async (req, res, next) => {
  try {
    const org = await Organisation.findById(req.user!.orgId)
      .select('name hosts modelVersion datasetAccess createdAt')
      .lean();
    if (!org) {
      res.status(404).json({ error: 'Organisation not found' });
      return;
    }
    res.json(org);
  } catch (err) {
    next(err);
  }
});

export default router;
