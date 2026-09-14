import { Router } from 'express';
import { authenticate } from '../middleware/auth.js';
import { requirePermission } from '../middleware/rbac.js';
import { getNetworkGraph, getHostDetails } from '../controllers/networkController.js';

const router = Router();

router.use(authenticate, requirePermission('alerts.read'));

// ── GET /api/network/graph ──────────────────────────────
router.get('/graph', getNetworkGraph);

// ── GET /api/network/hosts/:id ──────────────────────────
router.get('/hosts/:id', getHostDetails);

export default router;

