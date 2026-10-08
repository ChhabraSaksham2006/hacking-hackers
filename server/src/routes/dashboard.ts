import { Router } from 'express';
import {
  getSummary,
  getTimeline,
  getStages,
  getAlerts,
  getFlows,
  getFullState,
  stepForward,
  resetBaseline,
  jumpAttack,
  streamDashboard,
} from '../controllers/dashboardController.js';

import { authenticate } from '../middleware/auth.js';

const router = Router();

// ── Real-time SSE Stream ─────────────────────────────────
router.get('/stream', streamDashboard);

router.use(authenticate);

// ── Granular REST Endpoints ──────────────────────────────
router.get('/summary', getSummary);
router.get('/timeline', getTimeline);
router.get('/stages', getStages);
router.get('/stage', getStages); // Backward compatible alias
router.get('/alerts', getAlerts);
router.get('/flows', getFlows);

// ── Simulation / Replay Actions ──────────────────────────
router.post('/step', stepForward);
router.post('/reset', resetBaseline);
router.post('/jump', jumpAttack);

// ── Consolidated Full Snapshot ───────────────────────────
router.get('/', getFullState);

export default router;
