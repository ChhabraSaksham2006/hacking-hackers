import { Router } from 'express';
import { authenticate } from '../middleware/auth.js';
import { requirePermission } from '../middleware/rbac.js';
import {
  getDashboardSummary,
  getDashboardTimeline,
  getDashboardStage,
} from '../services/dashboardService.js';

const router = Router();

// All dashboard routes require authentication + alerts.read
router.use(authenticate, requirePermission('alerts.read'));

// GET /api/dashboard/summary
router.get('/summary', async (req, res, next) => {
  try {
    const summary = await getDashboardSummary(req.user!.orgId);
    res.json(summary);
  } catch (err) {
    next(err);
  }
});

// GET /api/dashboard/timeline
router.get('/timeline', async (req, res, next) => {
  try {
    const timeline = await getDashboardTimeline(req.user!.orgId);
    res.json(timeline);
  } catch (err) {
    next(err);
  }
});

// GET /api/dashboard/stage
router.get('/stage', async (req, res, next) => {
  try {
    const stage = await getDashboardStage(req.user!.orgId);
    res.json(stage);
  } catch (err) {
    next(err);
  }
});

export default router;
