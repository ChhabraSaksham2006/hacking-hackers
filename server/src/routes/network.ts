import { Router } from 'express';
import { verifyAccessToken } from '../utils/jwt.js';
import { getNetworkGraph, getHostDetails } from '../controllers/networkController.js';

const router = Router();

// Optional authentication middleware for network graph access
router.use((req, _res, next) => {
  const token = req.cookies?.access_token as string | undefined;
  if (token) {
    try {
      req.user = verifyAccessToken(token);
    } catch {
      // ignore invalid token for topology viewer
    }
  }
  next();
});

// ── GET /api/network/graph ──────────────────────────────
router.get('/graph', getNetworkGraph);

// ── GET /api/network/hosts/:id ──────────────────────────
router.get('/hosts/:id', getHostDetails);

export default router;

