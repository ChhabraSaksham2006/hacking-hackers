import { Router } from 'express';
import { verifyAccessToken } from '../utils/jwt.js';
import { queryTelemetry, getSuggestedPrompts } from '../controllers/chatController.js';

const router = Router();

// Optional authentication middleware
router.use((req, _res, next) => {
  const token = req.cookies?.access_token as string | undefined;
  if (token) {
    try {
      req.user = verifyAccessToken(token);
    } catch {
      // Ignore token verification errors for chat telemetry queries
    }
  }
  next();
});

// ── POST /api/chat/query ─────────────────────────────────
router.post('/query', queryTelemetry);

// ── GET /api/chat/suggested ──────────────────────────────
router.get('/suggested', getSuggestedPrompts);

export default router;
