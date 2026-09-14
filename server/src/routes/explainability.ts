import { Router } from 'express';
import { getExplainability } from '../controllers/explainabilityController.js';

const router = Router();

// ── GET /api/explainability ─────────────────────────────
// Supports ?windowIndex=1796 or ?scrub=85 (optional auth so page loads seamlessly)
router.get('/', getExplainability);

export default router;
