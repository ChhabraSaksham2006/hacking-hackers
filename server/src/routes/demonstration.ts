import { Router } from 'express';
import multer from 'multer';
import { verifyAccessToken } from '../utils/jwt.js';
import {
  analyzeCapture,
  getDemonstrationPresets,
} from '../controllers/demonstrationController.js';

const router = Router();

// Memory storage for file uploads (pcap, pcapng, csv)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 30 * 1024 * 1024, // 30 MB max
  },
});

// Optional authentication middleware
router.use((req, _res, next) => {
  const token = req.cookies?.access_token as string | undefined;
  if (token) {
    try {
      req.user = verifyAccessToken(token);
    } catch {
      // Ignore token verification errors for demonstration interface
    }
  }
  next();
});

// ── GET /api/demonstration/presets ────────────────────────
router.get('/presets', getDemonstrationPresets);

// ── POST /api/demonstration/analyze ───────────────────────
// Accepts either multipart file or JSON with presetId
router.post('/analyze', upload.single('file'), analyzeCapture);

export default router;
