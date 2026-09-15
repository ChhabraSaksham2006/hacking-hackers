import type { Request, Response, NextFunction } from 'express';
import { analyzeCaptureFile, DEMO_PRESETS } from '../services/demonstrationService.js';

/**
 * POST /api/demonstration/analyze
 * Accepts multipart/form-data with a PCAP or CSV file, or JSON with presetId.
 * Runs Cyber World Model ensemble inference on the captured temporal windows.
 */
export async function analyzeCapture(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const file = req.file;
    const presetId = (req.body?.presetId || req.query?.presetId) as string | undefined;

    if (file) {
      const result = await analyzeCaptureFile({
        filename: file.originalname,
        fileBuffer: file.buffer,
      });
      res.json(result);
      return;
    }

    // If presetId is provided or fallback
    const result = await analyzeCaptureFile({
      presetId: presetId || 'thursday_infiltration',
    });

    res.json(result);
  } catch (err) {
    next(err);
  }
}

/**
 * GET /api/demonstration/presets
 * Returns available demonstration presets (e.g. CSE-CIC-IDS2018, Stealth Port Sweep, Cobalt Strike C2).
 */
export async function getDemonstrationPresets(_req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    res.json({
      presets: DEMO_PRESETS,
    });
  } catch (err) {
    next(err);
  }
}
