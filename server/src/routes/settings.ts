import { Router } from 'express';
import { z } from 'zod';
import { authenticate } from '../middleware/auth.js';
import { requirePermission } from '../middleware/rbac.js';
import { validate } from '../middleware/validate.js';
import { Settings } from '../models/Settings.js';
import { logAuditEvent } from '../services/auditService.js';

const router = Router();
router.use(authenticate);

// ── GET /api/settings ───────────────────────────────────

router.get(
  '/',
  requirePermission('settings.read'),
  async (req, res, next) => {
    try {
      const settings = await Settings.findOne({ orgId: req.user!.orgId })
        .select('-integrations.apiKeyHash')
        .lean();
      
      if (!settings) {
        res.status(404).json({ error: 'Settings not found' });
        return;
      }
      
      res.json(settings);
    } catch (err) {
      next(err);
    }
  },
);

// ── PATCH /api/settings ─────────────────────────────────

const updateSettingsSchema = z.object({
  modelConfig: z.object({
    windowK: z.coerce.number().int().min(1).optional(),
    alertThreshold: z.coerce.number().min(0).max(1).optional(),
    retrainingSchedule: z.string().min(1).optional(),
  }).optional(),
});

router.patch(
  '/',
  requirePermission('settings.update'),
  validate({ body: updateSettingsSchema }),
  async (req, res, next) => {
    try {
      const updates = req.body as z.infer<typeof updateSettingsSchema>;
      const settings = await Settings.findOne({ orgId: req.user!.orgId });

      if (!settings) {
        res.status(404).json({ error: 'Settings not found' });
        return;
      }

      const changedFields: string[] = [];

      if (updates.modelConfig) {
        settings.modelConfig = { ...settings.modelConfig, ...updates.modelConfig };
        changedFields.push(...Object.keys(updates.modelConfig).map(k => `modelConfig.${k}`));
      }

      await settings.save();
      
      await logAuditEvent('SETTINGS_UPDATED', 'Organisation settings', req, { changedFields });

      const safeSettings = settings.toObject();
      if (safeSettings.integrations?.apiKeyHash) {
        // @ts-ignore
        delete safeSettings.integrations.apiKeyHash;
      }

      res.json(safeSettings);
    } catch (err) {
      next(err);
    }
  },
);

export default router;
