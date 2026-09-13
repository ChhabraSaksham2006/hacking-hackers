import { Router } from 'express';
import { authenticate } from '../middleware/auth.js';
import { requirePermission } from '../middleware/rbac.js';
import { ModelVersion } from '../models/ModelVersion.js';
import { logAuditEvent } from '../services/auditService.js';
import { z } from 'zod';
import mongoose from 'mongoose';
import { validate } from '../middleware/validate.js';

const router = Router();
router.use(authenticate, requirePermission('alerts.read'));

// ── GET /api/models ─────────────────────────────────────

router.get('/', async (req, res, next) => {
  try {
    const models = await ModelVersion.find()
      .sort({ releasedAt: -1 })
      .populate('promotedBy', 'name initials')
      .lean();
    res.json(models);
  } catch (err) {
    next(err);
  }
});

// ── POST /api/models/:id/promote ────────────────────────

const modelIdSchema = z.object({
  id: z.string().regex(/^[0-9a-fA-F]{24}$/, 'Invalid model ID'),
});

router.post(
  '/:id/promote',
  requirePermission('model.promote'),
  validate({ params: modelIdSchema }),
  async (req, res, next) => {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      const targetModel = await ModelVersion.findById(req.params.id).session(session);
      if (!targetModel) {
        await session.abortTransaction();
        session.endSession();
        res.status(404).json({ error: 'Model version not found' });
        return;
      }

      if (targetModel.isProduction) {
        await session.abortTransaction();
        session.endSession();
        res.status(200).json({ message: 'Model is already in production', model: targetModel });
        return;
      }

      // Demote current production model
      await ModelVersion.updateMany(
        { isProduction: true },
        { $set: { isProduction: false } },
        { session }
      );

      // Promote target
      targetModel.isProduction = true;
      targetModel.promotedBy = new mongoose.Types.ObjectId(req.user!.userId);
      await targetModel.save({ session });

      await session.commitTransaction();
      session.endSession();

      await logAuditEvent('MODEL_PROMOTED', targetModel.version, req);

      res.json({ message: 'Model promoted to production', model: targetModel });
    } catch (err) {
      await session.abortTransaction();
      session.endSession();
      next(err);
    }
  },
);

export default router;
