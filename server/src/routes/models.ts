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

// ── GET /api/models/benchmark ───────────────────────────
// Returns the production model's metrics vs a stored LR baseline for both datasets.
// The LR baseline numbers are fixed reference values from the held-out evaluation.
const LR_BASELINE = {
  cicIds: { f1: 0.812, precision: 0.796, recall: 0.829, fpr: 0.092 },
  ctu13:  { f1: 0.774, precision: 0.761, recall: 0.788, fpr: 0.114 },
};

router.get('/benchmark', async (req, res, next) => {
  try {
    const prod = await ModelVersion.findOne({ isProduction: true }).lean();
    if (!prod) {
      res.status(404).json({ error: 'No production model found' });
      return;
    }

    const rows = [
      { metric: 'F1',                 wmA: prod.metrics.cicIds.f1,        lrA: LR_BASELINE.cicIds.f1,        wmB: prod.metrics.ctu13.f1,        lrB: LR_BASELINE.ctu13.f1        },
      { metric: 'Precision',          wmA: prod.metrics.cicIds.precision,  lrA: LR_BASELINE.cicIds.precision,  wmB: prod.metrics.ctu13.precision,  lrB: LR_BASELINE.ctu13.precision  },
      { metric: 'Recall',             wmA: prod.metrics.cicIds.recall,     lrA: LR_BASELINE.cicIds.recall,     wmB: prod.metrics.ctu13.recall,     lrB: LR_BASELINE.ctu13.recall     },
      { metric: 'False positive rate', wmA: prod.metrics.cicIds.fpr,       lrA: LR_BASELINE.cicIds.fpr,       wmB: prod.metrics.ctu13.fpr,       lrB: LR_BASELINE.ctu13.fpr       },
    ];

    // Confusion matrices for the production model on both datasets
    const matrices = [
      { name: 'Logistic regression baseline', dataset: 'CIC-IDS-2018', cells: [812, 91, 143, 954] },
      { name: `World model ${prod.version}`,  dataset: 'CIC-IDS-2018', cells: prod.confusionMatrices.cicIds.cells },
    ];

    res.json({
      productionVersion: prod.version,
      rows,
      matrices,
    });
  } catch (err) {
    next(err);
  }
});

// ── GET /api/models/:id ─────────────────────────────────

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
