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
// Held-out evaluation metrics from final.pdf (Table V, VI, VII).
// Setting C: Unseen-Family OOD Holdout (7 attack episodes, K=10, 20s lead)
// Setting A: Seen In-Distribution Master Benchmark (29 attack episodes, K=10, 20s lead)
const LR_BASELINE = {
  cicIds: { f1: 0.5531, precision: 0.4118, recall: 0.8418, fpr: 0.4935 }, // Setting C (OOD)
  ctu13:  { f1: 0.5312, precision: 0.3626, recall: 0.9923, fpr: 0.3293 }, // Setting A (Seen In-Dist)
};

router.get('/benchmark', async (req, res, next) => {
  try {
    const prod = await ModelVersion.findOne({ isProduction: true }).lean();
    if (!prod) {
      res.status(404).json({ error: 'No production model found' });
      return;
    }

    const rows = [
      { metric: 'Incident F1',        wmA: prod.metrics.cicIds.f1,        lrA: LR_BASELINE.cicIds.f1,        wmB: prod.metrics.ctu13.f1,        lrB: LR_BASELINE.ctu13.f1        },
      { metric: 'Precision',          wmA: prod.metrics.cicIds.precision,  lrA: LR_BASELINE.cicIds.precision,  wmB: prod.metrics.ctu13.precision,  lrB: LR_BASELINE.ctu13.precision  },
      { metric: 'Recall',             wmA: prod.metrics.cicIds.recall,     lrA: LR_BASELINE.cicIds.recall,     wmB: prod.metrics.ctu13.recall,     lrB: LR_BASELINE.ctu13.recall     },
      { metric: 'False positive rate', wmA: prod.metrics.cicIds.fpr,       lrA: LR_BASELINE.cicIds.fpr,       wmB: prod.metrics.ctu13.fpr,       lrB: LR_BASELINE.ctu13.fpr       },
    ];

    // Official confusion matrices from final.pdf
    const matrices = [
      { name: 'Logistic Regression (54-D Static, Setting C)', dataset: 'CIC-IDS-2018 OOD', cells: [3, 4, 1, 6] },
      { name: `Two-Stage SOC ${prod.version} (Setting C OOD)`, dataset: 'CIC-IDS-2018 OOD', cells: [6, 1, 0, 7] },
      { name: 'Logistic Regression (54-D Static, Setting A)', dataset: 'CIC-IDS-2018 In-Dist', cells: [19, 10, 1, 28] },
      { name: `Two-Stage SOC ${prod.version} (Setting A In-Dist)`, dataset: 'CIC-IDS-2018 In-Dist', cells: [28, 1, 0, 29] },
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
