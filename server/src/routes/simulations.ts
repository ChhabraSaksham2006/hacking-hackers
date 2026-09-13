import { Router } from 'express';
import { z } from 'zod';
import { authenticate } from '../middleware/auth.js';
import { requirePermission } from '../middleware/rbac.js';
import { validate } from '../middleware/validate.js';
import { Simulation } from '../models/Simulation.js';
import { Segment } from '../models/Segment.js';
import { logAuditEvent } from '../services/auditService.js';
import crypto from 'crypto';
import { paginationSchema, paginateQuery, paginatedResponse } from '../utils/pagination.js';

const router = Router();
router.use(authenticate);

// ── GET /api/simulations ────────────────────────────────

router.get(
  '/',
  requirePermission('alerts.read'),
  validate({ query: paginationSchema }),
  async (req, res, next) => {
    try {
      const { page, limit } = req.query as any;
      const { skip } = paginateQuery({ page, limit });

      const [simulations, total] = await Promise.all([
        Simulation.find({ orgId: req.user!.orgId })
          .sort({ createdAt: -1 })
          .skip(skip)
          .limit(limit)
          .lean(),
        Simulation.countDocuments({ orgId: req.user!.orgId }),
      ]);

      res.json(paginatedResponse(simulations, total, { page, limit }));
    } catch (err) {
      next(err);
    }
  },
);

// ── POST /api/simulations/run ───────────────────────────

const runSchema = z.object({
  segmentName: z.string().trim().min(1).max(100),
  perturbation: z.string().trim().min(1).max(250),
});

router.post(
  '/run',
  requirePermission('simulation.run'),
  validate({ body: runSchema }),
  async (req, res, next) => {
    try {
      const { segmentName, perturbation } = req.body as z.infer<typeof runSchema>;

      // Verify the segment actually exists in this organization
      const segment = await Segment.findOne({ orgId: req.user!.orgId, name: segmentName });
      if (!segment) {
        res.status(404).json({ error: 'Segment not found' });
        return;
      }

      const probabilityMap: Record<string, number> = { normal: 0.1, watch: 0.5, critical: 0.9 };
      const currentProbability = probabilityMap[segment.state] ?? 0.5;

      const simulation = await Simulation.create({
        orgId: req.user!.orgId,
        segmentName,
        perturbation,
        baseState: { 
          hosts: segment.hosts, 
          flows: segment.trafficVolume, 
          probability: currentProbability 
        },
        forecastSeries: [],
        actualSeries: [],
        divergence: [],
        steps: 8,
        status: 'running',
      });

      // In production this queues a BullMQ job
      const mockJobId = crypto.randomUUID();
      // await simulationQueue.add('run-simulation', { simulationId: simulation._id }, { jobId: mockJobId });

      await logAuditEvent('SIMULATION_RUN', simulation._id.toString(), req, {
        segmentName,
        perturbation,
      });

      res.status(202).json({
        message: 'Simulation queued',
        simulationId: simulation._id,
        status: simulation.status,
        jobId: mockJobId,
      });
    } catch (err) {
      next(err);
    }
  },
);

export default router;
