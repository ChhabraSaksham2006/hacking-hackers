import { Router } from 'express';
import { authenticate } from '../middleware/auth.js';
import { requirePermission } from '../middleware/rbac.js';
import { Report } from '../models/Report.js';
import { logAuditEvent } from '../services/auditService.js';
import { z } from 'zod';
import { validate } from '../middleware/validate.js';
import crypto from 'crypto';
import { paginationSchema, paginateQuery, paginatedResponse } from '../utils/pagination.js';

const router = Router();
router.use(authenticate);

// ── GET /api/reports ────────────────────────────────────

router.get(
  '/',
  requirePermission('reports.export'),
  validate({ query: paginationSchema }),
  async (req, res, next) => {
    try {
      const { page, limit } = req.query as any;
      const { skip } = paginateQuery({ page, limit });

      const [reports, total] = await Promise.all([
        Report.find({ orgId: req.user!.orgId })
          .sort({ createdAt: -1 })
          .skip(skip)
          .limit(limit)
          .lean(),
        Report.countDocuments({ orgId: req.user!.orgId }),
      ]);

      res.json(paginatedResponse(reports, total, { page, limit }));
    } catch (err) {
      next(err);
    }
  },
);

// ── POST /api/reports/generate ──────────────────────────

const generateSchema = z.object({
  name: z.string().min(1).trim(),
  scope: z.string().min(1).trim(),
  format: z.enum(['PDF', 'CSV']),
  timeWindow: z
    .object({
      start: z.coerce.date(),
      end: z.coerce.date(),
    })
    .refine(({ start, end }) => start <= end, {
      message: 'Start date must be before or equal to end date',
    }),
  segmentOrAlert: z.string().optional(),
});

router.post(
  '/generate',
  requirePermission('reports.export'),
  validate({ body: generateSchema }),
  async (req, res, next) => {
    try {
      const { name, scope, format, timeWindow, segmentOrAlert } = req.body as z.infer<typeof generateSchema>;

      const report = await Report.create({
        name,
        scope,
        format,
        timeWindow,
        segmentOrAlert: segmentOrAlert ?? '',
        orgId: req.user!.orgId,
        createdBy: req.user!.userId,
        status: 'generating',
      });

      // In production, enqueue BullMQ job here for PDF/CSV generation
      const mockJobId = crypto.randomUUID();
      // await reportQueue.add('generate-report', { reportId: report._id }, { jobId: mockJobId });

      await logAuditEvent('REPORT_GENERATED', report.name, req);

      res.status(202).json({
        message: 'Report generation queued',
        reportId: report._id,
        status: report.status,
        jobId: mockJobId,
      });
    } catch (err) {
      next(err);
    }
  },
);

export default router;
