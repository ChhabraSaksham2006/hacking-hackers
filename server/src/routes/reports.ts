import { Router } from 'express';
import { authenticate } from '../middleware/auth.js';
import { requirePermission } from '../middleware/rbac.js';
import { Report } from '../models/Report.js';
import { logAuditEvent } from '../services/auditService.js';
import { z } from 'zod';
import { validate } from '../middleware/validate.js';
import { paginationSchema, paginateQuery, paginatedResponse } from '../utils/pagination.js';
import {
  getReportPreview,
  generateAndSaveReport,
  getReportFileStream,
} from '../services/reportService.js';

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
          .populate('createdBy', 'name email initials')
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

// ── GET /api/reports/preview ────────────────────────────

const previewSchema = z.object({
  timeWindow: z.string().optional(),
  segmentOrAlert: z.string().optional(),
  startDate: z.string().optional(),
  endDate: z.string().optional(),
});

router.get(
  '/preview',
  requirePermission('reports.export'),
  validate({ query: previewSchema }),
  async (req, res, next) => {
    try {
      const preview = await getReportPreview(req.user!.orgId as any, req.query);
      res.json(preview);
    } catch (err) {
      next(err);
    }
  },
);

// ── POST /api/reports/generate ──────────────────────────

const generateSchema = z.object({
  name: z.string().min(1).trim().optional(),
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
      const { name, scope, format, timeWindow, segmentOrAlert } = req.body as z.infer<
        typeof generateSchema
      >;

      const report = await generateAndSaveReport(
        req.user!.orgId as any,
        req.user!.userId as any,
        {
          name,
          scope,
          format,
          timeWindow,
          segmentOrAlert,
        },
      );

      await logAuditEvent('REPORT_GENERATED', report.name, req);

      res.status(201).json({
        message: 'Report generated successfully',
        report,
      });
    } catch (err) {
      next(err);
    }
  },
);

// ── GET /api/reports/:id/download ───────────────────────

router.get(
  '/:id/download',
  requirePermission('reports.export'),
  async (req, res, next) => {
    try {
      const id = req.params.id as string;
      const { filename, contentType, buffer } = await getReportFileStream(
        id,
        req.user!.orgId as any,
      );

      res.setHeader('Content-Type', contentType);
      res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
      res.setHeader('Content-Length', buffer.length);
      res.send(buffer);
    } catch (err: any) {
      if (err.message === 'Report not found') {
        res.status(404).json({ error: 'Report not found' });
        return;
      }
      next(err);
    }
  },
);

// ── DELETE /api/reports/:id ─────────────────────────────

router.delete(
  '/:id',
  requirePermission('reports.export'),
  async (req, res, next) => {
    try {
      const id = req.params.id as string;
      const deleted = await Report.findOneAndDelete({
        _id: id,
        orgId: req.user!.orgId,
      });

      if (!deleted) {
        res.status(404).json({ error: 'Report not found' });
        return;
      }

      res.json({ message: 'Report deleted successfully', id: req.params.id });
    } catch (err) {
      next(err);
    }
  },
);

export default router;
