import { Router } from 'express';
import { z } from 'zod';
import { authenticate } from '../middleware/auth.js';
import { requirePermission } from '../middleware/rbac.js';
import { validate } from '../middleware/validate.js';
import { Ingestion } from '../models/Ingestion.js';
import { logAuditEvent } from '../services/auditService.js';
import crypto from 'crypto';
import { env } from '../config/env.js';
import { paginationSchema, paginateQuery, paginatedResponse } from '../utils/pagination.js';

const router = Router();
router.use(authenticate);

// ── GET /api/ingestion ──────────────────────────────────

router.get(
  '/',
  requirePermission('alerts.read'),
  validate({ query: paginationSchema }),
  async (req, res, next) => {
    try {
      const { page, limit } = req.query as any;
      const { skip } = paginateQuery({ page, limit });

      const [ingestions, total] = await Promise.all([
        Ingestion.find({ orgId: req.user!.orgId })
          .sort({ createdAt: -1 })
          .skip(skip)
          .limit(limit)
          .lean(),
        Ingestion.countDocuments({ orgId: req.user!.orgId }),
      ]);

      res.json(paginatedResponse(ingestions, total, { page, limit }));
    } catch (err) {
      next(err);
    }
  },
);

// ── POST /api/ingestion/init ────────────────────────────

const initSchema = z.object({
  filename: z.string().min(1),
  datasetType: z.enum(['CIC-IDS-2018', 'CTU-13', 'Custom upload']),
  fileSize: z.coerce.number().int().nonnegative(),
});

router.post(
  '/init',
  requirePermission('ingestion.create'),
  validate({ body: initSchema }),
  async (req, res, next) => {
    try {
      const { filename, datasetType, fileSize } = req.body as z.infer<typeof initSchema>;
      
      // In production, we'd use AWS SDK to generate a presigned PUT URL.
      // For this implementation, we return a mock URL and store local path.
      const uploadId = crypto.randomUUID();
      const mockUploadUrl = `http://localhost:${env.PORT}/api/ingestion/upload/${uploadId}`;
      const storagePath = `${req.user!.orgId}/ingestions/${uploadId}/original.pcap`;

      const ingestion = await Ingestion.create({
        filename,
        datasetType,
        fileSize,
        storagePath,
        orgId: req.user!.orgId,
        uploadedBy: req.user!.userId,
        status: 'uploading',
        pipelineSteps: [
          { name: 'Parsing', status: 'pending' },
          { name: 'Feature extraction', status: 'pending' },
          { name: 'Normalisation', status: 'pending' },
          { name: 'Inference', status: 'pending' },
          { name: 'Explanation', status: 'pending' },
        ],
      });

      res.json({
        ingestionId: ingestion._id,
        uploadUrl: mockUploadUrl,
      });
    } catch (err) {
      next(err);
    }
  },
);

// ── POST /api/ingestion/complete ────────────────────────

const completeSchema = z.object({
  ingestionId: z.string().regex(/^[0-9a-fA-F]{24}$/, 'Invalid ID'),
});

router.post(
  '/complete',
  requirePermission('ingestion.create'),
  validate({ body: completeSchema }),
  async (req, res, next) => {
    try {
      const { ingestionId } = req.body as z.infer<typeof completeSchema>;

      const ingestion = await Ingestion.findOne({
        _id: ingestionId,
        orgId: req.user!.orgId,
      });

      if (!ingestion) {
        res.status(404).json({ error: 'Ingestion not found' });
        return;
      }

      // Idempotency protection
      if (ingestion.status !== 'uploading') {
        res.status(200).json({
          message: 'Ingestion already started',
          ingestionId: ingestion._id,
          status: ingestion.status,
        });
        return;
      }

      // TODO: In production, verify the object actually exists in S3/MinIO here
      // const exists = await verifyS3Object(ingestion.storagePath);
      // if (!exists) return res.status(400).json({ error: 'Upload not found' });

      ingestion.status = 'parsing';
      if (ingestion.pipelineSteps[0]) {
        ingestion.pipelineSteps[0].status = 'running';
        ingestion.pipelineSteps[0].startedAt = new Date();
      }
      await ingestion.save();

      // In production, enqueue a BullMQ job to start the background pipeline
      // e.g. await ingestionQueue.add('process-pcap', { ingestionId }, { jobId: `ingestion:${ingestionId}` })
      
      await logAuditEvent('INGESTION_STARTED', ingestion._id.toString(), req, {
        filename: ingestion.filename,
      });

      res.status(202).json({
        message: 'Upload confirmed. Pipeline started.',
        ingestion,
      });
    } catch (err) {
      next(err);
    }
  },
);

export default router;
