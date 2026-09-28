import { Router, type Request, type Response, type NextFunction } from 'express';
import { z } from 'zod';
import crypto from 'crypto';
import { authenticate } from '../middleware/auth.js';
import { requirePermission } from '../middleware/rbac.js';
import { validate } from '../middleware/validate.js';
import { Organisation } from '../models/Organisation.js';
import { dashboardStore } from '../models/dashboardModel.js';
import { logAuditEvent } from '../services/auditService.js';
import { kafkaService } from '../services/kafkaService.js';

const router = Router();

// ── Ingestion Endpoint (Called by Edge Sensor — No User Cookie Required) ────

const telemetrySchema = z.object({
  sensor_id: z.string().default('edge-sensor-alpha-01'),
  window_idx: z.number().optional().default(0),
  timestamp_start: z.number().optional(),
  timestamp_end: z.number().optional(),
  packet_count: z.number().optional().default(0),
  byte_count: z.number().optional().default(0),
  flow_count: z.number().optional().default(0),
  features_54: z.array(z.number()).optional(),
  top_flows: z.array(z.any()).optional().default([]),
  alerts: z.array(z.any()).optional().default([]),
  calibrated_probability: z.number().optional(),
  probability: z.number().optional(),
  stage: z.string().optional(),
  risk_level: z.string().optional(),
  confidence: z.string().optional(),
  dispatched_at: z.number().optional(),
});

router.post('/telemetry', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const rawKey =
      (req.headers['x-sensor-key'] as string) ||
      (req.headers.authorization?.startsWith('Bearer ')
        ? req.headers.authorization.slice(7)
        : '');

    if (!rawKey) {
      res.status(401).json({ error: 'Missing sensor API key in x-sensor-key or Authorization header' });
      return;
    }

    const org = await Organisation.findOne({ sensorApiKey: rawKey }).lean();
    if (!org) {
      res.status(401).json({ error: 'Invalid sensor API key' });
      return;
    }

    const payload = req.body;
    const orgId = org._id.toString();

    // Dispatch telemetry through Kafka message broker (or fallback)
    const result = await kafkaService.publishTelemetry(orgId, payload);
    const estateRisk = result.directState
      ? result.directState.summary.infiltrationProbabilityPct
      : `${Math.round((payload.calibrated_probability ?? payload.probability ?? 0.5) * 100)}%`;

    res.status(200).json({
      status: 'ok',
      queued: result.queued,
      broker: result.queued ? 'kafka' : 'direct',
      sensor_id: payload.sensor_id,
      window_idx: payload.window_idx,
      estate_risk: estateRisk,
      received_at: Date.now(),
    });
  } catch (err) {
    next(err);
  }
});

// ── Management Endpoints (Require User Authentication) ──────────────────────

router.use(authenticate);

// GET /api/sensors — Current organization sensor status & API key
router.get('/', async (req: Request, res: Response, next: NextFunction) => {
  try {
    let org = await Organisation.findById(req.user!.orgId);
    if (!org) {
      res.status(404).json({ error: 'Organisation not found' });
      return;
    }

    if (!org.sensorApiKey) {
      org.sensorApiKey = `av_sec_${crypto.randomBytes(24).toString('hex')}`;
      await org.save();
    }

    const orgId = org._id.toString();
    const liveSensors = dashboardStore.getOrgLiveSensors(orgId);
    const isLive = dashboardStore.isOrgLive(orgId);

    const protocol = req.headers['x-forwarded-proto'] || req.protocol || 'http';
    const host = req.get('host') || 'localhost:5000';
    const upstreamUrl = `${protocol}://${host}/api/sensors/telemetry`;

    res.json({
      sensorApiKey: org.sensorApiKey,
      sensorSetupCompleted: org.sensorSetupCompleted ?? false,
      monitoredSubnets: org.monitoredSubnets || [],
      environmentType: org.environmentType || 'enterprise',
      activeSensors: liveSensors,
      activeSensorsCount: liveSensors.length,
      isLive,
      kafkaActive: kafkaService.isKafkaActive(),
      upstreamUrl,
      exampleCommand: `python edge_sensor/run_sensor.py --mode tap --interface eth0 --upstream ${upstreamUrl} --api-key ${org.sensorApiKey}`,
    });
  } catch (err) {
    next(err);
  }
});

// POST /api/sensors/setup — Save onboarding configuration
const setupSchema = z.object({
  monitoredSubnets: z.array(z.string().trim()).default([]),
  environmentType: z.enum(['enterprise', 'cloud_vpc', 'homelab', 'evaluation']).default('enterprise'),
  sensorSetupCompleted: z.boolean().default(true),
});

router.post('/setup', validate({ body: setupSchema }), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { monitoredSubnets, environmentType, sensorSetupCompleted } = req.body;

    const org = await Organisation.findByIdAndUpdate(
      req.user!.orgId,
      {
        $set: {
          monitoredSubnets,
          environmentType,
          sensorSetupCompleted,
        },
      },
      { new: true },
    );

    await logAuditEvent('SETTINGS_UPDATED', `Sensor setup configured for ${org?.name}`, req, {
      subnets: monitoredSubnets,
      environmentType,
    });

    res.json({
      message: 'Sensor configuration saved successfully',
      org,
    });
  } catch (err) {
    next(err);
  }
});

// POST /api/sensors/key/regenerate — Rotate organization sensor API key
router.post(
  '/key/regenerate',
  requirePermission('integrations.manage'),
  async (req: Request, res: Response, next: NextFunction) => {
  try {
    const newKey = `av_sec_${crypto.randomBytes(24).toString('hex')}`;

    const org = await Organisation.findByIdAndUpdate(
      req.user!.orgId,
      { $set: { sensorApiKey: newKey } },
      { new: true },
    );

    await logAuditEvent('SETTINGS_UPDATED', `Regenerated sensor API key for ${org?.name}`, req);

    res.json({
      message: 'Sensor API key regenerated',
      sensorApiKey: newKey,
    });
  } catch (err) {
    next(err);
  }
});

export default router;
