import type { Request, Response, NextFunction } from 'express';
import { Flow } from '../models/Flow.js';
import { Settings } from '../models/Settings.js';
import { paginateQuery, paginatedResponse } from '../utils/pagination.js';

// ── GET /api/flows ──────────────────────────────────────
export async function listFlows(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const { page, limit, minScore, flaggedOnly, search } = req.query as any;
    const filter: Record<string, unknown> = { orgId: req.user!.orgId };

    if (minScore !== undefined) {
      filter.score = { $gte: Number(minScore) };
    }
    if (flaggedOnly) {
      const settings = await Settings.findOne({ orgId: req.user!.orgId }).lean();
      const threshold = settings?.modelConfig?.alertThreshold ?? 0.65;
      filter.score = { ...(filter.score as object || {}), $gte: threshold };
    }
    if (search) {
      filter.$or = [
        { src: { $regex: search, $options: 'i' } },
        { dst: { $regex: search, $options: 'i' } },
        { proto: { $regex: search, $options: 'i' } },
      ];
    }

    const { skip } = paginateQuery({ page, limit });
    const [flows, total] = await Promise.all([
      Flow.find(filter).sort({ score: -1 }).skip(skip).limit(limit).lean(),
      Flow.countDocuments(filter),
    ]);

    res.json(paginatedResponse(flows, total, { page, limit }));
  } catch (err) {
    next(err);
  }
}

// ── GET /api/flows/:id ──────────────────────────────────
export async function getFlowById(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const flow = await Flow.findOne({
      _id: req.params.id,
      orgId: req.user!.orgId,
    }).lean();

    if (!flow) {
      res.status(404).json({ error: 'Flow not found' });
      return;
    }
    res.json(flow);
  } catch (err) {
    next(err);
  }
}
