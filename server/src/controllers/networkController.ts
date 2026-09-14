import type { Request, Response, NextFunction } from 'express';
import { Flow } from '../models/Flow.js';
import { Alert } from '../models/Alert.js';
import { dashboardStore } from '../models/dashboardModel.js';

// ── GET /api/network/graph ──────────────────────────────
export async function getNetworkGraph(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const orgId = req.user?.orgId;
    const scrub = req.query.scrub ? Number(req.query.scrub) : undefined;

    // First check if database has seeded flows for this org
    let flows: Array<{ src: string; dst: string; bytes: number; score: number }> = [];
    if (orgId) {
      flows = (await Flow.find({ orgId }).lean()) as any;
    }

    if (!flows || flows.length === 0) {
      // Return real CIC-IDS-2018 benchmark topology from live model store
      res.json(dashboardStore.getNetworkGraph(scrub));
      return;
    }

    // Otherwise aggregate DB records
    const alerts = await Alert.find(
      { orgId, status: { $ne: 'Resolved' } },
      { ip: 1, state: 1 }
    ).lean();

    const hostMap = new Map<string, { id: string; flows: number; bytes: number; state: string }>();

    for (const flow of flows) {
      const srcHost = flow.src.split(':')[0]!;
      const dstHost = flow.dst.split(':')[0]!;

      for (const host of [srcHost, dstHost]) {
        const existing = hostMap.get(host);
        if (existing) {
          existing.flows += 1;
          existing.bytes += flow.bytes;
        } else {
          hostMap.set(host, { id: host, flows: 1, bytes: flow.bytes, state: 'normal' });
        }
      }
    }

    for (const alert of alerts) {
      const alertIp = alert.ip.split(':')[0]!;
      let node = hostMap.get(alertIp);

      if (!node) {
        node = { id: alertIp, flows: 0, bytes: 0, state: 'normal' };
        hostMap.set(alertIp, node);
      }

      if (alert.state === 'critical' || node.state === 'critical') {
        node.state = 'critical';
      } else if (alert.state === 'watch' || node.state === 'watch') {
        node.state = 'watch';
      }
    }

    const nodes = Array.from(hostMap.values()).map((n) => ({
      id: n.id,
      size: Math.max(1, Math.round(n.bytes / 100000)),
      state: n.state,
      flows: n.flows,
    }));

    const edges = flows.map((f) => ({
      source: f.src.split(':')[0],
      target: f.dst.split(':')[0],
      bytes: f.bytes,
      score: f.score,
    }));

    res.json({ nodes, edges });
  } catch (err) {
    next(err);
  }
}

// ── GET /api/network/hosts/:id ──────────────────────────
export async function getHostDetails(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const orgId = req.user?.orgId;
    const hostIp = String(req.params.id);

    if (!orgId) {
      res.json(dashboardStore.getHostDetail(hostIp));
      return;
    }

    const hostFlowsFilter = {
      orgId,
      $or: [
        { src: { $regex: `^${hostIp}:` } },
        { dst: { $regex: `^${hostIp}:` } },
      ],
    };

    const hostFlows = await Flow.find(hostFlowsFilter)
      .sort({ score: -1 })
      .limit(10)
      .lean();

    if (hostFlows.length === 0) {
      // Fallback to real CIC-IDS-2018 host telemetry in dashboard store
      res.json(dashboardStore.getHostDetail(hostIp));
      return;
    }

    const activeFlows = await Flow.countDocuments(hostFlowsFilter);

    const bytesAggregation = await Flow.aggregate([
      { $match: hostFlowsFilter },
      { $group: { _id: null, totalBytes: { $sum: '$bytes' } } }
    ]);
    const totalBytes = bytesAggregation[0]?.totalBytes ?? 0;

    const alert = await Alert.findOne({
      orgId,
      ip: hostIp,
      status: { $ne: 'Resolved' },
    })
      .sort({ probability: -1 })
      .lean();

    res.json({
      id: hostIp,
      state: alert?.state ?? 'normal',
      riskScore: alert?.probability ?? 0,
      activeFlows,
      totalBytes,
      recentFlows: hostFlows.slice(0, 5).map((f) => ({
        dst: f.dst,
        bytes: f.bytes,
        score: f.score,
      })),
    });
  } catch (err) {
    next(err);
  }
}
