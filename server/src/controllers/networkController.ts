import type { Request, Response, NextFunction } from 'express';
import { Flow } from '../models/Flow.js';
import { Alert } from '../models/Alert.js';
import { dashboardStore } from '../models/dashboardModel.js';

// ── GET /api/network/graph ──────────────────────────────
export async function getNetworkGraph(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const scrub = req.query.scrub !== undefined && req.query.scrub !== '' ? Number(req.query.scrub) : undefined;
    const live = req.query.live === 'true' || scrub === undefined;

    // Always fetch benchmark topology with positioned nodes (x, y, segment, role)
    // and responsive state based on live step or time scrubber
    const graph = dashboardStore.getNetworkGraph(scrub, live);

    // If org has active DB alerts, overlay them
    const orgId = req.user?.orgId;
    if (orgId) {
      const activeAlerts = await Alert.find(
        { orgId, status: { $ne: 'Resolved' } },
        { ip: 1, state: 1 }
      ).lean();

      for (const alert of activeAlerts) {
        const alertIp = alert.ip.split(':')[0]!;
        const node = graph.nodes.find((n) => n.id === alertIp);
        if (node) {
          if (alert.state === 'critical') {
            node.state = 'critical';
          } else if (alert.state === 'watch' && node.state !== 'critical') {
            node.state = 'watch';
          }
        }
      }
    }

    res.json(graph);
  } catch (err) {
    next(err);
  }
}

// ── GET /api/network/hosts/:id ──────────────────────────
export async function getHostDetails(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const hostIp = String(req.params.id);
    const scrub = req.query.scrub !== undefined && req.query.scrub !== '' ? Number(req.query.scrub) : undefined;
    const live = req.query.live === 'true' || scrub === undefined;

    // Get host detail from dashboardStore with scrub awareness
    const detail = dashboardStore.getHostDetail(hostIp, scrub, live);
    res.json(detail);
  } catch (err) {
    next(err);
  }
}
