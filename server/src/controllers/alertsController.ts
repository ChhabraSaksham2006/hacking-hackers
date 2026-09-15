import type { Request, Response, NextFunction } from 'express';
import { Alert } from '../models/Alert.js';
import { User } from '../models/User.js';
import { logAuditEvent } from '../services/auditService.js';
import { paginateQuery, paginatedResponse } from '../utils/pagination.js';

// ── GET /api/alerts ─────────────────────────────────────
export async function listAlerts(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const { page, limit, status, state, host } = req.query as any;
    const { skip } = paginateQuery({ page, limit });

    const filter: Record<string, unknown> = { orgId: req.user!.orgId };
    if (status) filter.status = status;
    if (state) filter.state = state;
    if (host) filter.host = { $regex: host, $options: 'i' };

    const [alerts, total] = await Promise.all([
      Alert.find(filter)
        .sort({ detectedAt: -1 })
        .skip(skip)
        .limit(limit)
        .populate('assignedTo', 'name initials email')
        .lean(),
      Alert.countDocuments(filter),
    ]);

    res.json(paginatedResponse(alerts, total, { page, limit }));
  } catch (err) {
    next(err);
  }
}

// ── GET /api/alerts/:id ─────────────────────────────────
export async function getAlertById(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const alert = await Alert.findOne({
      alertId: req.params.id,
      orgId: req.user!.orgId,
    })
      .populate('assignedTo', 'name initials email')
      .lean();

    if (!alert) {
      res.status(404).json({ error: 'Alert not found' });
      return;
    }
    res.json(alert);
  } catch (err) {
    next(err);
  }
}

// ── PATCH /api/alerts/:id ───────────────────────────────
export async function updateAlert(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const alert = await Alert.findOne({
      alertId: req.params.id,
      orgId: req.user!.orgId,
    });

    if (!alert) {
      res.status(404).json({ error: 'Alert not found' });
      return;
    }

    const oldStatus = alert.status;

    if (req.body.status) alert.status = req.body.status;

    if (req.body.assignedTo !== undefined) {
      if (req.body.assignedTo === null) {
        alert.assignedTo = undefined;
      } else {
        const targetUser = await User.findOne({
          _id: req.body.assignedTo,
          orgId: req.user!.orgId,
        });

        if (!targetUser) {
          res.status(400).json({ error: 'Invalid assignee or cross-organization assignment not permitted' });
          return;
        }
        alert.assignedTo = targetUser._id;
      }
    }

    if (req.body.notes !== undefined) alert.notes = req.body.notes;

    await alert.save();

    if (req.body.status && req.body.status !== oldStatus) {
      const metadata = { oldStatus, newStatus: req.body.status };
      if (req.body.status === 'Acknowledged') {
        await logAuditEvent('ALERT_ACKNOWLEDGED', alert.alertId, req, metadata);
      } else if (req.body.status === 'Resolved') {
        await logAuditEvent('ALERT_RESOLVED', alert.alertId, req, metadata);
      } else if (req.body.status === 'Investigating') {
        await logAuditEvent('ALERT_INVESTIGATING', alert.alertId, req, metadata);
      }
    }

    if (req.body.assignedTo !== undefined && req.body.assignedTo !== null) {
      await logAuditEvent('ALERT_ASSIGNED', alert.alertId, req, {
        assignedTo: req.body.assignedTo,
      });
    }

    import('../socket.js').then(({ emitToOrg }) => {
      emitToOrg(req.user!.orgId, 'alert_updated', alert);
    }).catch(err => console.error('Failed to emit alert_updated', err));

    res.json(alert);
  } catch (err) {
    next(err);
  }
}
