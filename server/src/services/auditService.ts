import type { Request } from 'express';
import { AuditEntry } from '../models/AuditEntry.js';

export const AUDIT_EVENTS = [
  'ALERT_ACKNOWLEDGED',
  'ALERT_RESOLVED',
  'ALERT_INVESTIGATING',
  'ALERT_ASSIGNED',
  'INFERENCE_RUN',
  'MODEL_PROMOTED',
  'MODEL_ROLLED_BACK',
  'USER_CREATED',
  'USER_ROLE_CHANGED',
  'SETTINGS_UPDATED',
  'DATASOURCE_ADDED',
  'DATASOURCE_REMOVED',
  'API_KEY_ROTATED',
  'REPORT_GENERATED',
  'INGESTION_STARTED',
  'INGESTION_COMPLETED',
  'SIMULATION_RUN',
  'LOGIN_SUCCESS',
  'LOGIN_FAILED',
  'LOGOUT',
  'SEGMENT_ISOLATED',
  'SEGMENT_RESTORED',
] as const;

export type AuditEvent = (typeof AUDIT_EVENTS)[number];

/**
 * Log an explicit audit event.
 * Called from route handlers — not middleware — so we control exactly which
 * actions produce audit entries.
 * 
 * WARNING: Never put secrets (passwords, JWTs, refresh tokens, API keys, webhook secrets)
 * into the metadata field, as audit logs are generally queryable by admins.
 */
export async function logAuditEvent(
  event: AuditEvent,
  target: string,
  req: Request,
  metadata?: Record<string, unknown>,
): Promise<void> {
  try {
    const actorEmail =
      req.user?.email ||
      (typeof metadata?.actor === 'string' ? metadata.actor : undefined) ||
      (typeof req.body?.email === 'string' ? req.body.email : undefined) ||
      'system';

    const entry = await AuditEntry.create({
      timestamp: new Date(),
      actor: actorEmail,
      actorUserId: req.user?.userId,
      event,
      target,
      orgId: req.user?.orgId,
      ip: req.ip || req.socket?.remoteAddress,
      metadata,
    });

    if (entry.orgId) {
      import('../socket.js')
        .then(({ emitToOrg }) => {
          emitToOrg(entry.orgId!, 'audit_created', entry.toObject ? entry.toObject() : entry);
        })
        .catch(() => {});
    }
  } catch (err) {
    // Audit failures should never break the request
    console.error('Failed to write audit entry:', err);
  }
}

