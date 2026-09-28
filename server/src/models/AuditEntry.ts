import mongoose, { Schema, type Document } from 'mongoose';
import type { AuditEvent } from '../services/auditService.js';

export interface IAuditEntry extends Document {
  timestamp: Date;
  actor: string;
  actorUserId?: mongoose.Types.ObjectId;
  event: AuditEvent;
  target: string;
  orgId?: mongoose.Types.ObjectId;
  ip?: string;
  metadata?: Record<string, unknown>;
}

const auditEntrySchema = new Schema<IAuditEntry>(
  {
    timestamp: { type: Date, required: true, default: Date.now },
    actor: { type: String, required: true },
    actorUserId: { type: Schema.Types.ObjectId, ref: 'User' },
    event: { type: String, required: true },
    target: { type: String, required: true },
    orgId: { type: Schema.Types.ObjectId, ref: 'Organisation' },
    ip: { type: String },
    metadata: { type: Schema.Types.Mixed },
  },
  {
    timestamps: false, // we manage timestamp explicitly
  },
);

auditEntrySchema.index({ orgId: 1, timestamp: -1 });
auditEntrySchema.index({ orgId: 1, event: 1 });

// TTL index: auto-delete audit entries after 30 days
auditEntrySchema.index({ timestamp: 1 }, { expireAfterSeconds: 30 * 24 * 60 * 60 });

export const AuditEntry = mongoose.model<IAuditEntry>(
  'AuditEntry',
  auditEntrySchema,
);
