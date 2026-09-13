import mongoose, { Schema, type Document } from 'mongoose';

export type RiskState = 'normal' | 'watch' | 'critical';
export type AlertStatus = 'New' | 'Acknowledged' | 'Investigating' | 'Resolved';

export interface IAlert extends Document {
  alertId: string;
  host: string;
  ip: string;
  stage: string;
  probability: number;
  state: RiskState;
  reason: string;
  detectedAt: Date;
  status: AlertStatus;
  assignedTo?: mongoose.Types.ObjectId;
  orgId: mongoose.Types.ObjectId;
  notes: string;
  createdAt: Date;
  updatedAt: Date;
}

const alertSchema = new Schema<IAlert>(
  {
    alertId: { type: String, required: true, unique: true },
    host: { type: String, required: true, trim: true },
    ip: { type: String, required: true, trim: true },
    stage: { type: String, required: true, trim: true },
    probability: {
      type: Number,
      required: true,
      min: 0,
      max: 1,
    },
    state: {
      type: String,
      required: true,
      enum: ['normal', 'watch', 'critical'],
    },
    reason: { type: String, required: true, trim: true },
    detectedAt: { type: Date, required: true },
    status: {
      type: String,
      required: true,
      enum: ['New', 'Acknowledged', 'Investigating', 'Resolved'],
      default: 'New',
    },
    assignedTo: { type: Schema.Types.ObjectId, ref: 'User' },
    orgId: {
      type: Schema.Types.ObjectId,
      ref: 'Organisation',
      required: true,
    },
    notes: { type: String, default: '' },
  },
  { timestamps: true },
);

alertSchema.index({ orgId: 1, status: 1 });
alertSchema.index({ orgId: 1, state: 1 });
alertSchema.index({ orgId: 1, detectedAt: -1 });

export const Alert = mongoose.model<IAlert>('Alert', alertSchema);
