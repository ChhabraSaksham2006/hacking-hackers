import mongoose, { Schema, type Document } from 'mongoose';
import type { RiskState } from './Alert.js';

export interface ISegment extends Document {
  name: string;
  hosts: number;
  activeAlerts: number;
  trafficVolume: number;
  state: RiskState;
  lastIncident: string;
  orgId: mongoose.Types.ObjectId;
  isolated?: boolean;
  throughputMbps?: number;
  sparkline?: number[];
  description?: string;
}

const segmentSchema = new Schema<ISegment>(
  {
    name: { type: String, required: true, trim: true },
    hosts: { type: Number, required: true, min: 0 },
    activeAlerts: { type: Number, default: 0, min: 0 },
    trafficVolume: { type: Number, required: true, min: 0 },
    state: {
      type: String,
      required: true,
      enum: ['normal', 'watch', 'critical'],
    },
    lastIncident: { type: String, default: '—' },
    isolated: { type: Boolean, default: false },
    throughputMbps: { type: Number, default: 0 },
    sparkline: { type: [Number], default: [] },
    description: { type: String, default: '' },
    orgId: {
      type: Schema.Types.ObjectId,
      ref: 'Organisation',
      required: true,
    },
  },
  { timestamps: true },
);

segmentSchema.index({ orgId: 1, name: 1 }, { unique: true });

export const Segment = mongoose.model<ISegment>('Segment', segmentSchema);
