import mongoose, { Schema, type Document } from 'mongoose';

export interface IFlow extends Document {
  src: string;
  dst: string;
  proto: string;
  flags: string;
  bytes: number;
  packets: number;
  duration: number;
  iatMean: number;
  iatVar: number;
  iatMax: number;
  ttlVar: number;
  window: number;
  retrans: number;
  score: number;
  ingestionId?: mongoose.Types.ObjectId;
  orgId: mongoose.Types.ObjectId;
  timestamp: Date;
  createdAt: Date;
}

const flowSchema = new Schema<IFlow>(
  {
    src: { type: String, required: true, trim: true },
    dst: { type: String, required: true, trim: true },
    proto: { type: String, required: true, trim: true },
    flags: { type: String, required: true, trim: true },
    bytes: { type: Number, required: true, min: 0 },
    packets: { type: Number, required: true, min: 0 },
    duration: { type: Number, required: true, min: 0 },
    iatMean: { type: Number, required: true, min: 0 },
    iatVar: { type: Number, required: true, min: 0 },
    iatMax: { type: Number, required: true, min: 0 },
    ttlVar: { type: Number, required: true, min: 0 },
    window: { type: Number, required: true, min: 0 },
    retrans: { type: Number, required: true, min: 0 },
    score: { type: Number, required: true, min: 0, max: 1 },
    ingestionId: { type: Schema.Types.ObjectId, ref: 'Ingestion' },
    orgId: {
      type: Schema.Types.ObjectId,
      ref: 'Organisation',
      required: true,
    },
    timestamp: { type: Date, required: true, default: Date.now },
  },
  { timestamps: { createdAt: true, updatedAt: false } },
);

flowSchema.index({ orgId: 1, score: -1 });
flowSchema.index({ orgId: 1, src: 1 });
flowSchema.index({ orgId: 1, timestamp: -1 });

export const Flow = mongoose.model<IFlow>('Flow', flowSchema);
