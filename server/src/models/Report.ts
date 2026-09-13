import mongoose, { Schema, type Document } from 'mongoose';

export interface IReport extends Document {
  name: string;
  scope: string;
  format: 'PDF' | 'CSV';
  timeWindow: { start: Date; end: Date };
  segmentOrAlert: string;
  storagePath: string;
  fileSize: number;
  orgId: mongoose.Types.ObjectId;
  createdBy: mongoose.Types.ObjectId;
  status: 'generating' | 'complete' | 'failed';
  errorMessage?: string;
  createdAt: Date;
}

const reportSchema = new Schema<IReport>(
  {
    name: { type: String, required: true },
    scope: { type: String, required: true },
    format: { type: String, required: true, enum: ['PDF', 'CSV'] },
    timeWindow: {
      start: { type: Date, required: true },
      end: { type: Date, required: true },
    },
    segmentOrAlert: { type: String, default: '' },
    storagePath: { type: String, default: '' },
    fileSize: { type: Number, default: 0, min: 0 },
    orgId: {
      type: Schema.Types.ObjectId,
      ref: 'Organisation',
      required: true,
    },
    createdBy: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    status: {
      type: String,
      required: true,
      enum: ['generating', 'complete', 'failed'],
      default: 'generating',
    },
    errorMessage: { type: String, trim: true },
  },
  { timestamps: { createdAt: true, updatedAt: false } },
);

reportSchema.index({ orgId: 1, createdAt: -1 });

export const Report = mongoose.model<IReport>('Report', reportSchema);
