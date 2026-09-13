import mongoose, { Schema, type Document } from 'mongoose';

export interface IPipelineStep {
  name: string;
  status: 'pending' | 'running' | 'done' | 'failed';
  startedAt?: Date;
  completedAt?: Date;
}

export interface IIngestion extends Document {
  filename: string;
  datasetType: 'CIC-IDS-2018' | 'CTU-13' | 'Custom upload';
  fileSize: number;
  storagePath: string;
  orgId: mongoose.Types.ObjectId;
  uploadedBy: mongoose.Types.ObjectId;
  status: 'uploading' | 'parsing' | 'extracting' | 'normalizing' | 'inferring' | 'explaining' | 'complete' | 'failed';
  pipelineSteps: IPipelineStep[];
  flowsExtracted: number;
  predictionsGenerated: number;
  errorMessage?: string;
  createdAt: Date;
  updatedAt: Date;
}

const pipelineStepSchema = new Schema<IPipelineStep>(
  {
    name: { type: String, required: true },
    status: {
      type: String,
      required: true,
      enum: ['pending', 'running', 'done', 'failed'],
      default: 'pending',
    },
    startedAt: { type: Date },
    completedAt: { type: Date },
  },
  { _id: false },
);

const ingestionSchema = new Schema<IIngestion>(
  {
    filename: { type: String, required: true },
    datasetType: {
      type: String,
      required: true,
      enum: ['CIC-IDS-2018', 'CTU-13', 'Custom upload'],
    },
    fileSize: { type: Number, required: true, min: 0 },
    storagePath: { type: String, default: '' },
    orgId: {
      type: Schema.Types.ObjectId,
      ref: 'Organisation',
      required: true,
    },
    uploadedBy: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    status: {
      type: String,
      required: true,
      enum: ['uploading', 'parsing', 'extracting', 'normalizing', 'inferring', 'explaining', 'complete', 'failed'],
      default: 'uploading',
    },
    pipelineSteps: {
      type: [pipelineStepSchema],
      default: [
        { name: 'Parsing', status: 'pending' },
        { name: 'Feature extraction', status: 'pending' },
        { name: 'Normalisation', status: 'pending' },
        { name: 'Inference', status: 'pending' },
        { name: 'Explanation', status: 'pending' },
      ],
    },
    flowsExtracted: { type: Number, default: 0 },
    predictionsGenerated: { type: Number, default: 0 },
    errorMessage: { type: String, trim: true },
  },
  { timestamps: true },
);

ingestionSchema.index({ orgId: 1, createdAt: -1 });
ingestionSchema.index({ orgId: 1, status: 1, createdAt: -1 });

export const Ingestion = mongoose.model<IIngestion>('Ingestion', ingestionSchema);
