import mongoose, { Schema, type Document } from 'mongoose';

export interface IDivergencePoint {
  step: string;
  predicted: number;
  observed: number;
}

export interface ISimulation extends Document {
  orgId: mongoose.Types.ObjectId;
  segmentName: string;
  perturbation: string;
  baseState: {
    hosts: number;
    flows: number;
    probability: number;
  };
  forecastSeries: number[];
  actualSeries: number[];
  divergence: IDivergencePoint[];
  steps: number;
  status: 'running' | 'complete' | 'failed';
  errorMessage?: string;
  createdAt: Date;
}

const divergenceSchema = new Schema<IDivergencePoint>(
  {
    step: { type: String, required: true },
    predicted: { type: Number, required: true },
    observed: { type: Number, required: true },
  },
  { _id: false },
);

const simulationSchema = new Schema<ISimulation>(
  {
    orgId: {
      type: Schema.Types.ObjectId,
      ref: 'Organisation',
      required: true,
    },
    segmentName: { type: String, required: true },
    perturbation: { type: String, required: true },
    baseState: {
      hosts: { type: Number, required: true, min: 0 },
      flows: { type: Number, required: true, min: 0 },
      probability: { type: Number, required: true, min: 0, max: 1 },
    },
    forecastSeries: { type: [Number], default: [] },
    actualSeries: { type: [Number], default: [] },
    divergence: { type: [divergenceSchema], default: [] },
    steps: { type: Number, required: true, min: 1 },
    status: {
      type: String,
      required: true,
      enum: ['running', 'complete', 'failed'],
      default: 'running',
    },
    errorMessage: { type: String, trim: true },
  },
  { timestamps: { createdAt: true, updatedAt: false } },
);

simulationSchema.index({ orgId: 1, createdAt: -1 });

export const Simulation = mongoose.model<ISimulation>(
  'Simulation',
  simulationSchema,
);
