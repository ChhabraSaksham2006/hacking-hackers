import mongoose, { Schema, type Document } from 'mongoose';

export interface IFeatureContribution {
  feature: string;
  value: string;
  weight: number;
}

export interface IPrediction extends Document {
  orgId: mongoose.Types.ObjectId;
  segmentId?: mongoose.Types.ObjectId;
  segmentName: string;
  windowStart: Date;
  windowEnd: Date;
  probability: number;
  stage: string;
  confidence: number;
  series: number[];
  featureContributions: IFeatureContribution[];
  summary: string;
  modelVersion: string;
  createdAt: Date;
}

const featureContributionSchema = new Schema<IFeatureContribution>(
  {
    feature: { type: String, required: true },
    value: { type: String, required: true },
    weight: { type: Number, required: true },
  },
  { _id: false },
);

const predictionSchema = new Schema<IPrediction>(
  {
    orgId: {
      type: Schema.Types.ObjectId,
      ref: 'Organisation',
      required: true,
    },
    segmentId: { type: Schema.Types.ObjectId, ref: 'Segment' },
    segmentName: { type: String, required: true },
    windowStart: { type: Date, required: true },
    windowEnd: { type: Date, required: true },
    probability: { type: Number, required: true, min: 0, max: 1 },
    stage: { type: String, required: true },
    confidence: { type: Number, required: true, min: 0, max: 1 },
    series: { type: [Number], default: [] },
    featureContributions: { type: [featureContributionSchema], default: [] },
    summary: { type: String, default: '' },
    modelVersion: { type: String, required: true },
  },
  { timestamps: { createdAt: true, updatedAt: false } },
);

predictionSchema.pre('validate', function (next) {
  if (this.windowEnd && this.windowStart && this.windowEnd < this.windowStart) {
    this.invalidate(
      'windowEnd',
      'windowEnd must be greater than or equal to windowStart',
    );
  }
  next();
});

predictionSchema.index({ orgId: 1, windowEnd: -1 });

export const Prediction = mongoose.model<IPrediction>(
  'Prediction',
  predictionSchema,
);
