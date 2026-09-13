import mongoose, { Schema, type Document } from 'mongoose';

export interface IModelVersion extends Document {
  version: string;
  releasedAt: Date;
  metrics: {
    cicIds: { f1: number; precision: number; recall: number; fpr: number };
    ctu13: { f1: number; precision: number; recall: number; fpr: number };
  };
  confusionMatrices: {
    cicIds: { cells: number[] };
    ctu13: { cells: number[] };
  };
  lossCurve: {
    train: number[];
    val: number[];
  };
  note: string;
  isProduction: boolean;
  promotedBy?: mongoose.Types.ObjectId;
  createdAt: Date;
}

const metricsSubSchema = new Schema(
  {
    f1: { type: Number, required: true, min: 0, max: 1 },
    precision: { type: Number, required: true, min: 0, max: 1 },
    recall: { type: Number, required: true, min: 0, max: 1 },
    fpr: { type: Number, required: true, min: 0, max: 1 },
  },
  { _id: false },
);

const modelVersionSchema = new Schema<IModelVersion>(
  {
    version: { type: String, required: true, unique: true },
    releasedAt: { type: Date, required: true },
    metrics: {
      cicIds: { type: metricsSubSchema, required: true },
      ctu13: { type: metricsSubSchema, required: true },
    },
    confusionMatrices: {
      cicIds: {
        cells: {
          type: [Number],
          required: true,
          validate: {
            validator: (cells: number[]) => cells.length === 4,
            message: 'Confusion matrix must contain exactly 4 cells',
          },
        },
      },
      ctu13: {
        cells: {
          type: [Number],
          required: true,
          validate: {
            validator: (cells: number[]) => cells.length === 4,
            message: 'Confusion matrix must contain exactly 4 cells',
          },
        },
      },
    },
    lossCurve: {
      train: { type: [Number], default: [] },
      val: { type: [Number], default: [] },
    },
    note: { type: String, default: '' },
    isProduction: { type: Boolean, default: false },
    promotedBy: { type: Schema.Types.ObjectId, ref: 'User' },
  },
  { timestamps: { createdAt: true, updatedAt: false } },
);

modelVersionSchema.index(
  { isProduction: 1 },
  {
    unique: true,
    partialFilterExpression: { isProduction: true },
  },
);

export const ModelVersion = mongoose.model<IModelVersion>(
  'ModelVersion',
  modelVersionSchema,
);
