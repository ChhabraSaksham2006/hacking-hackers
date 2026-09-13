import mongoose, { Schema, type Document } from 'mongoose';

export interface IOrganisation extends Document {
  name: string;
  hosts: number;
  modelVersion: string;
  datasetAccess: string[];
  createdAt: Date;
}

const organisationSchema = new Schema<IOrganisation>(
  {
    name: { type: String, required: true, unique: true, trim: true },
    hosts: { type: Number, default: 0 },
    modelVersion: { type: String, default: 'wm-v4.2.1' },
    datasetAccess: {
      type: [String],
      enum: ['CIC-IDS-2018', 'CTU-13', 'Custom upload'],
      default: ['CIC-IDS-2018', 'CTU-13'],
    },
  },
  {
    timestamps: { createdAt: true, updatedAt: false },
  },
);

export const Organisation = mongoose.model<IOrganisation>(
  'Organisation',
  organisationSchema,
);
