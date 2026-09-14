import mongoose, { Schema, type Document } from 'mongoose';

export interface IDataSource {
  name: string;
  type: string;
  status: 'connected' | 'disconnected';
  note: string;
}

export interface INotificationPref {
  label: string;
  enabled: boolean;
}

export interface ISettings extends Document {
  orgId: mongoose.Types.ObjectId;
  modelConfig: {
    windowK: number;
    alertThreshold: number;
    retrainingSchedule: string;
  };
  dataSources: IDataSource[];
  notifications: INotificationPref[];
  integrations: {
    apiKeyHash: string;
    apiKeyLastFour: string;
    webhookUrl: string;
  };
}

const dataSourceSchema = new Schema<IDataSource>(
  {
    name: { type: String, required: true },
    type: {
      type: String,
      required: true,
      enum: ['PCAP', 'Network sensor', 'API', 'S3', 'IPFIX'],
    },
    status: {
      type: String,
      required: true,
      enum: ['connected', 'disconnected'],
    },
    note: { type: String, default: '' },
  },
  { _id: true },
);

const notificationSchema = new Schema<INotificationPref>(
  {
    label: { type: String, required: true },
    enabled: { type: Boolean, default: true },
  },
  { _id: false },
);

const settingsSchema = new Schema<ISettings>(
  {
    orgId: {
      type: Schema.Types.ObjectId,
      ref: 'Organisation',
      required: true,
      unique: true,
    },
    modelConfig: {
      windowK: { type: Number, required: true, min: 1, default: 8 },
      alertThreshold: { type: Number, required: true, min: 0, max: 1, default: 0.65 },
      retrainingSchedule: { type: String, default: 'nightly 02:00Z' },
    },
    dataSources: { type: [dataSourceSchema], default: [] },
    notifications: { type: [notificationSchema], default: [] },
    integrations: {
      apiKeyHash: { type: String, default: '' },
      apiKeyLastFour: { type: String, default: '' },
      webhookUrl: { type: String, default: '', trim: true },
    },
  },
  { timestamps: true },
);

export const Settings = mongoose.model<ISettings>('Settings', settingsSchema);
