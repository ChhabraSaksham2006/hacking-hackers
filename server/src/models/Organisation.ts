import mongoose, { Schema, type Document } from 'mongoose';
import crypto from 'crypto';

export interface ISensorInfo {
  sensorId: string;
  name: string;
  mode: 'tap' | 'live' | 'demo' | 'pcap';
  interface?: string;
  subnet?: string;
  status: 'online' | 'offline';
  lastHeartbeatAt?: Date;
  registeredAt: Date;
}

export interface IOrganisation extends Document {
  name: string;
  hosts: number;
  modelVersion: string;
  datasetAccess: string[];
  sensorApiKey: string;
  sensorSetupCompleted: boolean;
  monitoredSubnets: string[];
  activeSensors: ISensorInfo[];
  environmentType: 'enterprise' | 'cloud_vpc' | 'homelab' | 'evaluation';
  createdAt: Date;
}

const sensorInfoSchema = new Schema<ISensorInfo>(
  {
    sensorId: { type: String, required: true },
    name: { type: String, required: true },
    mode: { type: String, enum: ['tap', 'live', 'demo', 'pcap'], default: 'tap' },
    interface: { type: String, default: '' },
    subnet: { type: String, default: '' },
    status: { type: String, enum: ['online', 'offline'], default: 'offline' },
    lastHeartbeatAt: { type: Date },
    registeredAt: { type: Date, default: Date.now },
  },
  { _id: false },
);

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
    sensorApiKey: {
      type: String,
      default: () => `av_sec_${crypto.randomBytes(24).toString('hex')}`,
      index: true,
    },
    sensorSetupCompleted: { type: Boolean, default: false },
    monitoredSubnets: { type: [String], default: [] },
    activeSensors: { type: [sensorInfoSchema], default: [] },
    environmentType: {
      type: String,
      enum: ['enterprise', 'cloud_vpc', 'homelab', 'evaluation'],
      default: 'enterprise',
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
