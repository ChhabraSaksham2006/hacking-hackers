import mongoose, { Schema, type Document } from 'mongoose';

export interface INotification extends Document {
  orgId: mongoose.Types.ObjectId;
  userId?: mongoose.Types.ObjectId; // if omitted, applies to all users in the org
  type: string; // e.g. 'alert_created', 'alert_updated'
  title: string;
  message: string;
  severity: 'info' | 'warning' | 'critical';
  alertId?: string;
  isRead: boolean;
  createdAt: Date;
  updatedAt: Date;
}

const notificationSchema = new Schema<INotification>(
  {
    orgId: { type: Schema.Types.ObjectId, ref: 'Organisation', required: true },
    userId: { type: Schema.Types.ObjectId, ref: 'User' },
    type: { type: String, required: true },
    title: { type: String, required: true },
    message: { type: String, required: true },
    severity: { type: String, enum: ['info', 'warning', 'critical'], default: 'info' },
    alertId: { type: String },
    isRead: { type: Boolean, default: false },
  },
  {
    timestamps: true,
  }
);

// Index to quickly fetch a user's notifications in an org
notificationSchema.index({ orgId: 1, userId: 1, isRead: 1 });

export const Notification = mongoose.model<INotification>('Notification', notificationSchema);
