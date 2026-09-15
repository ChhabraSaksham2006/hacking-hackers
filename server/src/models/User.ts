import mongoose, { Schema, type Document } from 'mongoose';
import { type Role, ROLES } from '../permissions/index.js';

export interface IRefreshToken {
  tokenHash: string;
  familyId: string;
  expiresAt: Date;
  usedAt?: Date;
}

export interface IUser extends Document {
  email: string;
  passwordHash: string;
  name: string;
  initials: string;
  role: Role;
  orgId: mongoose.Types.ObjectId;
  twoFactorSecret?: string;
  twoFactorEnabled: boolean;
  emailVerified: boolean;
  emailVerificationToken?: string;
  emailVerificationExpires?: Date;
  passwordResetToken?: string;
  passwordResetExpires?: Date;
  alertNotificationsEnabled: boolean;
  refreshTokens: IRefreshToken[];
  createdAt: Date;
  updatedAt: Date;
}

const refreshTokenSchema = new Schema<IRefreshToken>(
  {
    tokenHash: { type: String, required: true },
    familyId: { type: String, required: true },
    expiresAt: { type: Date, required: true },
    usedAt: { type: Date },
  },
  { _id: false },
);

const userSchema = new Schema<IUser>(
  {
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
    },
    passwordHash: { type: String, required: true },
    name: { type: String, required: true, trim: true },
    initials: { type: String, required: true, trim: true, maxlength: 3 },
    role: {
      type: String,
      required: true,
      enum: ROLES,
      default: 'Analyst',
    },
    orgId: {
      type: Schema.Types.ObjectId,
      ref: 'Organisation',
      required: true,
    },
    twoFactorSecret: { type: String },
    twoFactorEnabled: { type: Boolean, default: false },
    emailVerified: { type: Boolean, default: false },
    emailVerificationToken: { type: String },
    emailVerificationExpires: { type: Date },
    passwordResetToken: { type: String },
    passwordResetExpires: { type: Date },
    alertNotificationsEnabled: { type: Boolean, default: false },
    refreshTokens: { type: [refreshTokenSchema], default: [] },
  },
  {
    timestamps: true,
  },
);

// Index for looking up users by org
userSchema.index({ orgId: 1 });

export const User = mongoose.model<IUser>('User', userSchema);
