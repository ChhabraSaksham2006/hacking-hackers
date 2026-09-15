import crypto from 'crypto';
import speakeasy from 'speakeasy';
import { User, type IUser } from '../models/User.js';
import { Organisation } from '../models/Organisation.js';
import { hashPassword, comparePassword, hashToken, compareToken } from '../utils/hash.js';
import {
  signAccessToken,
  signRefreshToken,
  verifyRefreshToken,
  signTwoFactorChallenge,
  verifyTwoFactorChallenge,
  type AccessTokenPayload,
} from '../utils/jwt.js';
import { AppError } from '../middleware/errorHandler.js';
import { ROLE_PERMISSIONS, type Role } from '../permissions/index.js';
import {
  sendVerificationEmail,
  sendPasswordResetEmail,
  sendTwoFactorCodeEmail,
} from './emailService.js';

// ── Single-use 2FA challenge tracking ───────────────────
// In-memory set of consumed jti values. Acceptable for single-instance MVP.
// For horizontal scaling, replace with a Redis SET with TTL.
const consumedChallengeJtis = new Set<string>();

// ── Types ───────────────────────────────────────────────

interface UserSummary {
  id: unknown;
  email: string;
  name: string;
  initials: string;
  role: string;
}

export type LoginResult =
  | { requiresTwoFactor: true; challengeId: string }
  | { requiresTwoFactor: false; accessToken: string; refreshToken: string; user: UserSummary };

// ── Registration ────────────────────────────────────────

export interface RegisterInput {
  orgName: string;
  email: string;
  password: string;
  name: string;
}

export async function registerUser(input: RegisterInput) {
  const existing = await User.findOne({ email: input.email });
  if (existing) {
    throw new AppError(409, 'An account with this email already exists');
  }

  // Create or find organisation transactionally (upsert)
  const org = await Organisation.findOneAndUpdate(
    { name: input.orgName },
    { $setOnInsert: { name: input.orgName } },
    { upsert: true, new: true }
  );

  const passwordHash = await hashPassword(input.password);
  const initials = input.name
    .split(' ')
    .map((n) => n[0])
    .join('')
    .toUpperCase()
    .slice(0, 2);

  // Generate email verification token
  const rawToken = crypto.randomBytes(32).toString('hex');
  const verificationHash = await hashToken(rawToken);

  const user = await User.create({
    email: input.email,
    passwordHash,
    name: input.name,
    initials,
    role: 'Analyst', // Public registration must always default to least privilege
    orgId: org._id,
    emailVerified: false,
    emailVerificationToken: verificationHash,
    emailVerificationExpires: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24h
  });

  // Send verification email (fire-and-forget)
  sendVerificationEmail(user.email, user.name, rawToken).catch((err) => {
    console.error('Failed to send verification email:', err);
  });

  return { user, org };
}

// ── Login ───────────────────────────────────────────────

export interface LoginInput {
  email: string;
  password: string;
}

export async function loginUser(input: LoginInput): Promise<LoginResult> {
  const user = await User.findOne({ email: input.email });
  if (!user) {
    throw new AppError(401, 'Invalid email or password');
  }

  const valid = await comparePassword(input.password, user.passwordHash);
  if (!valid) {
    throw new AppError(401, 'Invalid email or password');
  }

  // Require email verification before allowing login (bypass in test env)
  if (!user.emailVerified && process.env.NODE_ENV !== 'test') {
    throw new AppError(403, 'Please verify your email before logging in. Check your inbox for a verification link.');
  }

  if (user.twoFactorEnabled) {
    const challengeId = signTwoFactorChallenge({ userId: user._id.toString(), type: '2fa_challenge' });
    return { requiresTwoFactor: true, challengeId };
  }

  return issueTokens(user);
}

// ── 2FA Setup ───────────────────────────────────────────

export async function setupTwoFactor(userId: string) {
  const user = await User.findById(userId);
  if (!user) throw new AppError(404, 'User not found');

  const secret = speakeasy.generateSecret({
    name: `Aegis Vantage (${user.email})`,
    length: 20,
  });

  user.twoFactorSecret = secret.base32;
  await user.save();

  return {
    secret: secret.base32,
    otpAuthUrl: secret.otpauth_url,
  };
}

export async function verifyTwoFactor(challengeId: string, code: string): Promise<LoginResult> {
  let payload;
  try {
    payload = verifyTwoFactorChallenge(challengeId);
  } catch (err) {
    throw new AppError(401, 'Invalid or expired 2FA challenge');
  }

  // Single-use enforcement: reject replayed challenge tokens
  if (consumedChallengeJtis.has(payload.jti)) {
    throw new AppError(401, '2FA challenge has already been used');
  }
  consumedChallengeJtis.add(payload.jti);

  // Cleanup: remove jti after 5 minutes (matches token expiry)
  setTimeout(() => consumedChallengeJtis.delete(payload!.jti), 5 * 60 * 1000);

  const user = await User.findById(payload.userId);
  if (!user || !user.twoFactorSecret) {
    throw new AppError(400, 'Two-factor authentication is not set up');
  }

  const verified = speakeasy.totp.verify({
    secret: user.twoFactorSecret,
    encoding: 'base32',
    token: code,
    window: 1, // allow 30s clock drift
  });

  if (!verified) {
    throw new AppError(401, 'Invalid verification code');
  }

  // Enable 2FA on first successful verification
  if (!user.twoFactorEnabled) {
    user.twoFactorEnabled = true;
    await user.save();
  }

  return issueTokens(user);
}

// ── Token Refresh ───────────────────────────────────────

export async function refreshTokens(refreshTokenValue: string) {
  let payload;
  try {
    payload = verifyRefreshToken(refreshTokenValue);
  } catch {
    throw new AppError(401, 'Invalid or expired refresh token');
  }

  const user = await User.findById(payload.userId);
  if (!user) {
    throw new AppError(401, 'User not found');
  }

  // Find the matching token entry (including used ones)
  const tokenEntry = await findAndValidateRefreshToken(
    user,
    refreshTokenValue,
    true // includeUsed
  );

  if (!tokenEntry) {
    throw new AppError(401, 'Invalid or expired refresh token');
  }

  if (tokenEntry.usedAt) {
    // Token reuse detected in memory
    const familyId = tokenEntry.familyId;
    user.refreshTokens = user.refreshTokens.filter((t) => t.familyId !== familyId);
    await user.save();
    throw new AppError(401, 'Refresh token reuse detected — session revoked');
  }

  // Atomically mark the token as used to prevent concurrency bypass
  const updatedUser = await User.findOneAndUpdate(
    { 
      _id: user._id, 
      'refreshTokens.familyId': tokenEntry.familyId, 
      'refreshTokens.tokenHash': tokenEntry.tokenHash, 
      'refreshTokens.usedAt': { $exists: false } 
    },
    { $set: { 'refreshTokens.$.usedAt': new Date() } },
    { new: true }
  );

  if (!updatedUser) {
    // If not found, another concurrent request already rotated it. Reuse detected!
    const familyId = tokenEntry.familyId;
    user.refreshTokens = user.refreshTokens.filter((t) => t.familyId !== familyId);
    await user.save();
    throw new AppError(401, 'Refresh token reuse detected — session revoked');
  }

  // Issue new tokens in the same family using the updated user document
  const result = await issueTokens(updatedUser, tokenEntry.familyId);
  return result;
}

// ── Logout ──────────────────────────────────────────────

export async function logoutUser(userId: string) {
  await User.findByIdAndUpdate(userId, { refreshTokens: [] });
}

// ── Get Profile ─────────────────────────────────────────

export async function getUserProfile(userId: string) {
  const user = await User.findById(userId).select('-passwordHash -refreshTokens -twoFactorSecret');
  if (!user) throw new AppError(404, 'User not found');

  const org = await Organisation.findById(user.orgId);
  const permissions = ROLE_PERMISSIONS[user.role] ?? [];

  return {
    id: user._id,
    email: user.email,
    name: user.name,
    initials: user.initials,
    emailVerified: user.emailVerified,
    alertNotificationsEnabled: user.alertNotificationsEnabled,
    role: user.role,
    twoFactorEnabled: user.twoFactorEnabled,
    org: org ? { id: org._id, name: org.name } : null,
    permissions,
  };
}

// ── Internal Helpers ────────────────────────────────────

async function issueTokens(user: IUser, existingFamilyId?: string) {
  const accessPayload: AccessTokenPayload = {
    userId: user._id.toString(),
    email: user.email,
    role: user.role,
    orgId: user.orgId.toString(),
  };

  const tokenId = crypto.randomUUID();
  const familyId = existingFamilyId ?? crypto.randomUUID();
  const accessToken = signAccessToken(accessPayload);
  const refreshToken = signRefreshToken({ userId: user._id.toString(), tokenId });

  // Store hashed refresh token
  const tokenHash = await hashToken(refreshToken);
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

  // Clean up expired tokens
  user.refreshTokens = user.refreshTokens.filter(
    (t) => t.expiresAt > new Date()
  );
  
  // Add new token
  user.refreshTokens.push({ tokenHash, familyId, expiresAt });
  await user.save();

  return {
    requiresTwoFactor: false as const,
    accessToken,
    refreshToken,
    user: {
      id: user._id,
      email: user.email,
      name: user.name,
      initials: user.initials,
      role: user.role,
    },
  };
}

async function findAndValidateRefreshToken(
  user: IUser,
  rawToken: string,
  includeUsed = false
) {
  for (const entry of user.refreshTokens) {
    // Skip expired tokens
    if (entry.expiresAt < new Date()) continue;
    
    // Skip used tokens unless explicitly requested (to detect reuse)
    if (!includeUsed && entry.usedAt) continue;

    const match = await compareToken(rawToken, entry.tokenHash);
    if (match) return entry;
  }
  return null;
}

// ── Email Verification ──────────────────────────────────

export async function verifyEmail(token: string) {
  // We must scan all users with a pending verification since the token is hashed
  const users = await User.find({
    emailVerified: false,
    emailVerificationToken: { $exists: true, $ne: null },
    emailVerificationExpires: { $gt: new Date() },
  });

  for (const user of users) {
    const match = await compareToken(token, user.emailVerificationToken!);
    if (match) {
      user.emailVerified = true;
      user.emailVerificationToken = undefined;
      user.emailVerificationExpires = undefined;
      await user.save();
      return { email: user.email, name: user.name };
    }
  }

  throw new AppError(400, 'Invalid or expired verification link');
}

export async function resendVerificationEmail(email: string) {
  const user = await User.findOne({ email });
  if (!user) {
    // Don't reveal whether email exists
    return;
  }
  if (user.emailVerified) {
    throw new AppError(400, 'Email is already verified');
  }

  const rawToken = crypto.randomBytes(32).toString('hex');
  user.emailVerificationToken = await hashToken(rawToken);
  user.emailVerificationExpires = new Date(Date.now() + 24 * 60 * 60 * 1000);
  await user.save();

  await sendVerificationEmail(user.email, user.name, rawToken);
}

// ── Password Reset ──────────────────────────────────────

export async function requestPasswordReset(email: string) {
  const user = await User.findOne({ email });
  if (!user) {
    // Don't reveal whether email exists — return silently
    return;
  }

  const rawToken = crypto.randomBytes(32).toString('hex');
  user.passwordResetToken = await hashToken(rawToken);
  user.passwordResetExpires = new Date(Date.now() + 60 * 60 * 1000); // 1 hour
  await user.save();

  await sendPasswordResetEmail(user.email, user.name, rawToken);
}

export async function resetPassword(token: string, newPassword: string) {
  const users = await User.find({
    passwordResetToken: { $exists: true, $ne: null },
    passwordResetExpires: { $gt: new Date() },
  });

  for (const user of users) {
    const match = await compareToken(token, user.passwordResetToken!);
    if (match) {
      user.passwordHash = await hashPassword(newPassword);
      user.passwordResetToken = undefined;
      user.passwordResetExpires = undefined;
      // Also verify email if not already (they proved email ownership)
      user.emailVerified = true;
      user.emailVerificationToken = undefined;
      user.emailVerificationExpires = undefined;
      await user.save();
      return { email: user.email };
    }
  }

  throw new AppError(400, 'Invalid or expired reset link');
}

// ── Email-Based 2FA ─────────────────────────────────────

// In-memory store for email-based 2FA codes (single instance; use Redis for HA)
const email2faCodes = new Map<string, { code: string; expiresAt: number }>();

export async function sendTwoFactorEmailCode(userId: string) {
  const user = await User.findById(userId);
  if (!user) throw new AppError(404, 'User not found');

  const code = Math.floor(100000 + Math.random() * 900000).toString();
  email2faCodes.set(userId, { code, expiresAt: Date.now() + 5 * 60 * 1000 });

  // Cleanup after 5 min
  setTimeout(() => email2faCodes.delete(userId), 5 * 60 * 1000);

  await sendTwoFactorCodeEmail(user.email, user.name, code);
}

export function verifyEmail2FACode(userId: string, code: string): boolean {
  const entry = email2faCodes.get(userId);
  if (!entry) return false;
  if (Date.now() > entry.expiresAt) {
    email2faCodes.delete(userId);
    return false;
  }
  if (entry.code !== code) return false;
  email2faCodes.delete(userId); // single-use
  return true;
}

// ── Update Alert Notifications Preference ───────────────

export async function updateAlertNotifications(userId: string, enabled: boolean) {
  const user = await User.findById(userId);
  if (!user) throw new AppError(404, 'User not found');
  user.alertNotificationsEnabled = enabled;
  await user.save();
  return { alertNotificationsEnabled: user.alertNotificationsEnabled };
}
