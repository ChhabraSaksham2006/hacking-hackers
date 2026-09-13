import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import type { Response } from 'express';
import { env } from '../config/env.js';

import type { Role } from '../permissions/index.js';

export interface AccessTokenPayload {
  userId: string;
  email: string;
  role: Role;
  orgId: string;
}

export interface RefreshTokenPayload {
  userId: string;
  tokenId: string; // unique per refresh token for rotation tracking
}

export interface TwoFactorChallengePayload {
  userId: string;
  type: '2fa_challenge';
  jti: string;
}

/** Parses simple duration strings (like '15m' or '7d') into milliseconds. */
function parseDurationMs(duration: string): number {
  const match = duration.match(/^(\d+)([smhd])$/);
  if (!match) return parseInt(duration) || 0;
  const value = parseInt(match[1]);
  const unit = match[2];
  switch (unit) {
    case 's': return value * 1000;
    case 'm': return value * 60 * 1000;
    case 'h': return value * 60 * 60 * 1000;
    case 'd': return value * 24 * 60 * 60 * 1000;
    default: return value;
  }
}

/** Sign a short-lived access token (15m default). */
export function signAccessToken(payload: AccessTokenPayload): string {
  return jwt.sign(payload, env.JWT_SECRET, {
    expiresIn: env.JWT_ACCESS_EXPIRY as jwt.SignOptions['expiresIn'],
  });
}

/** Sign a long-lived refresh token (7d default). */
export function signRefreshToken(payload: RefreshTokenPayload): string {
  return jwt.sign(payload, env.JWT_REFRESH_SECRET, {
    expiresIn: env.JWT_REFRESH_EXPIRY as jwt.SignOptions['expiresIn'],
  });
}

/** Verify and decode an access token. */
export function verifyAccessToken(token: string): AccessTokenPayload {
  return jwt.verify(token, env.JWT_SECRET) as AccessTokenPayload;
}

/** Verify and decode a refresh token. */
export function verifyRefreshToken(token: string): RefreshTokenPayload {
  return jwt.verify(token, env.JWT_REFRESH_SECRET) as RefreshTokenPayload;
}

/** Sign a short-lived 2FA challenge token (5m) with a unique jti. */
export function signTwoFactorChallenge(payload: Omit<TwoFactorChallengePayload, 'jti'>): string {
  const jti = crypto.randomUUID();
  return jwt.sign({ ...payload, jti }, env.JWT_2FA_CHALLENGE_SECRET, { expiresIn: '5m' });
}

/** Verify a 2FA challenge token. */
export function verifyTwoFactorChallenge(token: string): TwoFactorChallengePayload {
  const decoded = jwt.verify(token, env.JWT_2FA_CHALLENGE_SECRET) as TwoFactorChallengePayload;
  if (decoded.type !== '2fa_challenge') {
    throw new Error('Invalid token type');
  }
  return decoded;
}

/** Set both access and refresh tokens as httpOnly cookies on the response. */
export function setAuthCookies(
  res: Response,
  accessToken: string,
  refreshToken: string,
): void {
  const isProduction = env.NODE_ENV === 'production';

  res.cookie('access_token', accessToken, {
    httpOnly: true,
    secure: isProduction,
    sameSite: 'strict',
    maxAge: parseDurationMs(env.JWT_ACCESS_EXPIRY),
    path: '/',
  });

  res.cookie('refresh_token', refreshToken, {
    httpOnly: true,
    secure: isProduction,
    sameSite: 'strict',
    maxAge: parseDurationMs(env.JWT_REFRESH_EXPIRY),
    path: '/api/auth', // only sent to auth endpoints
  });
}

/** Clear auth cookies on logout. */
export function clearAuthCookies(res: Response): void {
  res.clearCookie('access_token', { path: '/' });
  res.clearCookie('refresh_token', { path: '/api/auth' });
}
