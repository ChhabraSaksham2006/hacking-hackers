import type { Request, Response, NextFunction } from 'express';
import { verifyAccessToken, type AccessTokenPayload } from '../utils/jwt.js';
import { AppError } from './errorHandler.js';

// Extend Express Request to include user
declare global {
  namespace Express {
    interface Request {
      user?: AccessTokenPayload;
    }
  }
}

/**
 * Authenticate middleware — reads the access_token from httpOnly cookie,
 * verifies it, and attaches the decoded payload to req.user.
 */
export function authenticate(
  req: Request,
  _res: Response,
  next: NextFunction,
): void {
  const token = req.cookies?.access_token as string | undefined;

  if (!token) {
    return next(new AppError(401, 'Authentication required'));
  }

  try {
    const payload = verifyAccessToken(token);
    req.user = payload;
    return next();
  } catch {
    return next(new AppError(401, 'Invalid or expired access token'));
  }
}
