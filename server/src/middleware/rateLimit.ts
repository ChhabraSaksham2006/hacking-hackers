import rateLimit from 'express-rate-limit';

/**
 * Rate-limit presets for Flow दृष्टि.
 *
 * These use the default in-memory store, which is appropriate for
 * single-instance deployments. Switch to `rate-limit-redis` when
 * scaling horizontally.
 */

/** Login endpoint: 10 attempts per 15 minutes per IP. */
export const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many login attempts. Please try again in 15 minutes.' },
});

/** 2FA verification: 5 attempts per 5 minutes per IP. */
export const twoFactorLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many verification attempts. Please try again in 5 minutes.' },
});

/** General API fallback: 100 requests per minute per IP. */
export const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Rate limit exceeded. Please slow down.' },
});
