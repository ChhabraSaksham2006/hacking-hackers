import { Router } from 'express';
import { z } from 'zod';
import { validate } from '../middleware/validate.js';
import { authenticate } from '../middleware/auth.js';
import { loginLimiter, twoFactorLimiter } from '../middleware/rateLimit.js';
import { setAuthCookies, clearAuthCookies } from '../utils/jwt.js';
import { logAuditEvent } from '../services/auditService.js';
import {
  registerUser,
  loginUser,
  verifyTwoFactor,
  refreshTokens,
  logoutUser,
  getUserProfile,
  verifyEmail,
  resendVerificationEmail,
  requestPasswordReset,
  resetPassword,
  sendTwoFactorEmailCode,
  verifyEmail2FACode,
  updateAlertNotifications,
} from '../services/authService.js';

const router = Router();

// ── Schemas ─────────────────────────────────────────────

const registerSchema = z.object({
  orgName: z.string().min(1).max(200),
  email: z.string().email(),
  password: z.string().min(12, 'Password must be at least 12 characters'),
  name: z.string().min(1).max(100),
});

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1),
});

const verifyTwoFactorSchema = z.object({
  challengeId: z.string().min(1, 'Challenge ID is required'),
  code: z.string().regex(/^\d{6}$/, 'Code must be exactly 6 digits'),
});

// ── POST /api/auth/register ─────────────────────────────

router.post(
  '/register',
  validate({ body: registerSchema }),
  async (req, res, next) => {
    try {
      const { user, org } = await registerUser(req.body);

      await logAuditEvent('USER_CREATED', user.email, req, {
        role: user.role,
        org: org.name,
      });

      res.status(201).json({
        message: 'Account created. Please log in.',
        user: {
          id: user._id,
          email: user.email,
          name: user.name,
          role: user.role,
        },
      });
    } catch (err) {
      next(err);
    }
  },
);

// ── POST /api/auth/login ────────────────────────────────

router.post(
  '/login',
  loginLimiter,
  validate({ body: loginSchema }),
  async (req, res, next) => {
    try {
      const result = await loginUser(req.body);

      if (result.requiresTwoFactor) {
        await logAuditEvent('LOGIN_SUCCESS', req.body.email, req, {
          twoFactorPending: true,
        });
        res.json({
          requiresTwoFactor: true,
          challengeId: result.challengeId,
        });
        return;
      }

      setAuthCookies(res, result.accessToken, result.refreshToken);

      await logAuditEvent('LOGIN_SUCCESS', req.body.email, req);

      res.json({
        requiresTwoFactor: false,
        user: result.user,
      });
    } catch (err) {
      // Log failed login attempts
      if (req.body?.email) {
        await logAuditEvent('LOGIN_FAILED', req.body.email, req).catch(
          () => {},
        );
      }
      next(err);
    }
  },
);

// ── POST /api/auth/verify-2fa ───────────────────────────

router.post(
  '/verify-2fa',
  twoFactorLimiter,
  validate({ body: verifyTwoFactorSchema }),
  async (req, res, next) => {
    try {
      const result = await verifyTwoFactor(req.body.challengeId, req.body.code);

      if (result.requiresTwoFactor) {
        // Should never happen after 2FA verification, but satisfies type narrowing
        res.status(400).json({ error: 'Unexpected state' });
        return;
      }

      setAuthCookies(res, result.accessToken, result.refreshToken);

      await logAuditEvent('LOGIN_SUCCESS', result.user.email, req, {
        twoFactorVerified: true,
      });

      res.json({
        requiresTwoFactor: false,
        user: result.user,
      });
    } catch (err) {
      next(err);
    }
  },
);

// ── POST /api/auth/refresh ──────────────────────────────

router.post('/refresh', async (req, res, next) => {
  try {
    const refreshToken = req.cookies?.refresh_token as string | undefined;
    if (!refreshToken) {
      res.status(401).json({ error: 'No refresh token provided' });
      return;
    }

    const result = await refreshTokens(refreshToken);

    if (result.requiresTwoFactor) {
      res.status(400).json({ error: 'Unexpected 2FA state during refresh' });
      return;
    }

    setAuthCookies(res, result.accessToken, result.refreshToken);

    res.json({ user: result.user });
  } catch (err) {
    // Clear invalid cookies
    clearAuthCookies(res);
    next(err);
  }
});

// ── POST /api/auth/logout ───────────────────────────────

router.post('/logout', authenticate, async (req, res, next) => {
  try {
    await logoutUser(req.user!.userId);
    clearAuthCookies(res);

    await logAuditEvent('LOGOUT', req.user!.email, req);

    res.json({ message: 'Logged out' });
  } catch (err) {
    next(err);
  }
});

// ── GET /api/auth/me ────────────────────────────────────

router.get('/me', authenticate, async (req, res, next) => {
  try {
    const profile = await getUserProfile(req.user!.userId);
    res.json(profile);
  } catch (err) {
    next(err);
  }
});

// ── GET /api/auth/verify-email ──────────────────────────

const verifyEmailSchema = z.object({
  token: z.string().min(1, 'Token is required'),
});

router.get('/verify-email', async (req, res, next) => {
  try {
    const { token } = verifyEmailSchema.parse(req.query);
    const result = await verifyEmail(token);
    res.json({ message: 'Email verified successfully', email: result.email });
  } catch (err) {
    next(err);
  }
});

// ── POST /api/auth/resend-verification ──────────────────

const resendVerificationSchema = z.object({
  email: z.string().email(),
});

router.post(
  '/resend-verification',
  validate({ body: resendVerificationSchema }),
  async (req, res, next) => {
    try {
      await resendVerificationEmail(req.body.email);
      // Always return success to prevent email enumeration
      res.json({ message: 'If that email is registered and unverified, a verification link has been sent.' });
    } catch (err) {
      next(err);
    }
  },
);

// ── POST /api/auth/forgot-password ──────────────────────

const forgotPasswordSchema = z.object({
  email: z.string().email(),
});

router.post(
  '/forgot-password',
  loginLimiter,
  validate({ body: forgotPasswordSchema }),
  async (req, res, next) => {
    try {
      await requestPasswordReset(req.body.email);
      // Always return success to prevent email enumeration
      res.json({ message: 'If that email is registered, a password reset link has been sent.' });
    } catch (err) {
      next(err);
    }
  },
);

// ── POST /api/auth/reset-password ───────────────────────

const resetPasswordSchema = z.object({
  token: z.string().min(1, 'Token is required'),
  password: z.string().min(12, 'Password must be at least 12 characters'),
});

router.post(
  '/reset-password',
  validate({ body: resetPasswordSchema }),
  async (req, res, next) => {
    try {
      await resetPassword(req.body.token, req.body.password);
      res.json({ message: 'Password reset successfully. You can now log in.' });
    } catch (err) {
      next(err);
    }
  },
);

// ── POST /api/auth/send-2fa-email ───────────────────────

const send2faEmailSchema = z.object({
  challengeId: z.string().min(1, 'Challenge ID is required'),
});

router.post(
  '/send-2fa-email',
  twoFactorLimiter,
  validate({ body: send2faEmailSchema }),
  async (req, res, next) => {
    try {
      // Decode the challenge to get userId
      const { verifyTwoFactorChallenge: verifyChallenge } = await import('../utils/jwt.js');
      let payload;
      try {
        payload = verifyChallenge(req.body.challengeId);
      } catch {
        res.status(401).json({ error: 'Invalid or expired challenge' });
        return;
      }
      await sendTwoFactorEmailCode(payload.userId);
      res.json({ message: 'Verification code sent to your email.' });
    } catch (err) {
      next(err);
    }
  },
);

// ── PATCH /api/auth/alert-notifications ─────────────────

const alertNotifSchema = z.object({
  enabled: z.boolean(),
});

router.patch(
  '/alert-notifications',
  authenticate,
  validate({ body: alertNotifSchema }),
  async (req, res, next) => {
    try {
      const result = await updateAlertNotifications(req.user!.userId, req.body.enabled);
      res.json(result);
    } catch (err) {
      next(err);
    }
  },
);

export default router;
