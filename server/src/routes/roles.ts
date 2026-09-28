import { Router } from 'express';
import { authenticate } from '../middleware/auth.js';
import { requirePermission } from '../middleware/rbac.js';
import { User } from '../models/User.js';
import { ROLES, Role, PERMISSIONS, ROLE_PERMISSIONS } from '../permissions/index.js';
import { logAuditEvent } from '../services/auditService.js';
import { z } from 'zod';
import { validate } from '../middleware/validate.js';
import crypto from 'crypto';
import { hashPassword } from '../utils/hash.js';

const router = Router();
router.use(authenticate);

// ── GET /api/roles/matrix ───────────────────────────────

router.get('/matrix', (_req, res) => {
  res.json({
    roles: ROLES,
    permissions: PERMISSIONS,
    rolePermissions: ROLE_PERMISSIONS,
  });
});

// ── GET /api/roles/users ────────────────────────────────

router.get('/users', async (req, res, next) => {
  try {
    const users = await User.find({ orgId: req.user!.orgId })
      .select('-passwordHash -refreshTokens -twoFactorSecret')
      .lean();
    res.json(users);
  } catch (err) {
    next(err);
  }
});

// ── POST /api/roles/users ───────────────────────────────
// Allows Admins and SOC Leads to add new people to their team

const createUserSchema = z.object({
  name: z.string().min(1, 'Name is required').max(100),
  email: z.string().email('Invalid email address'),
  role: z.enum(ROLES).default('Analyst'),
  password: z.string().min(8, 'Password must be at least 8 characters').optional(),
});

router.post(
  '/users',
  requirePermission('users.create'),
  validate({ body: createUserSchema }),
  async (req, res, next) => {
    try {
      const { name, email, role, password } = req.body as {
        name: string;
        email: string;
        role: Role;
        password?: string;
      };

      const normalizedEmail = email.toLowerCase().trim();

      // Role hierarchy enforcement:
      // - Non-Super Admins cannot create Super Admins
      if (req.user!.role !== 'Super Admin' && role === 'Super Admin') {
        res.status(403).json({ error: 'Only Super Admins can assign the Super Admin role' });
        return;
      }

      // - SOC Leads can only add Analysts or SOC Leads
      if (req.user!.role === 'SOC Lead' && role !== 'Analyst' && role !== 'SOC Lead') {
        res.status(403).json({ error: 'SOC Leads can only add Analysts or SOC Leads' });
        return;
      }

      const existing = await User.findOne({ email: normalizedEmail });
      if (existing) {
        res.status(409).json({ error: 'A user with this email address already exists' });
        return;
      }

      // If no password provided, generate a secure temporary password
      const tempPassword = password || `Temp#${crypto.randomBytes(4).toString('hex')}!Aa`;
      const passwordHash = await hashPassword(tempPassword);

      const initials =
        name
          .trim()
          .split(/\s+/)
          .map((n) => n[0])
          .join('')
          .toUpperCase()
          .slice(0, 2) || 'TM';

      const newUser = await User.create({
        name: name.trim(),
        email: normalizedEmail,
        passwordHash,
        initials,
        role,
        orgId: req.user!.orgId,
        emailVerified: true,
      });

      await logAuditEvent('USER_CREATED', newUser.email, req, {
        createdUserId: newUser._id.toString(),
        name: newUser.name,
        role: newUser.role,
        addedBy: req.user!.email,
        addedByRole: req.user!.role,
      });

      const safeUser = {
        _id: newUser._id,
        id: newUser._id,
        email: newUser.email,
        name: newUser.name,
        initials: newUser.initials,
        role: newUser.role,
        orgId: newUser.orgId,
        createdAt: newUser.createdAt,
      };

      res.status(201).json({
        message: `Team member ${newUser.name} added successfully`,
        user: safeUser,
        temporaryPassword: password ? undefined : tempPassword,
      });
    } catch (err) {
      next(err);
    }
  },
);

// ── POST /api/roles/demo-switch ─────────────────────────
// Enables seamless persona testing (Analyst vs SOC Lead vs Admin vs Super Admin)

const updateRoleSchema = z.object({
  role: z.enum(ROLES),
});

router.post(
  '/demo-switch',
  validate({ body: updateRoleSchema }),
  async (req, res, next) => {
    try {
      const { role } = req.body as { role: Role };
      const user = await User.findById(req.user!.userId);
      if (!user) {
        res.status(404).json({ error: 'User not found' });
        return;
      }

      const oldRole = user.role;
      user.role = role;
      await user.save();

      const { setAuthCookies, signAccessToken, signRefreshToken } = await import('../utils/jwt.js');
      const accessPayload = {
        userId: user._id.toString(),
        email: user.email,
        role,
        orgId: user.orgId.toString(),
      };
      const accessToken = signAccessToken(accessPayload);
      const refreshToken = signRefreshToken({ userId: user._id.toString(), tokenId: crypto.randomUUID() });
      setAuthCookies(res, accessToken, refreshToken);

      await logAuditEvent('USER_ROLE_CHANGED', user._id.toString(), req, {
        oldRole,
        newRole: role,
        mode: 'demo_role_switcher',
      });

      res.json({
        message: `Role switched to ${role}`,
        user: {
          id: user._id,
          email: user.email,
          name: user.name,
          initials: user.initials,
          role: user.role,
          orgId: user.orgId,
        },
      });
    } catch (err) {
      next(err);
    }
  },
);

// ── PATCH /api/roles/users/:id ──────────────────────────

const userIdSchema = z.object({
  id: z.string().regex(/^[0-9a-fA-F]{24}$/, 'Invalid user ID'),
});

router.patch(
  '/users/:id',
  requirePermission('users.manage'),
  validate({ params: userIdSchema, body: updateRoleSchema }),
  async (req, res, next) => {
    try {
      const { role } = req.body as { role: Role };
      
      const targetUser = await User.findOne({ _id: req.params.id, orgId: req.user!.orgId });
      if (!targetUser) {
        res.status(404).json({ error: 'User not found' });
        return;
      }

      // Prevent privilege escalation by non-Super Admins
      if (req.user!.role !== 'Super Admin' && role === 'Super Admin') {
        res.status(403).json({ error: 'Only Super Admins can assign the Super Admin role' });
        return;
      }

      // Prevent self-role modification
      if (targetUser._id.toString() === req.user!.userId) {
        res.status(403).json({ error: 'You cannot change your own role' });
        return;
      }

      const oldRole = targetUser.role;
      targetUser.role = role;
      await targetUser.save();

      await logAuditEvent('USER_ROLE_CHANGED', targetUser._id.toString(), req, {
        oldRole,
        newRole: role,
      });

      const safeUser = {
        id: targetUser._id,
        email: targetUser.email,
        name: targetUser.name,
        initials: targetUser.initials,
        role: targetUser.role,
        orgId: targetUser.orgId,
      };

      res.json({ message: 'Role updated', user: safeUser });
    } catch (err) {
      next(err);
    }
  },
);

export default router;
