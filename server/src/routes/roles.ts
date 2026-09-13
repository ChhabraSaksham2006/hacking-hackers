import { Router } from 'express';
import { authenticate } from '../middleware/auth.js';
import { requirePermission } from '../middleware/rbac.js';
import { User } from '../models/User.js';
import { ROLES, Role } from '../permissions/index.js';
import { logAuditEvent } from '../services/auditService.js';
import { z } from 'zod';
import { validate } from '../middleware/validate.js';

const router = Router();
router.use(authenticate, requirePermission('users.manage'));

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

// ── PATCH /api/roles/users/:id ──────────────────────────

const updateRoleSchema = z.object({
  role: z.enum(ROLES),
});

const userIdSchema = z.object({
  id: z.string().regex(/^[0-9a-fA-F]{24}$/, 'Invalid user ID'),
});

router.patch(
  '/users/:id',
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
