import type { Request, Response, NextFunction } from 'express';
import { roleHasPermission, type Permission } from '../permissions/index.js';
import { AppError } from './errorHandler.js';

/**
 * Permission-based access control middleware.
 * Checks that the authenticated user's role grants the required permission.
 *
 * Usage: requirePermission('alerts.update')
 */
export function requirePermission(permission: Permission) {
  return (req: Request, _res: Response, next: NextFunction): void => {
    if (!req.user) {
      return next(new AppError(401, 'Authentication required'));
    }

    if (!roleHasPermission(req.user.role, permission)) {
      return next(new AppError(
        403,
        `Permission denied: ${permission} is not granted to role ${req.user.role}`,
      ));
    }

    return next();
  };
}
