import type { Request, Response, NextFunction } from 'express';
import { Notification } from '../models/Notification.js';

export async function listNotifications(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const notifications = await Notification.find({
      orgId: req.user!.orgId,
      $or: [{ userId: req.user!.userId }, { userId: { $exists: false } }],
    })
      .sort({ createdAt: -1 })
      .limit(50)
      .lean();

    res.json(notifications);
  } catch (err) {
    next(err);
  }
}

export async function markAsRead(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const notification = await Notification.findOneAndUpdate(
      {
        _id: req.params.id,
        orgId: req.user!.orgId,
        $or: [{ userId: req.user!.userId }, { userId: { $exists: false } }],
      },
      { isRead: true },
      { new: true }
    );

    if (!notification) {
      res.status(404).json({ error: 'Notification not found' });
      return;
    }

    res.json(notification);
  } catch (err) {
    next(err);
  }
}

export async function markAllAsRead(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    await Notification.updateMany(
      {
        orgId: req.user!.orgId,
        $or: [{ userId: req.user!.userId }, { userId: { $exists: false } }],
        isRead: false,
      },
      { isRead: true }
    );

    res.json({ success: true });
  } catch (err) {
    next(err);
  }
}
