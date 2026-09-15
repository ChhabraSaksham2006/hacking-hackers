import { Router } from 'express';
import { authenticate } from '../middleware/auth.js';
import { listNotifications, markAsRead, markAllAsRead } from '../controllers/notificationsController.js';

const router = Router();

router.use(authenticate);

router.get('/', listNotifications);
router.post('/mark-all-read', markAllAsRead);
router.patch('/:id/read', markAsRead);

export default router;
