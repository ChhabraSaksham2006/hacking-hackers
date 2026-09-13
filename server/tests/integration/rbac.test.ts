import { describe, it, expect, beforeEach } from 'vitest';
import request from 'supertest';
import app from '../../src/index';

describe('RBAC & Authorization', () => {
  let analystCookies: string[];
  let adminCookies: string[];

  beforeEach(async () => {
    // 1. Create Analyst
    await request(app).post('/api/auth/register').send({
      orgName: 'Shield',
      email: 'analyst@shield.com',
      password: 'Password123!',
      name: 'Analyst User',
    });

    const analystLogin = await request(app).post('/api/auth/login').send({
      email: 'analyst@shield.com',
      password: 'Password123!',
    });
    analystCookies = analystLogin.headers['set-cookie'] as unknown as string[];

    // 2. We need an Admin. Since registration forces Analyst, we must manually elevate.
    // In a real test we might just create the user via mongoose directly,
    // but we can also use mongoose directly here.
    const { User } = await import('../../src/models/User');
    const org = await import('../../src/models/Organisation').then(m => m.Organisation.findOne({ name: 'Shield' }));
    
    const adminUser = new User({
      email: 'admin@shield.com',
      passwordHash: 'mock', // we will login via DB bypass or just set up password
      name: 'Admin User',
      initials: 'AU',
      role: 'Admin',
      orgId: org!._id,
    });
    // Let's use bcrypt to set a real password so we can login
    const bcrypt = await import('bcryptjs');
    adminUser.passwordHash = await bcrypt.hash('Password123!', 10);
    await adminUser.save();

    const adminLogin = await request(app).post('/api/auth/login').send({
      email: 'admin@shield.com',
      password: 'Password123!',
    });
    adminCookies = adminLogin.headers['set-cookie'] as unknown as string[];

    // 3. Seed Settings
    const { Settings } = await import('../../src/models/Settings');
    await Settings.create({
      orgId: org!._id,
      retentionDays: 30,
      mfaRequired: false
    });
  });

  describe('PATCH /api/settings', () => {
    it('should forbid access for Analyst (lacks settings.update)', async () => {
      const res = await request(app)
        .patch('/api/settings')
        .set('Cookie', analystCookies)
        .send({ modelConfig: { alertThreshold: 0.95 } });

      expect(res.status).toBe(403);
      expect(res.body.message).toMatch(/Permission denied/i);
    });

    it('should allow access for Admin (has settings.update)', async () => {
      const res = await request(app)
        .patch('/api/settings')
        .set('Cookie', adminCookies)
        .send({ modelConfig: { alertThreshold: 0.95 } });

      // Assuming settings router logic is correct, it will return 200
      expect(res.status).toBe(200);
      expect(res.body.modelConfig.alertThreshold).toBe(0.95);
    });
  });
});
