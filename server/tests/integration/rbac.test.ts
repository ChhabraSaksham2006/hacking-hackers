import { describe, it, expect, beforeEach } from 'vitest';
import request from 'supertest';
import app from '../../src/index';

describe('RBAC & Authorization', () => {
  let analystCookies: string[];
  let adminCookies: string[];

  beforeEach(async () => {
    // 1. Create Admin (first user of Shield automatically becomes Admin)
    await request(app).post('/api/auth/register').send({
      orgName: 'Shield',
      email: 'admin@shield.com',
      password: 'Password123!',
      name: 'Admin User',
    });

    const adminLogin = await request(app).post('/api/auth/login').send({
      email: 'admin@shield.com',
      password: 'Password123!',
    });
    adminCookies = adminLogin.headers['set-cookie'] as unknown as string[];

    // 2. Create Analyst (subsequent user of Shield automatically defaults to Analyst)
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

    // 3. Seed Settings
    const { Organisation } = await import('../../src/models/Organisation');
    const org = await Organisation.findOne({ name: 'Shield' });
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

  describe('POST /api/roles/users (Team Member Management)', () => {
    let socLeadCookies: string[];

    beforeEach(async () => {
      const { User } = await import('../../src/models/User');
      const { Organisation } = await import('../../src/models/Organisation');
      const { hashPassword } = await import('../../src/utils/hash');
      const org = await Organisation.findOne({ name: 'Shield' });

      await User.create({
        orgId: org!._id,
        email: 'soclead@shield.com',
        passwordHash: await hashPassword('Password123!'),
        name: 'SOC Lead User',
        initials: 'SL',
        role: 'SOC Lead',
        emailVerified: true,
      });

      const socLeadLogin = await request(app).post('/api/auth/login').send({
        email: 'soclead@shield.com',
        password: 'Password123!',
      });
      socLeadCookies = socLeadLogin.headers['set-cookie'] as unknown as string[];
    });

    it('should forbid Analyst from adding team members (lacks users.create)', async () => {
      const res = await request(app)
        .post('/api/roles/users')
        .set('Cookie', analystCookies)
        .send({
          name: 'Unauthorized Member',
          email: 'unauth@shield.com',
          role: 'Analyst',
        });

      expect(res.status).toBe(403);
      expect(res.body.message).toMatch(/Permission denied: users.create/i);
    });

    it('should allow SOC Lead to add a new Analyst with auto-generated temporary password', async () => {
      const res = await request(app)
        .post('/api/roles/users')
        .set('Cookie', socLeadCookies)
        .send({
          name: 'Priya Sharma',
          email: 'priya@shield.com',
          role: 'Analyst',
        });

      expect(res.status).toBe(201);
      expect(res.body.user.name).toBe('Priya Sharma');
      expect(res.body.user.email).toBe('priya@shield.com');
      expect(res.body.user.role).toBe('Analyst');
      expect(res.body.temporaryPassword).toBeDefined();
      expect(typeof res.body.temporaryPassword).toBe('string');
    });

    it('should forbid SOC Lead from adding an Admin (privilege escalation prevention)', async () => {
      const res = await request(app)
        .post('/api/roles/users')
        .set('Cookie', socLeadCookies)
        .send({
          name: 'Escalated User',
          email: 'escalated@shield.com',
          role: 'Admin',
        });

      expect(res.status).toBe(403);
      expect(res.body.error).toMatch(/SOC Leads can only add Analysts or SOC Leads/i);
    });

    it('should allow Admin to add a new SOC Lead with custom password', async () => {
      const res = await request(app)
        .post('/api/roles/users')
        .set('Cookie', adminCookies)
        .send({
          name: 'Vikram Singh',
          email: 'vikram@shield.com',
          role: 'SOC Lead',
          password: 'CustomPassword123!',
        });

      expect(res.status).toBe(201);
      expect(res.body.user.name).toBe('Vikram Singh');
      expect(res.body.user.role).toBe('SOC Lead');
      expect(res.body.temporaryPassword).toBeUndefined();

      // Verify the new user can immediately log in
      const loginRes = await request(app).post('/api/auth/login').send({
        email: 'vikram@shield.com',
        password: 'CustomPassword123!',
      });
      expect(loginRes.status).toBe(200);
      expect(loginRes.body.user.role).toBe('SOC Lead');
    });

    it('should reject adding a member with an existing email', async () => {
      const res = await request(app)
        .post('/api/roles/users')
        .set('Cookie', adminCookies)
        .send({
          name: 'Duplicate Admin',
          email: 'admin@shield.com',
          role: 'Analyst',
        });

      expect(res.status).toBe(409);
      expect(res.body.error).toMatch(/already exists/i);
    });
  });
});
