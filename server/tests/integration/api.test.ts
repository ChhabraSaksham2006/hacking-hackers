import { describe, it, expect, beforeEach } from 'vitest';
import request from 'supertest';
import app from '../../src/index';

describe('Tenant Isolation', () => {
  let userACookies: string[];
  let userBCookies: string[];

  beforeEach(async () => {
    // 1. Create Org A / User A
    await request(app).post('/api/auth/register').send({
      orgName: 'Org A',
      email: 'a@orga.com',
      password: 'Password123!',
      name: 'User A',
    });
    const loginA = await request(app).post('/api/auth/login').send({
      email: 'a@orga.com',
      password: 'Password123!',
    });
    userACookies = loginA.headers['set-cookie'] as unknown as string[];

    // 2. Create Org B / User B
    await request(app).post('/api/auth/register').send({
      orgName: 'Org B',
      email: 'b@orgb.com',
      password: 'Password123!',
      name: 'User B',
    });
    const loginB = await request(app).post('/api/auth/login').send({
      email: 'b@orgb.com',
      password: 'Password123!',
    });
    userBCookies = loginB.headers['set-cookie'] as unknown as string[];

    // 3. Seed Alerts directly via Mongoose to assign correct orgIds
    const { Alert } = await import('../../src/models/Alert');
    const { Organisation } = await import('../../src/models/Organisation');
    
    const orgA = await Organisation.findOne({ name: 'Org A' });
    const orgB = await Organisation.findOne({ name: 'Org B' });

    await Alert.create({
      alertId: 'alert-org-a-1',
      host: 'host-a',
      ip: '10.0.0.1',
      stage: 'Reconnaissance',
      probability: 0.8,
      state: 'watch',
      reason: 'Scan detected',
      detectedAt: new Date(),
      orgId: orgA!._id,
    });

    await Alert.create({
      alertId: 'alert-org-b-1',
      host: 'host-b',
      ip: '192.168.1.1',
      stage: 'Impact',
      probability: 0.99,
      state: 'critical',
      reason: 'Data exfiltration',
      detectedAt: new Date(),
      orgId: orgB!._id,
    });
  });

  describe('GET /api/alerts', () => {
    it('should only return alerts for Org A to User A', async () => {
      const res = await request(app)
        .get('/api/alerts')
        .set('Cookie', userACookies);

      expect(res.status).toBe(200);
      expect(res.body.data.length).toBe(1);
      expect(res.body.data[0].alertId).toBe('alert-org-a-1');
    });

    it('should only return alerts for Org B to User B', async () => {
      const res = await request(app)
        .get('/api/alerts')
        .set('Cookie', userBCookies);

      expect(res.status).toBe(200);
      expect(res.body.data.length).toBe(1);
      expect(res.body.data[0].alertId).toBe('alert-org-b-1');
    });
  });
});
