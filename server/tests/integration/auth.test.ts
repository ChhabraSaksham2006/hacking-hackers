import { describe, it, expect, beforeEach } from 'vitest';
import request from 'supertest';
import app from '../../src/index';

describe('Auth Endpoints', () => {
  const testUser = {
    orgName: 'ACME Corp',
    email: 'alice@acme.com',
    password: 'SuperSecurePassword123!',
    name: 'Alice Smith',
  };

  beforeEach(async () => {
    // Seed user for tests that require an existing user
    await request(app).post('/api/auth/register').send(testUser);
  });

  describe('POST /api/auth/register', () => {
    it('should register a new user successfully and ignore role escalation', async () => {
      const res = await request(app)
        .post('/api/auth/register')
        .send({
          orgName: 'Evil Corp',
          email: 'bob@evil.com',
          password: 'Password123456!',
          name: 'Bob',
          role: 'SOC Lead', // Attempt privilege escalation
        });

      expect(res.status).toBe(201);
      expect(res.body.user.email).toBe('bob@evil.com');
      // First user of an organisation is granted Admin, ignoring invalid roles like 'SOC Lead'
      expect(res.body.user.role).toBe('Admin');

      // Subsequent user registering for the same organisation defaults to Analyst
      const secondRes = await request(app)
        .post('/api/auth/register')
        .send({
          orgName: 'Evil Corp',
          email: 'charlie@evil.com',
          password: 'Password123456!',
          name: 'Charlie',
        });
      expect(secondRes.status).toBe(201);
      expect(secondRes.body.user.role).toBe('Analyst');
    });

    it('should prevent duplicate emails', async () => {
      const res = await request(app)
        .post('/api/auth/register')
        .send(testUser);

      expect(res.status).toBe(409);
    });
  });

  describe('POST /api/auth/login', () => {
    it('should login and return httpOnly cookies', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({
          email: testUser.email,
          password: testUser.password,
        });

      expect(res.status).toBe(200);
      expect(res.body.requiresTwoFactor).toBe(false);
      
      const cookies = res.headers['set-cookie'] as unknown as string[];
      expect(cookies).toBeDefined();
      expect(cookies.some((c: string) => c.includes('access_token='))).toBe(true);
      expect(cookies.some((c: string) => c.includes('refresh_token='))).toBe(true);
      expect(cookies.some((c: string) => c.includes('HttpOnly'))).toBe(true);
    });

    it('should reject invalid credentials', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({
          email: testUser.email,
          password: 'WrongPassword!',
        });

      expect(res.status).toBe(401);
    });
  });
});
