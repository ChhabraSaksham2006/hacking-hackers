import { describe, it, expect, beforeEach } from 'vitest';
import request from 'supertest';
import app from '../../src/index';

describe('Sensors API & Multi-Tenant Ingestion', () => {
  let userCookies: string[];
  let orgApiKey: string;

  beforeEach(async () => {
    const email = `admin-${Date.now()}@acme.corp`;
    await request(app).post('/api/auth/register').send({
      orgName: `Acme Corp ${Date.now()}`,
      email,
      password: 'Password123!',
      name: 'Acme Admin',
    });

    const loginRes = await request(app).post('/api/auth/login').send({
      email,
      password: 'Password123!',
    });
    userCookies = loginRes.headers['set-cookie'] as unknown as string[];

    const sensorsRes = await request(app)
      .get('/api/sensors')
      .set('Cookie', userCookies);

    expect(sensorsRes.status).toBe(200);
    expect(sensorsRes.body.sensorApiKey).toBeDefined();
    orgApiKey = sensorsRes.body.sensorApiKey;
  });

  it('allows organization to configure environment and subnets', async () => {
    const setupRes = await request(app)
      .post('/api/sensors/setup')
      .set('Cookie', userCookies)
      .send({
        monitoredSubnets: ['10.0.0.0/24', '192.168.1.0/24'],
        environmentType: 'enterprise',
        sensorSetupCompleted: true,
      });

    expect(setupRes.status).toBe(200);
    expect(setupRes.body.org.sensorSetupCompleted).toBe(true);
    expect(setupRes.body.org.monitoredSubnets).toEqual(['10.0.0.0/24', '192.168.1.0/24']);
  });

  it('rejects unauthenticated telemetry frame with 401', async () => {
    const res = await request(app)
      .post('/api/sensors/telemetry')
      .send({ sensor_id: 'rogue-sensor', window_idx: 1 });

    expect(res.status).toBe(401);
  });

  it('accepts authenticated edge telemetry and transitions dashboard to isLive: true', async () => {
    // 1. Initial dashboard is demo
    const initialDash = await request(app)
      .get('/api/dashboard')
      .set('Cookie', userCookies);
    expect(initialDash.status).toBe(200);
    expect(initialDash.body.isDemo).toBe(true);
    expect(initialDash.body.isLive).toBe(false);

    // 2. Transmit live edge telemetry frame
    const telemetryRes = await request(app)
      .post('/api/sensors/telemetry')
      .set('x-sensor-key', orgApiKey)
      .send({
        sensor_id: 'edge-probe-primary',
        window_idx: 101,
        packet_count: 50,
        byte_count: 14200,
        flow_count: 18,
        calibrated_probability: 0.74,
        stage: 'Lateral Movement',
        risk_level: 'critical',
        confidence: '95.5%',
        top_flows: [
          { src: '10.0.0.15:445', dst: '10.0.0.22:51203', proto: 'TCP', flags: 'ACK', bytes: 8400, score: 0.74 },
        ],
        alerts: [
          { alert_id: 'ALT-101', severity: 'high', threat_type: 'Lateral Movement', description: 'SMB credential sweep' },
        ],
      });

    expect(telemetryRes.status).toBe(200);
    expect(telemetryRes.body.status).toBe('ok');

    // 3. Query dashboard again — should now be live
    const liveDash = await request(app)
      .get('/api/dashboard')
      .set('Cookie', userCookies);

    expect(liveDash.status).toBe(200);
    expect(liveDash.body.isLive).toBe(true);
    expect(liveDash.body.isDemo).toBe(false);
    expect(liveDash.body.summary.currentStage).toBe('Lateral Movement');
    expect(liveDash.body.summary.riskLevel).toBe('critical');
    expect(liveDash.body.summary.infiltrationProbability).toBe(0.74);
  });
});
