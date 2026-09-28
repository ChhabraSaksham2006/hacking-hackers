import { describe, it, expect, beforeEach } from 'vitest';
import request from 'supertest';
import app from '../../src/index';
import { kafkaService, KAFKA_TOPICS } from '../../src/services/kafkaService';

describe('Kafka Message Broker & Ingestion Pipeline', () => {
  let userCookies: string[];
  let orgApiKey: string;

  beforeEach(async () => {
    const email = `kafka-admin-${Date.now()}@stream.io`;
    await request(app).post('/api/auth/register').send({
      orgName: `Kafka Streaming Corp ${Date.now()}`,
      email,
      password: 'Password12345!',
      name: 'Stream Admin',
    });

    const loginRes = await request(app).post('/api/auth/login').send({
      email,
      password: 'Password12345!',
    });
    userCookies = loginRes.headers['set-cookie'] as unknown as string[];

    const sensorsRes = await request(app)
      .get('/api/sensors')
      .set('Cookie', userCookies);

    orgApiKey = sensorsRes.body.sensorApiKey;
  });

  it('exposes defined topic names for telemetry and alerts', () => {
    expect(KAFKA_TOPICS.TELEMETRY_RAW).toBe('aegis.telemetry.raw');
    expect(KAFKA_TOPICS.ALERTS_STREAM).toBe('aegis.alerts.stream');
  });

  it('falls back to resilient in-memory mode when KAFKA_BROKERS is unconfigured', () => {
    // In test environment, KAFKA_BROKERS is empty by default
    expect(kafkaService.isKafkaActive()).toBe(false);
  });

  it('ingests telemetry through fallback pipeline and responds with broker mode', async () => {
    const payload = {
      sensor_id: 'edge-tap-kafka-01',
      window_idx: 404,
      packet_count: 120,
      byte_count: 32000,
      flow_count: 15,
      calibrated_probability: 0.81,
      stage: 'Lateral Movement',
      risk_level: 'critical',
      confidence: '97.2%',
    };

    const res = await request(app)
      .post('/api/sensors/telemetry')
      .set('x-sensor-key', orgApiKey)
      .send(payload);

    expect(res.status).toBe(200);
    expect(res.body.status).toBe('ok');
    expect(res.body.broker).toBeDefined(); // 'direct' or 'kafka'
    expect(res.body.sensor_id).toBe('edge-tap-kafka-01');

    // Verify dashboard reflects the state
    const dashRes = await request(app)
      .get('/api/dashboard')
      .set('Cookie', userCookies);

    expect(dashRes.status).toBe(200);
    expect(dashRes.body.isLive).toBe(true);
    expect(dashRes.body.summary.currentStage).toBe('Lateral Movement');
  });
});
