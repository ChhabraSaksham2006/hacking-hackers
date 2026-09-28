import { Kafka, type Producer, type Consumer, type SASLOptions, logLevel } from 'kafkajs';
import { env } from '../config/env.js';
import { dashboardStore } from '../models/dashboardModel.js';
import { emitToOrg } from '../socket.js';

export const KAFKA_TOPICS = {
  TELEMETRY_RAW: 'aegis.telemetry.raw',
  ALERTS_STREAM: 'aegis.alerts.stream',
} as const;

export interface TelemetryPayloadMessage {
  orgId: string;
  payload: any;
  receivedAt: number;
}

export interface KafkaPublishResult {
  queued: boolean;
  topic?: string;
  directState?: any;
}

class KafkaService {
  private kafka: Kafka | null = null;
  private producer: Producer | null = null;
  private consumer: Consumer | null = null;
  private active = false;
  private connecting = false;

  /**
   * Initializes Kafka producer and consumer if KAFKA_BROKERS is configured.
   * If not configured or broker unreachable, gracefully falls back to direct in-memory pipeline.
   */
  async init(): Promise<boolean> {
    if (!env.KAFKA_BROKERS || env.KAFKA_BROKERS.trim() === '') {
      console.log('⚡ [Kafka] KAFKA_BROKERS not configured. Using direct in-memory telemetry pipeline.');
      this.active = false;
      return false;
    }

    if (this.connecting || this.active) return this.active;
    this.connecting = true;

    try {
      const brokers = env.KAFKA_BROKERS.split(',').map((b) => b.trim()).filter(Boolean);
      console.log(`🌐 [Kafka] Connecting to brokers: ${brokers.join(', ')}...`);

      let sasl: SASLOptions | undefined = undefined;
      if (env.KAFKA_USERNAME && env.KAFKA_PASSWORD) {
        sasl = {
          mechanism: 'plain',
          username: env.KAFKA_USERNAME,
          password: env.KAFKA_PASSWORD,
        };
      }

      this.kafka = new Kafka({
        clientId: env.KAFKA_CLIENT_ID,
        brokers,
        ssl: env.KAFKA_SSL ? true : false,
        sasl,
        logLevel: env.NODE_ENV === 'production' ? logLevel.ERROR : logLevel.WARN,
        connectionTimeout: 5000,
        retry: {
          initialRetryTime: 300,
          retries: 3,
        },
      });

      // 1. Initialize Producer
      this.producer = this.kafka.producer({
        allowAutoTopicCreation: true,
      });
      await this.producer.connect();
      console.log('✅ [Kafka] Producer connected successfully');

      // 2. Initialize Consumer Group
      this.consumer = this.kafka.consumer({
        groupId: env.KAFKA_GROUP_ID,
        allowAutoTopicCreation: true,
      });
      await this.consumer.connect();
      await this.consumer.subscribe({
        topic: KAFKA_TOPICS.TELEMETRY_RAW,
        fromBeginning: false,
      });

      // 3. Start Consumer Stream Loop
      await this.consumer.run({
        eachMessage: async ({ topic, partition, message }) => {
          if (!message.value) return;
          try {
            const raw = message.value.toString();
            const data: TelemetryPayloadMessage = JSON.parse(raw);
            const { orgId, payload } = data;

            // Ingest into dashboard store & emit real-time SSE ticks
            const state = dashboardStore.ingestTelemetry(orgId, payload);

            // Push real-time Socket.io events if alerts are included
            if (payload.alerts && Array.isArray(payload.alerts) && payload.alerts.length > 0) {
              for (const alert of payload.alerts) {
                emitToOrg(orgId, 'alert_created', alert);
              }
            }
          } catch (err) {
            console.error(`❌ [Kafka Consumer Error] Failed to process message from ${topic}:${partition}:`, err);
          }
        },
      });

      console.log(`✅ [Kafka] Consumer active in group "${env.KAFKA_GROUP_ID}" on topic "${KAFKA_TOPICS.TELEMETRY_RAW}"`);
      this.active = true;
      return true;
    } catch (err: any) {
      console.warn(`⚠️ [Kafka] Could not connect to Kafka (${err?.message || err}). Falling back to in-memory mode.`);
      this.active = false;
      this.producer = null;
      this.consumer = null;
      return false;
    } finally {
      this.connecting = false;
    }
  }

  /**
   * Publishes edge telemetry frame to Kafka topic partitioned by orgId.
   * If Kafka is unavailable, automatically ingests directly in-memory.
   */
  async publishTelemetry(orgId: string, payload: any): Promise<KafkaPublishResult> {
    if (!this.active || !this.producer) {
      // Direct in-memory ingestion fallback
      const directState = dashboardStore.ingestTelemetry(orgId, payload);
      return {
        queued: false,
        directState,
      };
    }

    try {
      const message: TelemetryPayloadMessage = {
        orgId,
        payload,
        receivedAt: Date.now(),
      };

      const record = await this.producer.send({
        topic: KAFKA_TOPICS.TELEMETRY_RAW,
        messages: [
          {
            key: orgId, // Guarantees chronological partition ordering per organization
            value: JSON.stringify(message),
            headers: {
              'sensor-id': String(payload.sensor_id || 'unknown'),
              'timestamp': String(Date.now()),
            },
          },
        ],
      });

      // If payload has alerts, also broadcast to alerts stream topic
      if (payload.alerts && Array.isArray(payload.alerts) && payload.alerts.length > 0) {
        this.producer.send({
          topic: KAFKA_TOPICS.ALERTS_STREAM,
          messages: payload.alerts.map((alert: any) => ({
            key: orgId,
            value: JSON.stringify({ orgId, alert, timestamp: Date.now() }),
          })),
        }).catch((err) => console.error('❌ [Kafka] Failed to publish to alerts stream topic:', err));
      }

      return {
        queued: true,
        topic: KAFKA_TOPICS.TELEMETRY_RAW,
      };
    } catch (err) {
      console.error('⚠️ [Kafka Producer Error] Send failed. Falling back to in-memory ingestion:', err);
      const directState = dashboardStore.ingestTelemetry(orgId, payload);
      return {
        queued: false,
        directState,
      };
    }
  }

  isKafkaActive(): boolean {
    return this.active;
  }

  async disconnect(): Promise<void> {
    if (this.producer) {
      try {
        await this.producer.disconnect();
      } catch {}
      this.producer = null;
    }
    if (this.consumer) {
      try {
        await this.consumer.disconnect();
      } catch {}
      this.consumer = null;
    }
    this.active = false;
    console.log('🛑 [Kafka] Disconnected gracefully');
  }
}

export const kafkaService = new KafkaService();
