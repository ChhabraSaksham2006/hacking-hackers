import { z } from 'zod';
import dotenv from 'dotenv';

dotenv.config();

const envSchema = z.object({
  PORT: z.coerce.number().default(5000),
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),

  // MongoDB
  MONGODB_URI: z.string().min(1, 'MONGODB_URI is required'),

  // JWT
  JWT_SECRET: z.string().min(32, 'JWT_SECRET must be at least 32 characters'),
  JWT_REFRESH_SECRET: z.string().min(32, 'JWT_REFRESH_SECRET must be at least 32 characters'),
  JWT_2FA_CHALLENGE_SECRET: z.string().min(32, 'JWT_2FA_CHALLENGE_SECRET must be at least 32 characters').default('aegis-dev-jwt-2fa-secret-do-not-use-in-production-1234567890abcdef'),
  JWT_ACCESS_EXPIRY: z.string().default('15m'),
  JWT_REFRESH_EXPIRY: z.string().default('7d'),

  // CORS
  FRONTEND_URL: z.string().url().default('http://localhost:5173'),

  // ML Service (optional)
  ML_SERVICE_URL: z.string().url().optional().or(z.literal('')),
  PYTHON_PATH: z.string().optional().or(z.literal('')),

  // S3 / Object Storage (optional)
  S3_ENDPOINT: z.string().optional().or(z.literal('')),
  S3_BUCKET: z.string().optional().or(z.literal('')),
  S3_ACCESS_KEY: z.string().optional().or(z.literal('')),
  S3_SECRET_KEY: z.string().optional().or(z.literal('')),
  S3_REGION: z.string().optional().or(z.literal('')),

  // Redis (optional)
  REDIS_URL: z.string().optional().or(z.literal('')),

  // Brevo Email Service
  BREVO_API_KEY: z.string().min(1, 'BREVO_API_KEY is required for email').optional().or(z.literal('')),
  BREVO_SENDER_EMAIL: z.string().email().default('noreply@aegisvantage.com'),
  BREVO_SENDER_NAME: z.string().default('Aegis Vantage'),

  // AI Chat & RAG LLM Providers (Groq -> OpenRouter -> Cyber Engine fallback)
  GROQ_API_KEY: z.string().optional().default(() => (process.env.GROQ_API_KEY || process.env.GR0Q_API_KEY || process.env.GROK_API_KEY || '').trim()),
  OPENROUTER_API_KEY: z.string().optional().default(() => (process.env.OPENROUTER_API_KEY || '').trim()),
});

function validateEnv() {
  const result = envSchema.safeParse(process.env);

  if (!result.success) {
    console.error('❌ Invalid environment variables:');
    for (const issue of result.error.issues) {
      console.error(`   ${issue.path.join('.')}: ${issue.message}`);
    }
    process.exit(1);
  }

  return result.data;
}

export const env = validateEnv();
