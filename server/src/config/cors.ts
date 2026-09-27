import cors from 'cors';

import { env } from './env.js';

import { AppError } from '../middleware/errorHandler.js';

const allowedOrigins = [
  env.FRONTEND_URL.replace(/\/$/, ''), // Strip trailing slash just in case
  'http://localhost:8080',
  'http://localhost:5173',
  'http://localhost:3000',
  'https://hacking-hackers-frontend.vercel.app'
];

export const corsOptions: cors.CorsOptions = {
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new AppError(403, `Origin ${origin} not allowed by CORS`));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  maxAge: 86400,
};