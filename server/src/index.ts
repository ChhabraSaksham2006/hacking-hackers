import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import cookieParser from 'cookie-parser';

import { env } from './config/env.js';
import { connectDB } from './config/db.js';
import { corsOptions } from './config/cors.js';
import { errorHandler, AppError } from './middleware/errorHandler.js';
import mongoose from 'mongoose';
import { dashboardStore } from './models/dashboardModel.js';
import { initSocket } from './socket.js';
import { initCronJobs } from './services/cronService.js';


// ── Route Imports ───────────────────────────────────────
import authRouter from './routes/auth.js';
import dashboardRouter from './routes/dashboard.js';
import alertsRouter from './routes/alerts.js';
import flowsRouter from './routes/flows.js';
import predictionsRouter from './routes/predictions.js';
import networkRouter from './routes/network.js';
import segmentsRouter from './routes/segments.js';
import ingestionRouter from './routes/ingestion.js';
import reportsRouter from './routes/reports.js';
import settingsRouter from './routes/settings.js';
import simulationsRouter from './routes/simulations.js';
import modelsRouter from './routes/models.js';
import auditRouter from './routes/audit.js';
import rolesRouter from './routes/roles.js';
import orgsRouter from './routes/orgs.js';
import explainabilityRouter from './routes/explainability.js';
import notificationsRouter from './routes/notifications.js';
import chatRouter from './routes/chat.js';
import demonstrationRouter from './routes/demonstration.js';

const app = express();

// ── Security & parsing ──────────────────────────────────
app.use(helmet());
app.use(cors(corsOptions));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// ── Logging ─────────────────────────────────────────────
app.use(morgan(env.NODE_ENV === 'production' ? 'combined' : 'dev'));

// ── Health check ────────────────────────────────────────
app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.get('/api/ready', (_req, res) => {
  const isMongoConnected = mongoose.connection.readyState === 1;
  if (!isMongoConnected) {
    res.status(503).json({ status: 'error', reason: 'Database disconnected' });
    return;
  }
  res.json({ status: 'ok', database: 'connected' });
});

// ── API routes ──────────────────────────────────────────

app.use('/api/auth', authRouter);
app.use('/api/dashboard', dashboardRouter);
app.use('/api/alerts', alertsRouter);
app.use('/api/flows', flowsRouter);
app.use('/api/predictions', predictionsRouter);
app.use('/api/network', networkRouter);
app.use('/api/segments', segmentsRouter);
app.use('/api/ingestion', ingestionRouter);
app.use('/api/reports', reportsRouter);
app.use('/api/settings', settingsRouter);
app.use('/api/simulations', simulationsRouter);
app.use('/api/models', modelsRouter);
app.use('/api/audit', auditRouter);
app.use('/api/roles', rolesRouter);
app.use('/api/orgs', orgsRouter);
app.use('/api/explainability', explainabilityRouter);
app.use('/api/notifications', notificationsRouter);
app.use('/api/chat', chatRouter);
app.use('/api/demonstration', demonstrationRouter);

// ── Root Route ──────────────────────────────────────────
app.get('/', (_req, res) => {
  res.json({
    message: 'Welcome to Aegis Vantage API',
    status: 'online',
    documentation: 'Internal API',
    version: '0.1.0'
  });
});

// ── 404 Route Not Found ─────────────────────────────────
app.use((_req, _res, next) => {
  next(new AppError(404, 'Route not found'));
});

// ── Global error handler (must be last) ─────────────────
app.use(errorHandler);

// ── Start server ────────────────────────────────────────
async function start() {
  await connectDB();
  await dashboardStore.init();
  initCronJobs();

  const server = app.listen(env.PORT, () => {
    console.log(`🚀 Aegis Vantage API running on port ${env.PORT}`);
    console.log(`   Environment: ${env.NODE_ENV}`);
    console.log(`   Frontend:    ${env.FRONTEND_URL}`);
  });

  // Initialize Socket.io
  initSocket(server);

  // Master Clock / Ticker Loop: step simulation every 3,000 ms
  const ticker = setInterval(async () => {
    try {
      const state = await dashboardStore.stepForward();
      
      // Lazily import to avoid circular dependencies during initialization
      const { applyWindowToDatabase } = await import('./services/replayService.js');
      const { Organisation } = await import('./models/Organisation.js');
      
      const orgs = await Organisation.find({}, '_id');
      for (const org of orgs) {
        await applyWindowToDatabase(org._id.toString(), state.actual_window_index);
      }
    } catch (err) {
      console.error('Ticker step error:', err);
    }
  }, 3000);

  // Graceful shutdown
  const shutdown = async () => {
    console.log('\n🛑 SIGTERM / SIGINT received. Shutting down gracefully...');
    clearInterval(ticker);
    server.close(async () => {
      console.log('   Express server closed.');
      await mongoose.connection.close();
      console.log('   MongoDB connection closed.');
      process.exit(0);
    });
  };

  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}

if (env.NODE_ENV !== 'test') {
  start().catch((err) => {
    console.error('Failed to start server:', err);
    process.exit(1);
  });
}

export default app;
