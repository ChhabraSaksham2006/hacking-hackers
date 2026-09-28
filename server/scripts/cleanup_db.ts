/**
 * cleanup_db.ts
 * =============
 * One-time (or scheduled) database cleanup script.
 * 
 * Purges old replay-generated data that fills up the MongoDB free tier:
 *   - Notifications older than 7 days
 *   - Predictions older than 7 days
 *   - Flows older than 3 days
 *   - Audit entries older than 30 days
 *   - Resolved alerts older than 14 days
 * 
 * Usage:
 *   npx tsx server/scripts/cleanup_db.ts              # interactive / local
 *   node server/dist/scripts/cleanup_db.js             # compiled (CI)
 * 
 * Env: Reads MONGODB_URI from server/.env
 */

import 'dotenv/config';
import mongoose from 'mongoose';
import { Alert } from '../src/models/Alert.js';
import { Notification } from '../src/models/Notification.js';
import { Prediction } from '../src/models/Prediction.js';
import { Flow } from '../src/models/Flow.js';
import { AuditEntry } from '../src/models/AuditEntry.js';

async function cleanup() {
  const uri = process.env.MONGODB_URI;
  if (!uri) {
    console.error('❌ MONGODB_URI not set. Create a .env file or pass it as env var.');
    process.exit(1);
  }

  console.log('🔌 Connecting to MongoDB...');
  await mongoose.connect(uri);
  console.log('✅ Connected.\n');

  const now = new Date();

  // ── 1. Notifications: delete all older than 7 days ─────────────
  const notifCutoff = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
  const notifResult = await Notification.deleteMany({ createdAt: { $lt: notifCutoff } });
  console.log(`🗑️  Notifications (>7d old): ${notifResult.deletedCount} deleted`);

  // Also delete read notifications older than 1 day (they're noise)
  const readNotifCutoff = new Date(now.getTime() - 1 * 24 * 60 * 60 * 1000);
  const readNotifResult = await Notification.deleteMany({ isRead: true, createdAt: { $lt: readNotifCutoff } });
  console.log(`🗑️  Read notifications (>1d old): ${readNotifResult.deletedCount} deleted`);

  // ── 2. Predictions: delete all older than 7 days ───────────────
  const predCutoff = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
  const predResult = await Prediction.deleteMany({ createdAt: { $lt: predCutoff } });
  console.log(`🗑️  Predictions (>7d old): ${predResult.deletedCount} deleted`);

  // ── 3. Flows: delete all older than 3 days ─────────────────────
  const flowCutoff = new Date(now.getTime() - 3 * 24 * 60 * 60 * 1000);
  const flowResult = await Flow.deleteMany({ createdAt: { $lt: flowCutoff } });
  console.log(`🗑️  Flows (>3d old): ${flowResult.deletedCount} deleted`);

  // ── 4. Audit entries: delete all older than 30 days ────────────
  const auditCutoff = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
  const auditResult = await AuditEntry.deleteMany({ timestamp: { $lt: auditCutoff } });
  console.log(`🗑️  Audit entries (>30d old): ${auditResult.deletedCount} deleted`);

  // ── 5. Resolved alerts: delete alerts resolved >14 days ago ────
  const alertCutoff = new Date(now.getTime() - 14 * 24 * 60 * 60 * 1000);
  const alertResult = await Alert.deleteMany({ status: 'Resolved', updatedAt: { $lt: alertCutoff } });
  console.log(`🗑️  Resolved alerts (>14d old): ${alertResult.deletedCount} deleted`);

  // ── 6. Aggressive secondary pass: delete everything older than 24h for flows/predictions ──
  // This ensures we stay well within free tier limits even after the TTL-based cleanup above
  const aggressiveFlowCutoff = new Date(now.getTime() - 1 * 24 * 60 * 60 * 1000);
  const aggFlowResult = await Flow.deleteMany({ createdAt: { $lt: aggressiveFlowCutoff } });
  if (aggFlowResult.deletedCount > 0) {
    console.log(`   📉 Aggressive pass: ${aggFlowResult.deletedCount} more flows (>24h) deleted`);
  }

  const aggressivePredCutoff = new Date(now.getTime() - 2 * 24 * 60 * 60 * 1000);
  const aggPredResult = await Prediction.deleteMany({ createdAt: { $lt: aggressivePredCutoff } });
  if (aggPredResult.deletedCount > 0) {
    console.log(`   📉 Aggressive pass: ${aggPredResult.deletedCount} more predictions (>2d) deleted`);
  }

  const aggressiveNotifCutoff = new Date(now.getTime() - 2 * 24 * 60 * 60 * 1000);
  const aggNotifResult = await Notification.deleteMany({ createdAt: { $lt: aggressiveNotifCutoff } });
  if (aggNotifResult.deletedCount > 0) {
    console.log(`   📉 Aggressive pass: ${aggNotifResult.deletedCount} more notifications (>2d) deleted`);
  }

  // ── 7. Print remaining counts ──────────────────────────────────
  console.log('\n📊 Remaining document counts:');
  const collections = ['alerts', 'notifications', 'predictions', 'flows', 'auditentries', 'organisations', 'users', 'segments', 'modelversions', 'ingestions', 'reports', 'simulations', 'settings'];
  for (const name of collections) {
    try {
      const count = await mongoose.connection.db!.collection(name).countDocuments();
      console.log(`   ${name}: ${count}`);
    } catch {
      // collection may not exist
    }
  }

  // ── 8. Database stats ──────────────────────────────────────────
  const stats = await mongoose.connection.db!.stats();
  const dataSizeMB = (stats.dataSize / (1024 * 1024)).toFixed(2);
  const storageSizeMB = (stats.storageSize / (1024 * 1024)).toFixed(2);
  const indexSizeMB = (stats.indexSize / (1024 * 1024)).toFixed(2);
  const totalMB = ((stats.dataSize + stats.indexSize) / (1024 * 1024)).toFixed(2);
  console.log(`\n💾 Database size: ${dataSizeMB} MB data + ${indexSizeMB} MB indexes = ${totalMB} MB total`);
  console.log(`   Storage on disk: ${storageSizeMB} MB`);
  console.log(`   Free tier limit: 512 MB`);
  
  const usagePct = ((stats.dataSize + stats.indexSize) / (512 * 1024 * 1024) * 100).toFixed(1);
  console.log(`   Usage: ~${usagePct}%`);

  console.log('\n✅ Cleanup complete!');
  await mongoose.disconnect();
  process.exit(0);
}

cleanup().catch((err) => {
  console.error('Cleanup failed:', err);
  process.exit(1);
});
