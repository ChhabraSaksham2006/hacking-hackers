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

  const sixHoursCutoff = new Date(now.getTime() - 6 * 60 * 60 * 1000);

  // ── 1. Notifications: delete > 6h ─────────────
  const notifResult = await Notification.deleteMany({ createdAt: { $lt: sixHoursCutoff } });
  console.log(`🗑️  Notifications (>6h old): ${notifResult.deletedCount} deleted`);

  // ── 2. Predictions: delete > 6h ───────────────
  const predResult = await Prediction.deleteMany({ createdAt: { $lt: sixHoursCutoff } });
  console.log(`🗑️  Predictions (>6h old): ${predResult.deletedCount} deleted`);

  // ── 3. Flows: delete > 6h ─────────────────────
  const flowResult = await Flow.deleteMany({ createdAt: { $lt: sixHoursCutoff } });
  console.log(`🗑️  Flows (>6h old): ${flowResult.deletedCount} deleted`);

  // ── 4. Audit entries: delete > 6h ────────────
  const auditResult = await AuditEntry.deleteMany({ timestamp: { $lt: sixHoursCutoff } });
  console.log(`🗑️  Audit entries (>6h old): ${auditResult.deletedCount} deleted`);

  // ── 5. Alerts: delete > 6h ────
  const alertResult = await Alert.deleteMany({ createdAt: { $lt: sixHoursCutoff } });
  console.log(`🗑️  Alerts (>6h old): ${alertResult.deletedCount} deleted`);

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
