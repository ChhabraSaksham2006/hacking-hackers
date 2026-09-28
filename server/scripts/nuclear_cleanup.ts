/**
 * nuclear_cleanup.ts
 * ==================
 * Emergency one-time script to nuke ALL replay-generated data and re-seed
 * only the essential seed data. Use when the DB is critically full.
 * 
 * This keeps: Organisations, Users, Settings, ModelVersions, Ingestions, Reports, Simulations
 * This DELETES ALL: Flows, Predictions, Notifications, and non-seed Alerts
 */

import 'dotenv/config';
import mongoose from 'mongoose';
import { Alert } from '../src/models/Alert.js';
import { Notification } from '../src/models/Notification.js';
import { Prediction } from '../src/models/Prediction.js';
import { Flow } from '../src/models/Flow.js';
import { AuditEntry } from '../src/models/AuditEntry.js';

async function nuclearCleanup() {
  const uri = process.env.MONGODB_URI;
  if (!uri) {
    console.error('❌ MONGODB_URI not set.');
    process.exit(1);
  }

  console.log('🔌 Connecting to MongoDB...');
  await mongoose.connect(uri);
  console.log('✅ Connected.\n');

  console.log('☢️  NUCLEAR CLEANUP — Purging all replay-generated data...\n');

  // Keep only the 6 seed alerts (AV-4821, AV-4820, AV-4817, AV-4814, AV-4809, AV-4801)
  const seedAlertIds = ['AV-4821', 'AV-4820', 'AV-4817', 'AV-4814', 'AV-4809', 'AV-4801'];
  const alertResult = await Alert.deleteMany({ alertId: { $nin: seedAlertIds } });
  console.log(`🗑️  Alerts (non-seed): ${alertResult.deletedCount} deleted`);

  // Delete ALL notifications (they're all system-generated noise)
  const notifResult = await Notification.deleteMany({});
  console.log(`🗑️  Notifications (all): ${notifResult.deletedCount} deleted`);

  // Keep only 1 seed prediction, delete everything else
  // The seed has windowEnd of 2026-09-06, keep only that
  const predResult = await Prediction.deleteMany({
    windowEnd: { $ne: new Date('2026-09-06T14:40:00Z') }
  });
  console.log(`🗑️  Predictions (non-seed): ${predResult.deletedCount} deleted`);

  // Keep only the 8 seed flows (they have specific src/dst from seed.ts)
  const seedFlowSrcs = [
    '10.24.8.31:49722', '10.24.1.4:51344', '10.24.4.19:44100',
    '10.24.12.77:60122', '10.24.19.8:33012', '10.24.6.42:57812',
    '10.24.3.55:5353', '10.24.9.18:49001'
  ];
  const flowResult = await Flow.deleteMany({ src: { $nin: seedFlowSrcs } });
  console.log(`🗑️  Flows (non-seed): ${flowResult.deletedCount} deleted`);

  // Trim audit entries to last 50
  const auditCount = await AuditEntry.countDocuments();
  if (auditCount > 50) {
    // Delete all except the most recent 50 using date
    const cutoffEntry = await AuditEntry.find({}).sort({ timestamp: -1 }).skip(50).limit(1).lean();
    if (cutoffEntry.length > 0) {
      const auditResult = await AuditEntry.deleteMany({ timestamp: { $lt: cutoffEntry[0]!.timestamp } });
      console.log(`🗑️  Audit entries (excess): ${auditResult.deletedCount} deleted`);
    }
  }

  // Drop orphaned collections if any exist
  const db = mongoose.connection.db!;
  const collections = await db.listCollections().toArray();
  const knownCollections = new Set([
    'alerts', 'auditentries', 'flows', 'ingestions', 'modelversions',
    'notifications', 'organisations', 'predictions', 'reports', 'segments',
    'settings', 'simulations', 'users'
  ]);
  for (const col of collections) {
    if (!knownCollections.has(col.name) && !col.name.startsWith('system.')) {
      await db.dropCollection(col.name);
      console.log(`🗑️  Dropped orphan collection: ${col.name}`);
    }
  }

  // Print final stats
  console.log('\n📊 Remaining document counts:');
  for (const name of [...knownCollections].sort()) {
    try {
      const count = await db.collection(name).countDocuments();
      console.log(`   ${name}: ${count}`);
    } catch {}
  }

  const stats = await db.stats();
  const totalMB = ((stats.dataSize + stats.indexSize) / (1024 * 1024)).toFixed(2);
  const usagePct = ((stats.dataSize + stats.indexSize) / (512 * 1024 * 1024) * 100).toFixed(1);
  console.log(`\n💾 Database: ${totalMB} MB total (${usagePct}% of 512 MB free tier)`);

  // Request compact (may not work on free tier but worth trying)
  console.log('\n🔧 Requesting collection compaction (may take a moment)...');
  for (const name of ['flows', 'predictions', 'notifications', 'auditentries']) {
    try {
      await db.command({ compact: name });
      console.log(`   ✅ Compacted: ${name}`);
    } catch (e: any) {
      console.log(`   ⚠️  ${name}: ${e.message?.slice(0, 80) || 'skipped'}`);
    }
  }

  // Re-check stats after compact
  const postStats = await db.stats();
  const postTotalMB = ((postStats.dataSize + postStats.indexSize) / (1024 * 1024)).toFixed(2);
  const postUsagePct = ((postStats.dataSize + postStats.indexSize) / (512 * 1024 * 1024) * 100).toFixed(1);
  console.log(`\n💾 Final: ${postTotalMB} MB total (${postUsagePct}% of 512 MB free tier)`);

  console.log('\n✅ Nuclear cleanup complete!');
  await mongoose.disconnect();
  process.exit(0);
}

nuclearCleanup().catch((err) => {
  console.error('Cleanup failed:', err);
  process.exit(1);
});
