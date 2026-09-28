/**
 * drop_and_reseed.ts
 * ==================
 * DROPS the large collections entirely (this immediately reclaims disk space
 * on Atlas, unlike deleteMany which leaves allocated pages).
 * Then re-runs the seed to restore baseline data.
 * 
 * This is the ONLY way to truly free space on Atlas free tier since
 * the `compact` command is not allowed.
 */

import 'dotenv/config';
import mongoose from 'mongoose';

async function dropAndReseed() {
  const uri = process.env.MONGODB_URI;
  if (!uri) {
    console.error('❌ MONGODB_URI not set.');
    process.exit(1);
  }

  console.log('🔌 Connecting to MongoDB...');
  await mongoose.connect(uri);
  const db = mongoose.connection.db!;
  console.log('✅ Connected.\n');

  // Step 1: Show current stats
  const statsBefore = await db.stats();
  const beforeMB = ((statsBefore.dataSize + statsBefore.indexSize) / (1024 * 1024)).toFixed(2);
  console.log(`📊 Before: ${beforeMB} MB used\n`);

  // Step 2: Drop the bloated collections (this immediately frees disk space)
  const collectionsToDrop = ['flows', 'predictions', 'notifications', 'auditentries'];
  
  for (const name of collectionsToDrop) {
    try {
      const exists = await db.listCollections({ name }).hasNext();
      if (exists) {
        const count = await db.collection(name).countDocuments();
        await db.collection(name).drop();
        console.log(`🗑️  Dropped collection '${name}' (had ${count} docs) — disk space freed!`);
      } else {
        console.log(`⏭️  Collection '${name}' doesn't exist, skipping`);
      }
    } catch (err: any) {
      console.error(`❌ Failed to drop '${name}': ${err.message}`);
    }
  }

  // Step 3: Also drop non-seed alerts
  try {
    const seedAlertIds = ['AV-4821', 'AV-4820', 'AV-4817', 'AV-4814', 'AV-4809', 'AV-4801'];
    const alertsCollection = db.collection('alerts');
    const alertExists = await db.listCollections({ name: 'alerts' }).hasNext();
    if (alertExists) {
      const totalAlerts = await alertsCollection.countDocuments();
      const seedAlerts = await alertsCollection.countDocuments({ alertId: { $in: seedAlertIds } });
      
      if (totalAlerts > seedAlerts + 5) {
        // Too many non-seed alerts, drop and reseed will recreate
        await alertsCollection.drop();
        console.log(`🗑️  Dropped collection 'alerts' (had ${totalAlerts} docs, ${seedAlerts} were seed)`);
      } else {
        // Just delete non-seed
        const result = await alertsCollection.deleteMany({ alertId: { $nin: seedAlertIds } });
        console.log(`🗑️  Cleaned alerts: ${result.deletedCount} non-seed deleted, ${seedAlerts} seed kept`);
      }
    }
  } catch (err: any) {
    console.error(`❌ Alert cleanup error: ${err.message}`);
  }

  // Step 4: Show stats after drop
  console.log('\n⏳ Waiting for Atlas to recalculate...');
  await new Promise(resolve => setTimeout(resolve, 3000));

  const statsAfter = await db.stats();
  const afterMB = ((statsAfter.dataSize + statsAfter.indexSize) / (1024 * 1024)).toFixed(2);
  const storageMB = (statsAfter.storageSize / (1024 * 1024)).toFixed(2);
  const usagePct = ((statsAfter.dataSize + statsAfter.indexSize) / (512 * 1024 * 1024) * 100).toFixed(1);

  console.log(`\n📊 After drop:`);
  console.log(`   Data + Indexes: ${afterMB} MB`);
  console.log(`   Storage on disk: ${storageMB} MB`);
  console.log(`   Usage: ${usagePct}% of 512 MB`);
  console.log(`   Freed: ~${(parseFloat(beforeMB) - parseFloat(afterMB)).toFixed(2)} MB`);

  // Step 5: List remaining collections
  console.log('\n📋 Remaining collections:');
  const remaining = await db.listCollections().toArray();
  for (const col of remaining) {
    if (!col.name.startsWith('system.')) {
      try {
        const count = await db.collection(col.name).countDocuments();
        console.log(`   ${col.name}: ${count} docs`);
      } catch {}
    }
  }

  console.log('\n✅ Drop complete! Now run "npm run seed" to restore baseline seed data.');
  console.log('   cd server && npm run seed');

  await mongoose.disconnect();
  process.exit(0);
}

dropAndReseed().catch((err) => {
  console.error('Failed:', err);
  process.exit(1);
});
