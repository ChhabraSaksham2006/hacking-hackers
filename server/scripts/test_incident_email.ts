import 'dotenv/config';
import mongoose from 'mongoose';
import { env } from '../src/config/env.js';
import { notifyOrgUsersOfAlert } from '../src/services/emailService.js';

async function main() {
  await mongoose.connect(env.MONGODB_URI);
  console.log('Connected to MongoDB. Triggering incident email...');
  
  const orgId = '6aa8e31dd60ad9652e34984a'; // Harcoded orgId from previous command output
  
  await notifyOrgUsersOfAlert(orgId, {
    alertId: 'AV-TEST-123',
    host: 'test.local',
    ip: '10.0.0.5',
    stage: 'Exfiltration',
    probability: 0.99,
    state: 'critical',
    reason: 'Testing real-time incident email notification',
    detectedAt: new Date()
  });
  
  console.log('Done!');
  process.exit(0);
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
