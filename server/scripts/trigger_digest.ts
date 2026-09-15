import 'dotenv/config';
import mongoose from 'mongoose';
import { env } from '../src/config/env.js';
import { runDailyDigest } from '../src/services/cronService.js';

async function main() {
  await mongoose.connect(env.MONGODB_URI);
  console.log('Connected to MongoDB. Triggering daily digest...');
  
  await runDailyDigest();
  
  console.log('Done!');
  process.exit(0);
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
