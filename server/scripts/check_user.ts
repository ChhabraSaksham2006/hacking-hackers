import 'dotenv/config';
import mongoose from 'mongoose';
import { env } from '../src/config/env.js';

async function main() {
  await mongoose.connect(env.MONGODB_URI);
  const db = mongoose.connection.db;
  if (!db) { throw new Error('No DB'); }
  const user = await db.collection('users').findOne({ email: 'ccsaksham2006@gmail.com' });
  console.log(user);
  const orgs = await db.collection('organisations').find().toArray();
  console.log('Orgs:', orgs);
  
  process.exit(0);
}

main().catch(console.error);
