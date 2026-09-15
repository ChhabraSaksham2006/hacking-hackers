import 'dotenv/config';
import mongoose from 'mongoose';
import { User } from '../src/models/User.js';

async function main() {
  console.log('Connecting to MongoDB...');
  await mongoose.connect(process.env.MONGODB_URI!);
  console.log('Connected. Updating users...');
  const result = await User.updateMany({}, { $set: { alertNotificationsEnabled: false } });
  console.log('Updated users:', result.modifiedCount);
  process.exit(0);
}
main();
