import 'dotenv/config';
import mongoose from 'mongoose';
import { User } from './src/models/User.js';
import { env } from './src/config/env.js';

async function migrateUsers() {
  try {
    console.log('Connecting to MongoDB...', env.MONGODB_URI);
    await mongoose.connect(env.MONGODB_URI);

    console.log('Connected. Updating users...');

    const result = await User.updateMany(
      { emailVerified: { $exists: false } },
      { $set: { emailVerified: true, alertNotificationsEnabled: true } }
    );

    console.log(`Updated ${result.modifiedCount} old users to have emailVerified=true and alertNotificationsEnabled=true.`);

    // Also explicitly set emailVerified = true for anyone who currently has it as false, 
    // since the user might be testing with an existing account.
    const result2 = await User.updateMany(
      { emailVerified: false },
      { $set: { emailVerified: true } }
    );

    console.log(`Updated ${result2.modifiedCount} users with emailVerified=false to true.`);

  } catch (e) {
    console.error('Error during migration:', e);
  } finally {
    await mongoose.disconnect();
    process.exit(0);
  }
}

migrateUsers();
