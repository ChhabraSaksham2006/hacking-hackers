import mongoose from 'mongoose';
import { User } from './src/models/User.js';
import { Organisation } from './src/models/Organisation.js';
import { hashPassword } from './src/utils/hash.js';
import { env } from './src/config/env.js';

async function changePassword() {
  try {
    console.log('Connecting to MongoDB...');
    const uri = env.MONGODB_URI;
    await mongoose.connect(uri);
    
    const email = 'ccsaksham2006@gmail.com';
    const password = 'Saksham@2006';
    
    // find an org to attach to, e.g. Northwind Energy
    const org = await Organisation.findOne();
    
    if (!org) {
      console.log('No orgs found, cannot create user.');
      return;
    }
    
    const user = new User({
      email,
      name: 'Saksham Chhabra',
      initials: 'SC',
      role: 'Admin',
      orgId: org._id,
      passwordHash: await hashPassword(password),
      emailVerified: true,
      alertNotificationsEnabled: true
    });
    
    await user.save();
    
    console.log(`✅ Successfully created account for ${email} with the provided password.`);
    
  } catch (e) {
    console.error('Error changing password:', e);
  } finally {
    await mongoose.disconnect();
    process.exit(0);
  }
}

changePassword();
