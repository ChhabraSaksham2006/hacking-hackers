import mongoose from 'mongoose';
import { env } from '../src/config/env.js';
import { Alert } from '../src/models/Alert.js';

async function main() {
  await mongoose.connect('mongodb+srv://SakshamChhabra:Saksham%402006@hackinghackers.zgkiwub.mongodb.net/?appName=HackingHackers');
  const alerts = await Alert.find({}).lean();
  console.log("Found alerts:", alerts.length);
  console.log(alerts.map(a => ({ alertId: a.alertId, host: a.host, orgId: a.orgId, status: a.status })));
  process.exit(0);
}

main();
