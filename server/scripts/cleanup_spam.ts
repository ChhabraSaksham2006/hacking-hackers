import 'dotenv/config';
import mongoose from 'mongoose';
import { Alert } from '../src/models/Alert.js';
import { Notification } from '../src/models/Notification.js';

async function main() {
  await mongoose.connect(process.env.MONGODB_URI!);
  const del = await Alert.deleteMany({ alertId: { $regex: '^AV-1' } });
  const notifDel = await Notification.deleteMany({ alertId: { $regex: '^AV-1' } });
  console.log('Deleted alerts:', del.deletedCount, 'Notifications:', notifDel.deletedCount);
  process.exit(0);
}
main();
