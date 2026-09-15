import cron from 'node-cron';
import mongoose from 'mongoose';
import { Alert } from '../models/Alert.js';
import { Organisation } from '../models/Organisation.js';
import { User } from '../models/User.js';
import { sendRaw } from './emailService.js';

export async function runDailyDigest() {
  console.log('[Cron] Running Daily Digest job...');
  
  try {
    const orgs = await Organisation.find();
    
    for (const org of orgs) {
      // Fetch users in org who have notifications enabled
      const users = await User.find({ orgId: org._id, alertNotificationsEnabled: true });
      if (users.length === 0) continue;
      
      // Fetch yesterday's stats
      const yesterday = new Date();
      yesterday.setDate(yesterday.getDate() - 1);
      
      const alerts = await Alert.find({ 
        orgId: org._id,
        detectedAt: { $gte: yesterday }
      }).lean();
      
      if (alerts.length === 0) continue; // nothing to report
      
      const totalAlerts = alerts.length;
      const criticalAlerts = alerts.filter(a => a.state === 'critical').length;
      const acknowledged = alerts.filter(a => a.status === 'Acknowledged').length;
      const investigating = alerts.filter(a => a.status === 'Investigating').length;
      const resolved = alerts.filter(a => a.status === 'Resolved').length;
      
      const unresolvedCritical = alerts.filter(a => a.state === 'critical' && a.status !== 'Resolved');
      
      // Build email HTML
      const html = `
        <div style="font-family: sans-serif; max-width: 600px; margin: 0 auto; color: #333;">
          <h1 style="color: #000; font-size: 24px;">Daily Security Alert Digest</h1>
          <p style="color: #666; font-size: 16px;">Summary for ${org.name}</p>
          
          <div style="background: #f5f5f5; padding: 20px; border-radius: 8px; margin: 20px 0;">
            <table style="width: 100%; text-align: left;">
              <tr><td style="padding: 4px 0;"><strong>Total Alerts:</strong></td><td>${totalAlerts}</td></tr>
              <tr><td style="padding: 4px 0; color: #dc2626;"><strong>Critical Alerts:</strong></td><td style="color: #dc2626; font-weight: bold;">${criticalAlerts}</td></tr>
              <tr><td style="padding: 4px 0;"><strong>Acknowledged:</strong></td><td>${acknowledged}</td></tr>
              <tr><td style="padding: 4px 0;"><strong>Investigating:</strong></td><td>${investigating}</td></tr>
              <tr><td style="padding: 4px 0; color: #16a34a;"><strong>Resolved:</strong></td><td style="color: #16a34a; font-weight: bold;">${resolved}</td></tr>
            </table>
          </div>

          ${unresolvedCritical.length > 0 ? `
            <h2 style="font-size: 18px; color: #dc2626; margin-top: 30px;">Unresolved Critical Alerts</h2>
            <ul style="padding-left: 20px;">
              ${unresolvedCritical.map(a => `
                <li style="margin-bottom: 8px;">
                  <strong>${a.alertId}</strong>: ${a.reason} <span style="color: #666; font-size: 14px;">(Stage: ${a.stage})</span>
                </li>
              `).join('')}
            </ul>
          ` : `<p style="color: #16a34a; font-weight: bold;">🎉 No unresolved critical alerts!</p>`}
          
          <p style="margin-top: 40px; font-size: 12px; color: #999;">
            This is an automated digest from Aegis Vantage. You can adjust your notification settings in your profile.
          </p>
        </div>
      `;

      const recipients = users.map(u => ({ email: u.email, name: u.name }));
      await sendRaw(recipients, `Daily Security Digest — ${org.name}`, html);
      
      console.log(`[Cron] Sent digest to ${users.length} users in org ${org.name}`);
    }
  } catch (err) {
    console.error('[Cron] Error generating daily digest:', err);
  }
}

export function initCronJobs() {
  // Run daily at 17:00 (5 PM)
  cron.schedule('0 17 * * *', runDailyDigest);
}
