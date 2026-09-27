import { env } from '../config/env.js';

// â”€â”€ Brevo HTTP API Wrapper â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

const BREVO_API_URL = 'https://api.brevo.com/v3/smtp/email';

interface BrevoRecipient {
  email: string;
  name?: string;
}

interface BrevoPayload {
  sender: { name: string; email: string };
  to: BrevoRecipient[];
  subject: string;
  htmlContent: string;
}

/**
 * Send a transactional email via Brevo HTTP API.
 * Fails silently in development when BREVO_API_KEY is not configured.
 */
export async function sendRaw(
  to: BrevoRecipient[],
  subject: string,
  htmlContent: string,
): Promise<boolean> {
  const apiKey = env.BREVO_API_KEY;
  if (!apiKey) {
    console.warn(`ðŸ“§ [EMAIL SKIPPED] No BREVO_API_KEY set. Would have sent "${subject}" to ${to.map(r => r.email).join(', ')}`);
    return false;
  }

  const payload: BrevoPayload = {
    sender: {
      name: env.BREVO_SENDER_NAME,
      email: env.BREVO_SENDER_EMAIL,
    },
    to,
    subject,
    htmlContent,
  };

  try {
    const response = await fetch(BREVO_API_URL, {
      method: 'POST',
      headers: {
        'accept': 'application/json',
        'content-type': 'application/json',
        'api-key': apiKey,
      },
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      const errorBody = await response.text();
      console.error(`ðŸ“§ [EMAIL ERROR] Brevo returned ${response.status}: ${errorBody}`);
      return false;
    }

    console.log(`ðŸ“§ [EMAIL SENT] "${subject}" â†’ ${to.map(r => r.email).join(', ')}`);
    return true;
  } catch (err) {
    console.error('ðŸ“§ [EMAIL ERROR] Failed to send email:', err);
    return false;
  }
}

// â”€â”€ HTML Template Wrapper â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

function wrapTemplate(title: string, body: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${title}</title>
</head>
<body style="margin:0;padding:0;background-color:#0f1117;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif;">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background-color:#0f1117;padding:40px 20px;">
    <tr>
      <td align="center">
        <table role="presentation" width="560" cellspacing="0" cellpadding="0" style="max-width:560px;width:100%;">
          <!-- Logo -->
          <tr>
            <td style="padding-bottom:24px;">
              <table role="presentation" cellspacing="0" cellpadding="0">
                <tr>
                  <td style="width:18px;height:18px;transform:rotate(45deg);border:2px solid #2dd4bf;border-radius:4px;"></td>
                  <td style="padding-left:12px;font-size:15px;font-weight:600;color:#e4e5e9;letter-spacing:0.5px;">
                    Flow दृष्टि
                  </td>
                </tr>
              </table>
            </td>
          </tr>
          <!-- Card -->
          <tr>
            <td style="background-color:#1a1d27;border:1px solid #2a2e3b;border-radius:12px;padding:32px;">
              ${body}
            </td>
          </tr>
          <!-- Footer -->
          <tr>
            <td style="padding-top:24px;text-align:center;font-size:12px;color:#6b7280;">
              Flow दृष्टि Â· Predictive Cyber-Defence Console<br>
              This is an automated message â€” please do not reply.
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>`;
}

function buttonHtml(text: string, url: string): string {
  return `<table role="presentation" cellspacing="0" cellpadding="0" style="margin:24px 0;">
  <tr>
    <td style="background-color:#2dd4bf;border-radius:8px;">
      <a href="${url}" target="_blank" style="display:inline-block;padding:12px 28px;font-size:14px;font-weight:600;color:#0f1117;text-decoration:none;border-radius:8px;">
        ${text}
      </a>
    </td>
  </tr>
</table>`;
}

// â”€â”€ High-Level Email Methods â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/**
 * Send email verification link after signup.
 */
export async function sendVerificationEmail(
  email: string,
  name: string,
  token: string,
): Promise<boolean> {
  const verifyUrl = `${env.FRONTEND_URL}/verify-email?token=${encodeURIComponent(token)}`;
  const body = `
    <h1 style="margin:0 0 8px;font-size:22px;font-weight:600;color:#e4e5e9;">
      Verify your email
    </h1>
    <p style="margin:0 0 4px;font-size:15px;color:#9ca3af;">
      Hi ${escapeHtml(name)},
    </p>
    <p style="margin:0;font-size:15px;color:#9ca3af;line-height:1.6;">
      Click the button below to verify your email and activate your Flow दृष्टि account.
      This link expires in <strong style="color:#e4e5e9;">24 hours</strong>.
    </p>
    ${buttonHtml('Verify email address', verifyUrl)}
    <p style="margin:0;font-size:12px;color:#6b7280;">
      If you didn't create an account, you can safely ignore this email.
    </p>
    <p style="margin:16px 0 0;font-size:11px;color:#4b5563;word-break:break-all;">
      ${escapeHtml(verifyUrl)}
    </p>`;

  return sendRaw([{ email, name }], 'Verify your email â€” Flow दृष्टि', wrapTemplate('Verify Email', body));
}

/**
 * Send password reset link.
 */
export async function sendPasswordResetEmail(
  email: string,
  name: string,
  token: string,
): Promise<boolean> {
  const resetUrl = `${env.FRONTEND_URL}/reset-password?token=${encodeURIComponent(token)}`;
  const body = `
    <h1 style="margin:0 0 8px;font-size:22px;font-weight:600;color:#e4e5e9;">
      Reset your password
    </h1>
    <p style="margin:0 0 4px;font-size:15px;color:#9ca3af;">
      Hi ${escapeHtml(name)},
    </p>
    <p style="margin:0;font-size:15px;color:#9ca3af;line-height:1.6;">
      We received a request to reset your password. Click the button below to choose a new one.
      This link expires in <strong style="color:#e4e5e9;">1 hour</strong>.
    </p>
    ${buttonHtml('Reset password', resetUrl)}
    <p style="margin:0;font-size:12px;color:#6b7280;">
      If you didn't request a password reset, you can safely ignore this email.
      Your password will remain unchanged.
    </p>
    <p style="margin:16px 0 0;font-size:11px;color:#4b5563;word-break:break-all;">
      ${escapeHtml(resetUrl)}
    </p>`;

  return sendRaw([{ email, name }], 'Reset your password â€” Flow दृष्टि', wrapTemplate('Reset Password', body));
}

/**
 * Send 2FA verification code via email.
 */
export async function sendTwoFactorCodeEmail(
  email: string,
  name: string,
  code: string,
): Promise<boolean> {
  const digits = code.split('').map(d =>
    `<td style="width:40px;height:48px;background-color:#0f1117;border:1px solid #2a2e3b;border-radius:8px;text-align:center;font-size:24px;font-weight:700;color:#2dd4bf;font-family:'Courier New',monospace;">${d}</td>`
  ).join('<td style="width:8px;"></td>');

  const body = `
    <h1 style="margin:0 0 8px;font-size:22px;font-weight:600;color:#e4e5e9;">
      Your verification code
    </h1>
    <p style="margin:0 0 4px;font-size:15px;color:#9ca3af;">
      Hi ${escapeHtml(name)},
    </p>
    <p style="margin:0 0 20px;font-size:15px;color:#9ca3af;line-height:1.6;">
      Use the code below to complete your sign-in. This code expires in
      <strong style="color:#e4e5e9;">5 minutes</strong>.
    </p>
    <table role="presentation" cellspacing="0" cellpadding="0" style="margin:0 auto 20px;">
      <tr>${digits}</tr>
    </table>
    <p style="margin:0;font-size:12px;color:#6b7280;">
      If you didn't attempt to sign in, change your password immediately.
    </p>`;

  return sendRaw([{ email, name }], `${code} â€” Flow दृष्टि verification code`, wrapTemplate('Verification Code', body));
}

/**
 * Send critical alert notification.
 */
export async function sendAlertNotificationEmail(
  email: string,
  name: string,
  alert: {
    alertId: string;
    host: string;
    ip: string;
    stage: string;
    probability: number;
    state: string;
    reason: string;
    detectedAt: Date;
  },
): Promise<boolean> {
  const stateColor = alert.state === 'critical' ? '#ef4444' : alert.state === 'watch' ? '#f59e0b' : '#2dd4bf';
  const stateLabel = alert.state.charAt(0).toUpperCase() + alert.state.slice(1);
  const detectedTime = alert.detectedAt.toISOString().slice(0, 19).replace('T', ' ') + 'Z';

  const body = `
    <div style="display:flex;align-items:center;gap:8px;margin-bottom:16px;">
      <span style="display:inline-block;width:10px;height:10px;border-radius:50%;background-color:${stateColor};"></span>
      <h1 style="margin:0;font-size:22px;font-weight:600;color:#e4e5e9;">
        Alert: ${escapeHtml(alert.alertId)}
      </h1>
    </div>
    <p style="margin:0 0 20px;font-size:15px;color:#9ca3af;line-height:1.6;">
      A <strong style="color:${stateColor};">${stateLabel}</strong> alert was triggered on your monitored estate.
    </p>
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background-color:#0f1117;border:1px solid #2a2e3b;border-radius:8px;">
      <tr>
        <td style="padding:12px 16px;border-bottom:1px solid #2a2e3b;font-size:13px;color:#6b7280;width:120px;">Host</td>
        <td style="padding:12px 16px;border-bottom:1px solid #2a2e3b;font-size:14px;color:#e4e5e9;font-family:'Courier New',monospace;">${escapeHtml(alert.host)}</td>
      </tr>
      <tr>
        <td style="padding:12px 16px;border-bottom:1px solid #2a2e3b;font-size:13px;color:#6b7280;">IP</td>
        <td style="padding:12px 16px;border-bottom:1px solid #2a2e3b;font-size:14px;color:#e4e5e9;font-family:'Courier New',monospace;">${escapeHtml(alert.ip)}</td>
      </tr>
      <tr>
        <td style="padding:12px 16px;border-bottom:1px solid #2a2e3b;font-size:13px;color:#6b7280;">Stage</td>
        <td style="padding:12px 16px;border-bottom:1px solid #2a2e3b;font-size:14px;color:#e4e5e9;">${escapeHtml(alert.stage)}</td>
      </tr>
      <tr>
        <td style="padding:12px 16px;border-bottom:1px solid #2a2e3b;font-size:13px;color:#6b7280;">Probability</td>
        <td style="padding:12px 16px;border-bottom:1px solid #2a2e3b;font-size:14px;color:${stateColor};font-weight:600;font-family:'Courier New',monospace;">${alert.probability.toFixed(2)}</td>
      </tr>
      <tr>
        <td style="padding:12px 16px;border-bottom:1px solid #2a2e3b;font-size:13px;color:#6b7280;">Detected</td>
        <td style="padding:12px 16px;border-bottom:1px solid #2a2e3b;font-size:14px;color:#e4e5e9;font-family:'Courier New',monospace;">${detectedTime}</td>
      </tr>
      <tr>
        <td style="padding:12px 16px;font-size:13px;color:#6b7280;">Reason</td>
        <td style="padding:12px 16px;font-size:14px;color:#e4e5e9;">${escapeHtml(alert.reason)}</td>
      </tr>
    </table>
    ${buttonHtml('View in console', `${env.FRONTEND_URL}/app/alerts`)}
    <p style="margin:0;font-size:12px;color:#6b7280;">
      You're receiving this because alert notifications are enabled. Manage in Settings.
    </p>`;

  return sendRaw(
    [{ email, name }],
    `ðŸ”´ ${stateLabel} alert: ${alert.alertId} â€” ${alert.host}`,
    wrapTemplate('Alert Notification', body),
  );
}

/**
 * Send report delivery email.
 */
export async function sendReportEmail(
  email: string,
  name: string,
  reportTitle: string,
  reportUrl: string,
): Promise<boolean> {
  const body = `
    <h1 style="margin:0 0 8px;font-size:22px;font-weight:600;color:#e4e5e9;">
      Report ready
    </h1>
    <p style="margin:0 0 4px;font-size:15px;color:#9ca3af;">
      Hi ${escapeHtml(name)},
    </p>
    <p style="margin:0;font-size:15px;color:#9ca3af;line-height:1.6;">
      Your report <strong style="color:#e4e5e9;">"${escapeHtml(reportTitle)}"</strong>
      has been generated and is ready for download.
    </p>
    ${buttonHtml('Download report', reportUrl)}
    <p style="margin:0;font-size:12px;color:#6b7280;">
      This link is valid for 7 days from generation.
    </p>`;

  return sendRaw([{ email, name }], `Report ready: ${reportTitle} â€” Flow दृष्टि`, wrapTemplate('Report Ready', body));
}

/**
 * Send alert notification emails to all eligible users in an org.
 * Fire-and-forget â€” errors are logged but never thrown.
 */
export async function notifyOrgUsersOfAlert(
  orgId: string,
  alert: {
    alertId: string;
    host: string;
    ip: string;
    stage: string;
    probability: number;
    state: string;
    reason: string;
    detectedAt: Date;
  },
): Promise<void> {
  // Only notify for critical alerts
  if (alert.state !== 'critical') return;

  try {
    // Dynamic import to avoid circular dependency
    const { User } = await import('../models/User.js');
    const users = await User.find({
      orgId,
      alertNotificationsEnabled: true,
      emailVerified: true,
    }).select('email name').lean();

    await Promise.allSettled(
      users.map(user => sendAlertNotificationEmail(user.email, user.name, alert)),
    );
  } catch (err) {
    console.error('ðŸ“§ [NOTIFY ERROR] Failed to notify org users:', err);
  }
}

// â”€â”€ Utilities â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
