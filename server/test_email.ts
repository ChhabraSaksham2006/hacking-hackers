import { env } from './src/config/env.js';
import { sendVerificationEmail } from './src/services/emailService.js';

async function testVerification() {
  console.log('Using API Key:', env.BREVO_API_KEY ? 'Set' : 'Not Set');
  const success = await sendVerificationEmail('ccsaksham2006@gmail.com', 'Saksham', 'test-token-123');
  
  if (success) {
    console.log('✅ Test email sent successfully!');
  } else {
    console.log('❌ Failed to send test email.');
  }
  process.exit(0);
}

testVerification();
