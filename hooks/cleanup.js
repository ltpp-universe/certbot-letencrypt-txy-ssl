/**
 * Certbot manual cleanup hook for Tencent Cloud DNS
 * This script is called by certbot after the DNS-01 challenge
 */

const { removeDnsRecord } = require('../lib/dns');

const secretId = process.env.TENCENT_SECRET_ID;
const secretKey = process.env.TENCENT_SECRET_KEY;
const certbotDomain = process.env.CERTBOT_DOMAIN;

async function cleanup() {
  if (!secretId || !secretKey) {
    console.error(
      'Error: TENCENT_SECRET_ID and TENCENT_SECRET_KEY must be set',
    );
    process.exit(1);
  }

  if (!certbotDomain) {
    console.error('Error: CERTBOT_DOMAIN must be set');
    process.exit(1);
  }

  try {
    await removeDnsRecord({
      secretId: secretId,
      secretKey: secretKey,
      domain: certbotDomain,
    });

    console.log('DNS record deleted successfully');
  } catch (error) {
    if (error.message === 'No record ID found') {
      console.log('No record ID found, skipping cleanup');
      process.exit(0);
    }
    console.error(`Cleanup failed: ${error}`);
    process.exit(1);
  }
}

cleanup();
