/**
 * Certbot manual auth hook for Tencent Cloud DNS
 * This script is called by certbot during the DNS-01 challenge
 */

const { addDnsRecord } = require('../lib/dns');

const secretId = process.env.TENCENT_SECRET_ID;
const secretKey = process.env.TENCENT_SECRET_KEY;
const sleepTime = parseInt(process.env.TENCENT_SLEEP_TIME || '30');
const certbotDomain = process.env.CERTBOT_DOMAIN;
const certbotValidation = process.env.CERTBOT_VALIDATION;

async function authenticate() {
  if (!secretId || !secretKey) {
    console.error(
      'Error: TENCENT_SECRET_ID and TENCENT_SECRET_KEY must be set',
    );
    process.exit(1);
  }

  if (!certbotDomain || !certbotValidation) {
    console.error('Error: CERTBOT_DOMAIN and CERTBOT_VALIDATION must be set');
    process.exit(1);
  }

  try {
    console.log(`Creating DNS record for ${certbotDomain}...`);
    console.log(`Validation: ${certbotValidation}`);

    const recordId = await addDnsRecord({
      secretId: secretId,
      secretKey: secretKey,
      domain: certbotDomain,
      validation: certbotValidation,
      sleepTime: sleepTime,
    });

    console.log(`DNS record created with ID: ${recordId}`);
    console.log('DNS propagation wait completed');
  } catch (error) {
    console.error(`Authentication failed: ${error}`);
    process.exit(1);
  }
}

authenticate();
