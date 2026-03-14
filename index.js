#!/usr/bin/env node

/**
 * Main entry point for SSL certificate issuance
 * Supports issuing certificates for specific domains and wildcard domains
 */

const { issueCertificate, renewCertificates } = require('./lib/certbot');

/**
 * Print usage information
 */
function printUsage() {
  console.log(`
Usage: node index.js [options]

Options:
    --domain, -d <domain>        Domain to issue certificate for (required)
    --secret-id <id>             Tencent Cloud SecretId (required)
    --secret-key <key>           Tencent Cloud SecretKey (required)
    --cert-dir <path>            Certificate storage directory (default: /etc/letsencrypt)
    --email <email>              Contact email for Let's Encrypt
    --wildcard, -w               Issue wildcard certificate
    --staging                    Use Let's Encrypt staging environment
    --sleep <seconds>            DNS propagation wait time (default: 30)
    --renew                      Renew existing certificates
    --help, -h                   Show this help message

Examples:
    Issue certificate for single domain:
        node index.js -d example.com --secret-id XXX --secret-key YYY

    Issue wildcard certificate:
        node index.js -d "*.example.com" --secret-id XXX --secret-key YYY --wildcard

    Issue certificate with custom storage path:
        node index.js -d example.com --secret-id XXX --secret-key YYY --cert-dir /path/to/certs

    Renew all certificates:
        node index.js --renew --secret-id XXX --secret-key YYY
`);
}

/**
 * Parse command line arguments
 */
function parseArgs() {
  const args = process.argv.slice(2);
  const result = {
    wildcard: false,
    staging: false,
    sleepTime: 30,
    renew: false,
    help: false,
  };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];

    switch (arg) {
      case '--domain':
      case '-d':
        result.domain = args[++i];
        break;
      case '--secret-id':
        result.secretId = args[++i];
        break;
      case '--secret-key':
        result.secretKey = args[++i];
        break;
      case '--cert-dir':
        result.certDir = args[++i];
        break;
      case '--email':
        result.email = args[++i];
        break;
      case '--wildcard':
      case '-w':
        result.wildcard = true;
        break;
      case '--staging':
        result.staging = true;
        break;
      case '--sleep':
        result.sleepTime = parseInt(args[++i]) || 30;
        break;
      case '--renew':
        result.renew = true;
        break;
      case '--help':
      case '-h':
        result.help = true;
        break;
    }
  }

  return result;
}

/**
 * Main function
 */
async function main() {
  const args = parseArgs();

  if (args.help) {
    printUsage();
    process.exit(0);
  }

  if (!args.secretId || !args.secretKey) {
    console.error('Error: --secret-id and --secret-key are required');
    printUsage();
    process.exit(1);
  }

  if (args.renew) {
    console.log('Renewing certificates...');
    const result = await renewCertificates({
      certDir: args.certDir,
      secretId: args.secretId,
      secretKey: args.secretKey,
      sleepTime: args.sleepTime,
      staging: args.staging,
    });

    if (result.success) {
      console.log('Success:', result.message);
      process.exit(0);
    } else {
      console.error('Failed:', result.message);
      process.exit(1);
    }
  }

  if (!args.domain) {
    console.error('Error: --domain is required (unless using --renew)');
    printUsage();
    process.exit(1);
  }

  console.log(`Issuing certificate for: ${args.domain}`);
  console.log(`Wildcard: ${args.wildcard}`);
  console.log(`Certificate directory: ${args.certDir || '/etc/letsencrypt'}`);

  const result = await issueCertificate({
    domain: args.domain,
    secretId: args.secretId,
    secretKey: args.secretKey,
    certDir: args.certDir,
    email: args.email,
    staging: args.staging,
    sleepTime: args.sleepTime,
    isWildcard: args.wildcard,
  });

  if (result.success) {
    console.log('\nCertificate issued successfully!');
    console.log('Certificate files:');
    console.log(`  Certificate: ${result.certPath}`);
    console.log(`  Private Key: ${result.keyPath}`);
    console.log(`  Chain: ${result.chainPath}`);
    console.log(`  Full Chain: ${result.fullchainPath}`);
    process.exit(0);
  } else {
    console.error('\nFailed to issue certificate:');
    console.error(result.message);
    process.exit(1);
  }
}

main();
