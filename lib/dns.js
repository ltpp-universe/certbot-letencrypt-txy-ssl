const dns = require('dns');
const { promisify } = require('util');
const {
  createDnsRecord,
  deleteDnsRecord,
  parseDomain,
  buildAcmeChallengeDomain,
} = require('./dns-provider');
const { writeFile, readFile, deletePath } = require('./file-utils');
const path = require('path');
const os = require('os');

const dnsResolve = promisify(dns.resolveTxt);

const MIN_SLEEP_TIME = 60;
const DNS_CHECK_INTERVAL = 5000;
const DNS_CHECK_TIMEOUT = 300000;

/**
 * Add DNS TXT record for ACME challenge and save record ID
 * @param {Object} params Parameters
 * @param {string} params.secretId Tencent Cloud SecretId
 * @param {string} params.secretKey Tencent Cloud SecretKey
 * @param {string} params.domain Domain to validate (from CERTBOT_DOMAIN env)
 * @param {string} params.validation ACME validation string (from CERTBOT_VALIDATION env)
 * @param {number} [params.sleepTime] Sleep time for DNS propagation in seconds (minimum 60)
 * @returns {Promise<number>} Record ID
 */
async function addDnsRecord(params) {
  const [selfDomain, rootDomain] = parseDomain(params.domain);
  const subDomain = buildAcmeChallengeDomain(selfDomain);
  const fullDomain = `${subDomain}.${rootDomain}`;

  const recordId = await createDnsRecord({
    secretId: params.secretId,
    secretKey: params.secretKey,
    domain: params.domain,
    validation: params.validation,
  });

  const recordIdFile = path.join(
    os.tmpdir(),
    `certbot_txy_record_${params.domain}`,
  );
  writeFile(recordIdFile, String(recordId));

  const sleepTime = Math.max(
    params.sleepTime || MIN_SLEEP_TIME,
    MIN_SLEEP_TIME,
  );

  console.log(`Waiting ${sleepTime} seconds for DNS propagation...`);
  await new Promise((resolve) => setTimeout(resolve, sleepTime * 1000));

  console.log(`Checking DNS propagation for ${fullDomain}...`);
  await waitForDnsPropagation(fullDomain, params.validation);

  return recordId;
}

/**
 * Wait for DNS TXT record to propagate
 * @param {string} domain Domain to check
 * @param {string} expectedValue Expected TXT record value
 * @returns {Promise<void>}
 */
async function waitForDnsPropagation(domain, expectedValue) {
  const startTime = Date.now();

  while (Date.now() - startTime < DNS_CHECK_TIMEOUT) {
    try {
      const records = await dnsResolve(domain);
      const flatRecords = records.flat();

      if (flatRecords.includes(expectedValue)) {
        console.log(`DNS record verified: ${domain} -> ${expectedValue}`);
        return;
      }

      console.log(
        `DNS record not yet propagated, retrying in ${DNS_CHECK_INTERVAL / 1000}s...`,
      );
    } catch (error) {
      console.log(
        `DNS lookup failed: ${error.message}, retrying in ${DNS_CHECK_INTERVAL / 1000}s...`,
      );
    }

    await new Promise((resolve) => setTimeout(resolve, DNS_CHECK_INTERVAL));
  }

  throw new Error(
    `DNS propagation timeout after ${DNS_CHECK_TIMEOUT / 1000} seconds`,
  );
}

/**
 * Remove DNS TXT record for ACME challenge
 * @param {Object} params Parameters
 * @param {string} params.secretId Tencent Cloud SecretId
 * @param {string} params.secretKey Tencent Cloud SecretKey
 * @param {string} params.domain Domain name (from CERTBOT_DOMAIN env)
 * @returns {Promise<void>}
 */
async function removeDnsRecord(params) {
  const recordIdFile = path.join(
    os.tmpdir(),
    `certbot_txy_record_${params.domain}`,
  );
  const recordIdStr = readFile(recordIdFile);
  const recordId = parseInt(recordIdStr) || 0;

  if (!recordId) {
    throw new Error('No record ID found');
  }

  await deleteDnsRecord({
    secretId: params.secretId,
    secretKey: params.secretKey,
    domain: params.domain,
    recordId: recordId,
  });

  deletePath(recordIdFile);
}

/**
 * Get record ID file path for a domain
 * @param {string} domain Domain name
 * @returns {string} Record ID file path
 */
function getRecordIdFilePath(domain) {
  return path.join(os.tmpdir(), `certbot_txy_record_${domain}`);
}

module.exports = {
  addDnsRecord,
  removeDnsRecord,
  getRecordIdFilePath,
  parseDomain,
  buildAcmeChallengeDomain,
  createDnsRecord,
  deleteDnsRecord,
  waitForDnsPropagation,
};
