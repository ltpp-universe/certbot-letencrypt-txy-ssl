const https = require('https');
const crypto = require('crypto');

const HOST = 'dnspod.tencentcloudapi.com';
const SERVICE = 'dnspod';
const VERSION = '2021-03-23';
const RECORD_LINE = '默认';
// 域名解析记录类型
const RECORD_TYPE = 'TXT';
// 域名解析记录生存时间
const TTL = 3600;
// 域名解析记录备注信息
const REMARK = '';

/**
 * Generate HMAC-SHA256 signature
 * @param {string} message The message to sign
 * @param {string} secret The secret key
 * @param {string} encoding The output encoding
 * @returns {Buffer | string} The HMAC signature
 */
function sha256(message, secret, encoding) {
  const hmac = crypto.createHmac('sha256', secret);
  return hmac.update(message).digest(encoding);
}

/**
 * Generate SHA256 hash
 * @param {string} message The message to hash
 * @param {string} encoding The output encoding
 * @returns {string} The SHA256 hash
 */
function getHash(message, encoding = 'hex') {
  const hash = crypto.createHash('sha256');
  return hash.update(message).digest(encoding);
}

/**
 * Get date string in YYYY-MM-DD format from timestamp
 * @param {number} timestamp Unix timestamp in seconds
 * @returns {string} Formatted date string
 */
function getDate(timestamp) {
  const date = new Date(timestamp * 1000);
  const year = date.getUTCFullYear();
  const month = ('0' + (date.getUTCMonth() + 1)).slice(-2);
  const day = ('0' + date.getUTCDate()).slice(-2);
  return `${year}-${month}-${day}`;
}

/**
 * Parse domain into subdomain and root domain
 * @param {string} domain Full domain name
 * @returns {[string, string]} [subdomain, rootDomain]
 */
function parseDomain(domain) {
  const domainParts = domain.split('.');
  if (domainParts.length >= 2) {
    const rootDomain = domainParts.slice(-2).join('.');
    const selfDomain = domainParts.slice(0, -2).join('.');
    return [selfDomain, rootDomain];
  }
  return ['', domain];
}

/**
 * Build ACME challenge subdomain
 * @param {string} selfDomain The subdomain part
 * @returns {string} ACME challenge subdomain
 */
function buildAcmeChallengeDomain(selfDomain) {
  return `_acme-challenge${selfDomain ? '.' + selfDomain : ''}`;
}

/**
 * Generate Tencent Cloud API authorization header
 * @param {Object} params Parameters for signature generation
 * @param {string} params.secretId Tencent Cloud SecretId
 * @param {string} params.secretKey Tencent Cloud SecretKey
 * @param {string} params.action API action name
 * @param {Object} params.payload Request payload
 * @returns {Object} Headers object with Authorization
 */
function generateAuthorization(params) {
  const timestamp = parseInt(String(new Date().getTime() / 1000));
  const date = getDate(timestamp);
  const payloadJson = JSON.stringify(params.payload);
  const signedHeaders = 'content-type;host';
  const hashedRequestPayload = getHash(payloadJson);
  const httpRequestMethod = 'POST';
  const canonicalUri = '/';
  const canonicalQueryString = '';
  const canonicalHeaders =
    'content-type:application/json; charset=utf-8\n' + 'host:' + HOST + '\n';

  const canonicalRequest =
    httpRequestMethod +
    '\n' +
    canonicalUri +
    '\n' +
    canonicalQueryString +
    '\n' +
    canonicalHeaders +
    '\n' +
    signedHeaders +
    '\n' +
    hashedRequestPayload;

  const algorithm = 'TC3-HMAC-SHA256';
  const hashedCanonicalRequest = getHash(canonicalRequest);
  const credentialScope = date + '/' + SERVICE + '/' + 'tc3_request';
  const stringToSign =
    algorithm +
    '\n' +
    timestamp +
    '\n' +
    credentialScope +
    '\n' +
    hashedCanonicalRequest;

  const kDate = sha256(date, 'TC3' + params.secretKey);
  const kService = sha256(SERVICE, kDate);
  const kSigning = sha256('tc3_request', kService);
  const signature = sha256(stringToSign, kSigning, 'hex');

  const authorization =
    algorithm +
    ' ' +
    'Credential=' +
    params.secretId +
    '/' +
    credentialScope +
    ', ' +
    'SignedHeaders=' +
    signedHeaders +
    ', ' +
    'Signature=' +
    signature;

  const headers = {
    Authorization: authorization,
    'Content-Type': 'application/json; charset=utf-8',
    Host: HOST,
    'X-TC-Action': params.action,
    'X-TC-Timestamp': timestamp,
    'X-TC-Version': VERSION,
  };

  return headers;
}

/**
 * Make HTTPS request to Tencent Cloud API
 * @param {Object} options Request options
 * @param {string} payload Request body
 * @returns {Promise<Object>} Response data
 */
function makeRequest(options, payload) {
  return new Promise((resolve, reject) => {
    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => {
        data += chunk;
      });
      res.on('end', () => {
        try {
          const parsed = JSON.parse(data);
          resolve(parsed);
        } catch (error) {
          reject(new Error(`Failed to parse response: ${error}`));
        }
      });
    });
    req.on('error', (error) => {
      reject(error);
    });
    req.write(payload);
    req.end();
  });
}

/**
 * Create DNS TXT record for ACME challenge
 * @param {Object} params Parameters for creating record
 * @param {string} params.secretId Tencent Cloud SecretId
 * @param {string} params.secretKey Tencent Cloud SecretKey
 * @param {string} params.domain Domain to validate
 * @param {string} params.validation ACME validation string
 * @returns {Promise<number>} Record ID
 */
async function createDnsRecord(params) {
  const [selfDomain, rootDomain] = parseDomain(params.domain);
  const subDomain = buildAcmeChallengeDomain(selfDomain);

  const payload = {
    Domain: rootDomain,
    RecordType: RECORD_TYPE,
    RecordLine: RECORD_LINE,
    Value: params.validation,
    SubDomain: subDomain,
    TTL: TTL,
    Remark: REMARK,
  };

  const headers = generateAuthorization({
    secretId: params.secretId,
    secretKey: params.secretKey,
    action: 'CreateRecord',
    payload: payload,
  });

  const options = {
    hostname: HOST,
    method: 'POST',
    headers: headers,
  };

  const response = await makeRequest(options, JSON.stringify(payload));
  const recordId = response?.Response?.RecordId;

  if (!recordId) {
    throw new Error(`Failed to create DNS record: ${JSON.stringify(response)}`);
  }

  return recordId;
}

/**
 * Delete DNS TXT record
 * @param {Object} params Parameters for deleting record
 * @param {string} params.secretId Tencent Cloud SecretId
 * @param {string} params.secretKey Tencent Cloud SecretKey
 * @param {string} params.domain Domain name
 * @param {number} params.recordId Record ID to delete
 * @returns {Promise<void>}
 */
async function deleteDnsRecord(params) {
  const [, rootDomain] = parseDomain(params.domain);

  const payload = {
    Domain: rootDomain,
    RecordId: params.recordId,
  };

  const headers = generateAuthorization({
    secretId: params.secretId,
    secretKey: params.secretKey,
    action: 'DeleteRecord',
    payload: payload,
  });

  const options = {
    hostname: HOST,
    method: 'POST',
    headers: headers,
  };

  await makeRequest(options, JSON.stringify(payload));
}

module.exports = {
  parseDomain,
  buildAcmeChallengeDomain,
  createDnsRecord,
  deleteDnsRecord,
  generateAuthorization,
  makeRequest,
  HOST,
  SERVICE,
  VERSION,
  RECORD_LINE,
  RECORD_TYPE,
  TTL,
  REMARK,
};
