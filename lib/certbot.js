const { spawn } = require('child_process');
const path = require('path');
const { ensureDir, pathExists } = require('./file-utils');

const DEFAULT_CERT_DIR = '/etc/letsencrypt';
const DEFAULT_STAGING = false;
const DEFAULT_SLEEP_TIME = 30;

/**
 * Sleep for specified milliseconds
 * @param {number} ms Milliseconds to sleep
 * @returns {Promise<void>}
 */
function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Get certificate paths for a domain
 * @param {string} domain Domain name
 * @param {string} certDir Certificate directory
 * @returns {Object} Paths to certificate files
 */
function getCertPaths(domain, certDir) {
  const cleanDomain = domain.replace(/^\*\./, '');
  const configDir = path.join(certDir, 'live', cleanDomain);
  return {
    certPath: path.join(configDir, 'cert.pem'),
    keyPath: path.join(configDir, 'privkey.pem'),
    chainPath: path.join(configDir, 'chain.pem'),
    fullchainPath: path.join(configDir, 'fullchain.pem'),
    configDir: configDir,
  };
}

/**
 * Execute certbot command with DNS hook
 * @param {Object} config Certificate configuration
 * @param {string} config.domain Domain to issue certificate for
 * @param {string} config.secretId Tencent Cloud SecretId
 * @param {string} config.secretKey Tencent Cloud SecretKey
 * @param {string} [config.certDir] Certificate storage directory
 * @param {string} [config.email] Contact email
 * @param {boolean} [config.staging] Use staging environment
 * @param {number} [config.sleepTime] DNS propagation wait time
 * @param {boolean} [config.isWildcard] Issue wildcard certificate
 * @returns {Promise<Object>} Result of certificate issuance
 */
async function issueCertificate(config) {
  const certDir = config.certDir || DEFAULT_CERT_DIR;
  const sleepTime = config.sleepTime || DEFAULT_SLEEP_TIME;
  const staging = config.staging ?? DEFAULT_STAGING;

  ensureDir(certDir);

  const scriptDir = path.dirname(__dirname);
  const authHook = `node ${path.join(scriptDir, 'hooks', 'auth.js')}`;
  const cleanupHook = `node ${path.join(scriptDir, 'hooks', 'cleanup.js')}`;

  const domains = [config.domain];
  if (config.isWildcard) {
    const cleanDomain = config.domain.replace(/^\*\./, '');
    domains.push(cleanDomain);
  }

  const domainArgs = domains.flatMap((d) => ['-d', d]);

  const args = [
    'certonly',
    '--manual',
    '--preferred-challenges',
    'dns',
    '--manual-auth-hook',
    authHook,
    '--manual-cleanup-hook',
    cleanupHook,
    '--config-dir',
    certDir,
    '--work-dir',
    path.join(certDir, '.work'),
    '--logs-dir',
    path.join(certDir, '.logs'),
    ...domainArgs,
  ];

  if (staging) {
    args.push('--staging');
  }

  args.push('--agree-tos');
  args.push('--expand');

  if (config.email) {
    args.push('--email', config.email);
  } else {
    args.push('--register-unsafely-without-email');
  }

  args.push('--non-interactive');

  return new Promise((resolve) => {
    const env = {
      ...process.env,
      TENCENT_SECRET_ID: config.secretId,
      TENCENT_SECRET_KEY: config.secretKey,
      TENCENT_SLEEP_TIME: String(sleepTime),
    };

    const certbot = spawn('certbot', args, {
      env: env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    let stdout = '';
    let stderr = '';

    certbot.stdout?.on('data', (data) => {
      stdout += data.toString();
    });

    certbot.stderr?.on('data', (data) => {
      stderr += data.toString();
    });

    certbot.on('close', (code) => {
      const paths = getCertPaths(config.domain, certDir);

      if (code === 0 && pathExists(paths.certPath)) {
        resolve({
          success: true,
          message: 'Certificate issued successfully',
          certPath: paths.certPath,
          keyPath: paths.keyPath,
          chainPath: paths.chainPath,
          fullchainPath: paths.fullchainPath,
        });
      } else {
        resolve({
          success: false,
          message: `Certbot failed with code ${code}: ${stderr || stdout}`,
        });
      }
    });

    certbot.on('error', (error) => {
      resolve({
        success: false,
        message: `Failed to spawn certbot: ${error.message}`,
      });
    });
  });
}

/**
 * Renew certificates
 * @param {Object} params Renewal parameters
 * @param {string} [params.certDir] Certificate directory
 * @param {string} params.secretId Tencent Cloud SecretId
 * @param {string} params.secretKey Tencent Cloud SecretKey
 * @param {number} [params.sleepTime] Sleep time for DNS propagation
 * @param {boolean} [params.staging] Use staging environment
 * @returns {Promise<Object>} Result of renewal
 */
async function renewCertificates(params) {
  const certDir = params.certDir || DEFAULT_CERT_DIR;
  const sleepTime = params.sleepTime || DEFAULT_SLEEP_TIME;
  const staging = params.staging ?? DEFAULT_STAGING;

  const scriptDir = path.dirname(__dirname);
  const authHook = `node ${path.join(scriptDir, 'hooks', 'auth.js')}`;
  const cleanupHook = `node ${path.join(scriptDir, 'hooks', 'cleanup.js')}`;

  const args = [
    'renew',
    '--manual',
    '--preferred-challenges',
    'dns',
    '--manual-auth-hook',
    authHook,
    '--manual-cleanup-hook',
    cleanupHook,
    '--config-dir',
    certDir,
    '--work-dir',
    path.join(certDir, '.work'),
    '--logs-dir',
    path.join(certDir, '.logs'),
  ];

  if (staging) {
    args.push('--staging');
  }

  args.push('--non-interactive');

  return new Promise((resolve) => {
    const env = {
      ...process.env,
      TENCENT_SECRET_ID: params.secretId,
      TENCENT_SECRET_KEY: params.secretKey,
      TENCENT_SLEEP_TIME: String(sleepTime),
    };

    const certbot = spawn('certbot', args, {
      env: env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    let stdout = '';
    let stderr = '';

    certbot.stdout?.on('data', (data) => {
      stdout += data.toString();
    });

    certbot.stderr?.on('data', (data) => {
      stderr += data.toString();
    });

    certbot.on('close', (code) => {
      if (code === 0) {
        resolve({
          success: true,
          message: 'Certificates renewed successfully',
        });
      } else {
        resolve({
          success: false,
          message: `Certbot renew failed with code ${code}: ${stderr || stdout}`,
        });
      }
    });

    certbot.on('error', (error) => {
      resolve({
        success: false,
        message: `Failed to spawn certbot: ${error.message}`,
      });
    });
  });
}

module.exports = {
  issueCertificate,
  renewCertificates,
  getCertPaths,
  sleep,
};
