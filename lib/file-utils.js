const fs = require('fs');
const path = require('path');

/**
 * Ensure directory exists, create if not
 * @param {string} dirPath Directory path
 * @returns {void}
 */
function ensureDir(dirPath) {
  const absolutePath = path.resolve(dirPath);
  if (!fs.existsSync(absolutePath)) {
    fs.mkdirSync(absolutePath, { recursive: true });
  }
}

/**
 * Write data to file safely
 * @param {string} filePath File path
 * @param {string} data Data to write
 * @returns {void}
 */
function writeFile(filePath, data) {
  const absolutePath = path.resolve(filePath);
  const directoryPath = path.dirname(absolutePath);
  ensureDir(directoryPath);
  fs.writeFileSync(absolutePath, data);
}

/**
 * Read file content
 * @param {string} filePath File path
 * @returns {string} File content or empty string if not exists
 */
function readFile(filePath) {
  try {
    const absolutePath = path.resolve(filePath);
    if (fs.existsSync(absolutePath)) {
      return fs.readFileSync(absolutePath, 'utf8');
    }
  } catch (error) {
    console.error(`readFile error: ${error}`);
  }
  return '';
}

/**
 * Delete file or directory
 * @param {string} targetPath Path to delete
 * @returns {void}
 */
function deletePath(targetPath) {
  try {
    const absolutePath = path.resolve(targetPath);
    if (fs.existsSync(absolutePath)) {
      const stats = fs.statSync(absolutePath);
      if (stats.isFile()) {
        fs.unlinkSync(absolutePath);
      } else if (stats.isDirectory()) {
        fs.rmSync(absolutePath, { recursive: true, force: true });
      }
    }
  } catch (error) {
    console.error(`deletePath error: ${error}`);
  }
}

/**
 * Check if path exists
 * @param {string} targetPath Path to check
 * @returns {boolean} True if exists
 */
function pathExists(targetPath) {
  const absolutePath = path.resolve(targetPath);
  return fs.existsSync(absolutePath);
}

module.exports = {
  ensureDir,
  writeFile,
  readFile,
  deletePath,
  pathExists,
};
