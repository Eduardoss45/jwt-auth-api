// * imports
const crypto = require('crypto');
const bcrypt = require('bcrypt');

// * generate code
function generateCode() {
  const random = crypto.randomBytes(10).toString('base64');
  const code = random
    .toUpperCase()
    .replace(/[^A-Z0-9]/g, '')
    .slice(0, 6);
  const codeHash = bcrypt.hashSync(code, 12);
  const codeExpiresAt = new Date(Date.now() + 15 * 60 * 1000);
  const codeAttempts = 0;
  return { code, codeHash, codeExpiresAt, codeAttempts };
}

// * export
module.exports = generateCode;
