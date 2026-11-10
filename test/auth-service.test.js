const assert = require('node:assert/strict');
const test = require('node:test');

const {
  hashPassword,
  isValidEmail,
  normalizeEmail,
  validatePassword,
  verifyPassword,
} = require('../auth-service');

test('normalizes and validates account email addresses', () => {
  assert.equal(normalizeEmail('  Vendor@Example.com '), 'vendor@example.com');
  assert.equal(isValidEmail('vendor@example.com'), true);
  assert.equal(isValidEmail('not-an-email'), false);
  assert.equal(isValidEmail('x'.repeat(250)), false);
});

test('requires a long password for newly protected accounts', () => {
  assert.equal(validatePassword('short-password'), true);
  assert.equal(validatePassword('short'), false);
  assert.equal(validatePassword('x'.repeat(1025)), false);
  assert.equal(validatePassword(null), false);
});

test('hashes passwords with unique salts and compares them in constant time', async () => {
  const first = await hashPassword('a-unique-vendor-password');
  const second = await hashPassword('a-unique-vendor-password');
  assert.notDeepEqual(first.salt, second.salt);
  assert.notDeepEqual(first.hash, second.hash);
  assert.equal(
    await verifyPassword('a-unique-vendor-password', first.salt, first.hash),
    true,
  );
  assert.equal(await verifyPassword('a-different-password', first.salt, first.hash), false);
});
