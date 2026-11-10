const crypto = require('node:crypto');
const { promisify } = require('node:util');
const { sendSmtpEmail } = require('./messaging');
const { store } = require('./postgres-document-store');

const scrypt = promisify(crypto.scrypt);
const SESSION_LIFETIME_MS = 14 * 24 * 60 * 60 * 1000;
const EMAIL_TOKEN_LIFETIME_MS = 60 * 60 * 1000;
const PASSWORD_RESET_LIFETIME_MS = 30 * 60 * 1000;
const PASSWORD_HASH_BYTES = 64;

function normalizeEmail(email) {
  if (typeof email !== 'string') return '';
  return email.trim().toLowerCase();
}

function isValidEmail(email) {
  return email.length <= 254 &&
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function validatePassword(password) {
  return typeof password === 'string' &&
    password.length >= 12 &&
    password.length <= 1024;
}

async function hashPassword(password, salt = crypto.randomBytes(16)) {
  const hash = await scrypt(password, salt, PASSWORD_HASH_BYTES, {
    N: 1 << 15,
    r: 8,
    p: 1,
    maxmem: 128 * 1024 * 1024,
  });
  return { salt, hash: Buffer.from(hash) };
}

async function verifyPassword(password, salt, expectedHash) {
  const { hash } = await hashPassword(password, salt);
  return hash.length === expectedHash.length &&
    crypto.timingSafeEqual(hash, expectedHash);
}

function digestToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

function toUser(row) {
  const customClaims = row.business_id
    ? { businessId: row.business_id }
    : {};
  return {
    uid: row.id,
    email: row.email,
    emailVerified: row.email_verified === true,
    email_verified: row.email_verified === true,
    isAnonymous: row.is_anonymous === true,
    businessId: row.business_id || undefined,
    customClaims,
  };
}

function normalizeDeviceInput(installationId, deviceSecret) {
  if (typeof installationId !== 'string' ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
        .test(installationId) ||
      typeof deviceSecret !== 'string' ||
      !/^[A-Za-z0-9_-]{40,64}$/.test(deviceSecret)) {
    throw authError('This device could not establish a secure session.', 400);
  }
  return { installationId, deviceSecret };
}

function authError(message, status, code) {
  const error = new Error(message);
  error.status = status;
  if (code) error.code = code;
  return error;
}

async function issueSession(userId) {
  const token = crypto.randomBytes(32).toString('base64url');
  const tokenHash = digestToken(token);
  const expiresAt = new Date(Date.now() + SESSION_LIFETIME_MS);
  await store.pool().query(
    `INSERT INTO auth_sessions (token_hash, user_id, expires_at)
     VALUES ($1, $2, $3)`,
    [tokenHash, userId, expiresAt],
  );
  return { token, expiresAt: expiresAt.toISOString() };
}

async function createDeviceSession(installationId, deviceSecret) {
  const device = normalizeDeviceInput(installationId, deviceSecret);
  const secretHash = digestToken(device.deviceSecret);
  const client = await store.pool().connect();
  let user;
  try {
    await client.query('BEGIN');
    await client.query('SET TRANSACTION ISOLATION LEVEL SERIALIZABLE');
    const existing = await client.query(
      `SELECT users.*
       FROM auth_devices AS devices
       JOIN auth_users AS users ON users.id = devices.user_id
       WHERE devices.installation_id = $1
       FOR UPDATE OF devices, users`,
      [device.installationId],
    );
    if (existing.rowCount) {
      const currentHash = Buffer.from(existing.rows[0].secret_hash, 'hex');
      const suppliedHash = Buffer.from(secretHash, 'hex');
      if (!crypto.timingSafeEqual(currentHash, suppliedHash)) {
        throw authError('This device is already registered.', 401);
      }
      user = existing.rows[0];
      if (!user.is_anonymous) {
        throw authError('Sign in with your email and password to restore this session.', 401);
      }
    } else {
      const userId = crypto.randomUUID();
      const created = await client.query(
        `INSERT INTO auth_users (id, is_anonymous)
         VALUES ($1, TRUE)
         RETURNING *`,
        [userId],
      );
      await client.query(
        `INSERT INTO auth_devices (installation_id, user_id, secret_hash)
         VALUES ($1, $2, $3)`,
        [device.installationId, userId, secretHash],
      );
      user = created.rows[0];
    }
    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    if (error.code === '23505' || error.code === '40001') {
      throw authError('This device could not establish a secure session. Retry.', 409);
    }
    throw error;
  } finally {
    client.release();
  }
  return { ...(await issueSession(user.id)), user: toUser(user) };
}

async function readSession(token) {
  if (typeof token !== 'string' || token.length < 40 || token.length > 128) {
    throw authError('A valid sign-in session is required.', 401);
  }
  const result = await store.pool().query(
    `SELECT users.*, sessions.token_hash
     FROM auth_sessions AS sessions
     JOIN auth_users AS users ON users.id = sessions.user_id
     WHERE sessions.token_hash = $1
       AND sessions.revoked_at IS NULL
       AND sessions.expires_at > NOW()`,
    [digestToken(token)],
  );
  if (!result.rowCount) {
    throw authError('Your session has expired. Sign in again.', 401);
  }
  return {
    user: toUser(result.rows[0]),
    tokenHash: result.rows[0].token_hash,
  };
}

async function signOut(tokenHash) {
  await store.pool().query(
    `UPDATE auth_sessions SET revoked_at = NOW()
     WHERE token_hash = $1 AND revoked_at IS NULL`,
    [tokenHash],
  );
}

async function getUser(uid) {
  const result = await store.pool().query(
    'SELECT * FROM auth_users WHERE id = $1',
    [uid],
  );
  if (!result.rowCount) throw authError('The account no longer exists.', 404);
  return toUser(result.rows[0]);
}

async function getUserByEmail(email) {
  const result = await store.pool().query(
    'SELECT * FROM auth_users WHERE email = $1',
    [normalizeEmail(email)],
  );
  if (!result.rowCount) {
    const error = authError('The employee must create an account first.', 404);
    error.code = 'auth/user-not-found';
    throw error;
  }
  return toUser(result.rows[0]);
}

async function setBusinessId(uid, businessId) {
  await store.pool().query(
    `UPDATE auth_users SET business_id = $2, updated_at = NOW()
     WHERE id = $1`,
    [uid, businessId || null],
  );
}

async function secureAnonymousAccount(uid, email, password) {
  const normalizedEmail = normalizeEmail(email);
  if (!isValidEmail(normalizedEmail)) {
    throw authError('Enter a valid email address.', 400);
  }
  if (!validatePassword(password)) {
    throw authError('Use a password with at least 12 characters.', 400);
  }
  const credentials = await hashPassword(password);
  try {
    const result = await store.pool().query(
      `UPDATE auth_users
       SET email = $2, password_salt = $3, password_hash = $4,
           is_anonymous = FALSE, email_verified = FALSE, updated_at = NOW()
       WHERE id = $1 AND is_anonymous = TRUE
       RETURNING *`,
      [uid, normalizedEmail, credentials.salt, credentials.hash],
    );
    if (!result.rowCount) {
      throw authError('This account is already protected. Sign in instead.', 409);
    }
  } catch (error) {
    if (error.code === '23505') {
      throw authError('That email is already in use. Sign in instead.', 409);
    }
    throw error;
  }
  return getUser(uid);
}

async function signIn(email, password) {
  const normalizedEmail = normalizeEmail(email);
  if (!isValidEmail(normalizedEmail) ||
      typeof password !== 'string' || password.length === 0) {
    throw authError('Email or password is incorrect.', 401);
  }
  const result = await store.pool().query(
    `SELECT * FROM auth_users
     WHERE email = $1 AND is_anonymous = FALSE`,
    [normalizedEmail],
  );
  if (!result.rowCount) {
    await hashPassword(password, Buffer.alloc(16));
    throw authError('Email or password is incorrect.', 401);
  }
  const user = result.rows[0];
  if (!await verifyPassword(password, user.password_salt, user.password_hash)) {
    throw authError('Email or password is incorrect.', 401);
  }
  const session = await issueSession(user.id);
  return { ...session, user: toUser(user) };
}

function emailConfiguration() {
  const host = process.env.SMTP_HOST;
  const port = Number.parseInt(process.env.SMTP_PORT || '', 10);
  const fromEmail = process.env.SMTP_FROM_EMAIL;
  const domain = process.env.DOMAIN;
  if (!host || !Number.isInteger(port) || !fromEmail || !domain) {
    throw authError(
      'Account email is not configured on the server. Set SMTP_HOST, SMTP_PORT, SMTP_FROM_EMAIL, and DOMAIN.',
      503,
    );
  }
  const origin = new URL(domain);
  if (origin.protocol !== 'https:' || origin.username || origin.password) {
    throw authError('Account email links require a valid HTTPS DOMAIN.', 503);
  }
  return {
    host,
    port,
    secure: process.env.SMTP_SECURE === 'true',
    user: process.env.SMTP_USER || '',
    password: process.env.SMTP_PASSWORD || '',
    fromEmail,
    fromName: process.env.SMTP_FROM_NAME || 'Tienda',
    domain: origin.origin,
  };
}

async function createEmailToken(userId, purpose) {
  const token = crypto.randomBytes(32).toString('base64url');
  const lifetime = purpose === 'verify_email'
    ? EMAIL_TOKEN_LIFETIME_MS
    : PASSWORD_RESET_LIFETIME_MS;
  const expiresAt = new Date(Date.now() + lifetime);
  const client = await store.pool().connect();
  try {
    await client.query('BEGIN');
    await client.query(
      `DELETE FROM auth_email_tokens WHERE user_id = $1 AND purpose = $2`,
      [userId, purpose],
    );
    await client.query(
      `INSERT INTO auth_email_tokens (token_hash, user_id, purpose, expires_at)
       VALUES ($1, $2, $3, $4)`,
      [digestToken(token), userId, purpose, expiresAt],
    );
    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    throw error;
  } finally {
    client.release();
  }
  return token;
}

async function sendAccountEmail({ to, subject, body }) {
  const config = emailConfiguration();
  await sendSmtpEmail({
    host: config.host,
    port: config.port,
    secure: config.secure,
    user: config.user,
    password: config.password,
    fromEmail: config.fromEmail,
    fromName: config.fromName,
    to,
    subject,
    body,
  });
}

async function sendVerificationEmail(uid) {
  const user = await getUser(uid);
  if (!user.email || user.isAnonymous) {
    throw authError('Save an email and password before verifying this account.', 409);
  }
  if (user.emailVerified) return { alreadyVerified: true };
  const config = emailConfiguration();
  const token = await createEmailToken(uid, 'verify_email');
  await sendAccountEmail({
    to: user.email,
    subject: 'Verify your Tienda account',
    body: `Verify your Tienda email by opening this secure link: ${config.domain}/api/auth/email/verify?token=${encodeURIComponent(token)}\n\nThe link expires in one hour. If you did not request this, ignore this message.`,
  });
  return { sent: true };
}

async function verifyEmail(token) {
  if (typeof token !== 'string' || token.length < 40 || token.length > 128) {
    throw authError('This verification link is invalid or expired.', 400);
  }
  const client = await store.pool().connect();
  try {
    await client.query('BEGIN');
    const tokenResult = await client.query(
      `SELECT user_id FROM auth_email_tokens
       WHERE token_hash = $1 AND purpose = 'verify_email'
         AND expires_at > NOW()
       FOR UPDATE`,
      [digestToken(token)],
    );
    if (!tokenResult.rowCount) {
      throw authError('This verification link is invalid or expired.', 400);
    }
    const uid = tokenResult.rows[0].user_id;
    await client.query(
      `UPDATE auth_users SET email_verified = TRUE, updated_at = NOW()
       WHERE id = $1`,
      [uid],
    );
    await client.query(
      'DELETE FROM auth_email_tokens WHERE token_hash = $1',
      [digestToken(token)],
    );
    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    throw error;
  } finally {
    client.release();
  }
}

async function requestPasswordReset(email) {
  const normalizedEmail = normalizeEmail(email);
  if (!isValidEmail(normalizedEmail)) {
    throw authError('Enter a valid email address.', 400);
  }
  const config = emailConfiguration();
  const result = await store.pool().query(
    `SELECT id, email FROM auth_users
     WHERE email = $1 AND is_anonymous = FALSE`,
    [normalizedEmail],
  );
  if (!result.rowCount) return { accepted: true };
  const user = result.rows[0];
  const token = await createEmailToken(user.id, 'reset_password');
  await sendAccountEmail({
    to: user.email,
    subject: 'Reset your Tienda password',
    body: `Reset your Tienda password using this secure link: ${config.domain}/api/auth/password-reset?token=${encodeURIComponent(token)}\n\nThe link expires in 30 minutes. If you did not request this, ignore this message.`,
  });
  return { accepted: true };
}

async function resetPassword(token, password) {
  if (typeof token !== 'string' || token.length < 40 || token.length > 128) {
    throw authError('This password-reset link is invalid or expired.', 400);
  }
  if (!validatePassword(password)) {
    throw authError('Use a password with at least 12 characters.', 400);
  }
  const tokenHash = digestToken(token);
  const client = await store.pool().connect();
  try {
    await client.query('BEGIN');
    const tokenResult = await client.query(
      `SELECT user_id FROM auth_email_tokens
       WHERE token_hash = $1 AND purpose = 'reset_password'
         AND expires_at > NOW()
       FOR UPDATE`,
      [tokenHash],
    );
    if (!tokenResult.rowCount) {
      throw authError('This password-reset link is invalid or expired.', 400);
    }
    const uid = tokenResult.rows[0].user_id;
    const credentials = await hashPassword(password);
    await client.query(
      `UPDATE auth_users
       SET password_salt = $2, password_hash = $3, updated_at = NOW()
       WHERE id = $1`,
      [uid, credentials.salt, credentials.hash],
    );
    await client.query(
      `DELETE FROM auth_email_tokens WHERE user_id = $1`,
      [uid],
    );
    await client.query(
      `UPDATE auth_sessions SET revoked_at = NOW()
       WHERE user_id = $1 AND revoked_at IS NULL`,
      [uid],
    );
    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    throw error;
  } finally {
    client.release();
  }
}

function userFromSession(req) {
  return req.authUser;
}

module.exports = {
  authError,
  createDeviceSession,
  getUser,
  getUserByEmail,
  hashPassword,
  isValidEmail,
  normalizeEmail,
  readSession,
  requestPasswordReset,
  resetPassword,
  secureAnonymousAccount,
  setBusinessId,
  signIn,
  signOut,
  sendVerificationEmail,
  userFromSession,
  validatePassword,
  verifyPassword,
  verifyEmail,
};
