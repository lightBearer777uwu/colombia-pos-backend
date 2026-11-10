const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const test = require('node:test');

const {
  isValidE164,
  isValidReplyAddress,
  sendSmtpEmail,
  sendTwilioMessage,
  validateMessage,
  verifyTwilioSignature,
} = require('../messaging');

test('validates international contact numbers and message bounds', () => {
  assert.equal(isValidE164('+573001234567'), true);
  assert.equal(isValidE164('3001234567'), false);
  assert.equal(validateMessage('Please confirm your booking.'), null);
  assert.match(validateMessage('  '), /between 1 and 4000/);
  assert.match(validateMessage('x'.repeat(4001)), /between 1 and 4000/);
});

test('verifies Twilio webhook signatures and rejects tampering', () => {
  const token = 'twilio-test-token';
  const url = 'https://api.example.com/webhook/twilio/inbound';
  const params = { From: '+573001234567', Body: 'Hello' };
  const signed = Object.keys(params).sort()
    .reduce((value, key) => value + key + params[key], url);
  const signature = crypto.createHmac('sha1', token).update(signed).digest('base64');
  assert.equal(verifyTwilioSignature(token, url, params, signature), true);
  assert.equal(verifyTwilioSignature(token, url, { ...params, Body: 'tampered' }, signature), false);
});

test('validates the opaque inbound-email reply address before routing', () => {
  assert.equal(isValidReplyAddress(`reply+${'a'.repeat(32)}@inbound.example.com`, 'inbound.example.com'), true);
  assert.equal(isValidReplyAddress('reply+bad@inbound.example.com', 'inbound.example.com'), false);
  assert.equal(isValidReplyAddress('attacker@example.com', 'inbound.example.com'), false);
});

test('sends through Twilio with channel-aware addressing', async () => {
  let request;
  const result = await sendTwilioMessage({
    accountSid: 'AC123',
    authToken: 'secret',
    from: '+15005550006',
    to: '+573001234567',
    body: 'Hello',
    channel: 'whatsapp',
    fetchImpl: async (url, options) => {
      request = { url, options };
      return { ok: true, json: async () => ({ sid: 'SM123', status: 'queued' }) };
    },
  });
  assert.equal(result.id, 'SM123');
  const form = new URLSearchParams(request.options.body);
  assert.equal(form.get('From'), 'whatsapp:+15005550006');
  assert.equal(form.get('To'), 'whatsapp:+573001234567');
});

test('uses the configured WhatsApp template for business-initiated messages', async () => {
  let request;
  await sendTwilioMessage({
    accountSid: 'AC123',
    authToken: 'secret',
    from: '+15005550006',
    to: '+573001234567',
    body: 'Your booking is confirmed.',
    channel: 'whatsapp',
    whatsappContentSid: 'HX123',
    fetchImpl: async (url, options) => {
      request = options;
      return { ok: true, json: async () => ({ sid: 'SM123' }) };
    },
  });
  const form = new URLSearchParams(request.body);
  assert.equal(form.get('ContentSid'), 'HX123');
  assert.equal(form.get('ContentVariables'), '{"1":"Your booking is confirmed."}');
  assert.equal(form.has('Body'), false);
});

test('sends plain-text email over authenticated SMTP', async () => {
  let transportOptions;
  let message;
  const result = await sendSmtpEmail({
    host: 'smtp.example.com',
    port: 587,
    secure: false,
    user: 'mailer@example.com',
    password: 'smtp-test-password',
    fromEmail: 'shop@example.com',
    fromName: 'Shop',
    to: 'customer@example.com',
    subject: 'Appointment',
    body: 'Confirmed',
    replyTo: `reply+${'a'.repeat(32)}@inbound.example.com`,
    transportFactory: (options) => {
      transportOptions = options;
      return {
        sendMail: async (value) => {
          message = value;
          return { messageId: '<message-123@example.com>' };
        },
      };
    },
  });
  assert.equal(result.id, '<message-123@example.com>');
  assert.equal(transportOptions.host, 'smtp.example.com');
  assert.equal(transportOptions.port, 587);
  assert.equal(transportOptions.requireTLS, true);
  assert.deepEqual(transportOptions.auth, {
    user: 'mailer@example.com',
    pass: 'smtp-test-password',
  });
  assert.equal(message.from.address, 'shop@example.com');
  assert.equal(message.from.name, 'Shop');
  assert.equal(message.replyTo, `reply+${'a'.repeat(32)}@inbound.example.com`);
  assert.equal(message.text, 'Confirmed');
});
