const crypto = require('crypto');

const CHANNELS = new Set(['whatsapp', 'sms', 'email']);

function isValidE164(value) {
  return typeof value === 'string' && /^\+[1-9]\d{7,14}$/.test(value);
}

function validateMessage(value) {
  if (typeof value !== 'string' || value.trim().length === 0 ||
      value.length > 4000) {
    return 'Message text must contain between 1 and 4000 characters.';
  }
  return null;
}

function verifyTwilioSignature(authToken, url, params, signature) {
  if (!authToken || !signature || !url || !params ||
      typeof params !== 'object') return false;
  const signed = Object.keys(params).sort().reduce(
    (value, key) => value + key + String(params[key]),
    url,
  );
  const expected = crypto.createHmac('sha1', authToken)
    .update(signed)
    .digest('base64');
  const expectedBuffer = Buffer.from(expected);
  const actualBuffer = Buffer.from(signature);
  return expectedBuffer.length === actualBuffer.length &&
    crypto.timingSafeEqual(expectedBuffer, actualBuffer);
}

function isValidReplyAddress(recipient, domain) {
  if (typeof recipient !== 'string' || typeof domain !== 'string') return false;
  const escapedDomain = domain.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(`^reply\\+[a-f0-9]{32}@${escapedDomain}$`, 'i')
    .test(recipient.trim());
}

async function sendTwilioMessage({
  accountSid,
  authToken,
  from,
  to,
  body,
  channel,
  whatsappContentSid,
  fetchImpl = fetch,
}) {
  if (!accountSid || !authToken || !from) {
    throw new Error('Twilio sender configuration is incomplete.');
  }
  if (!CHANNELS.has(channel) || channel === 'email') {
    throw new Error('A supported Twilio messaging channel is required.');
  }
  const sender = channel === 'whatsapp' ? `whatsapp:${from}` : from;
  const recipient = channel === 'whatsapp' ? `whatsapp:${to}` : to;
  const formFields = { From: sender, To: recipient };
  if (channel === 'whatsapp' && whatsappContentSid) {
    formFields.ContentSid = whatsappContentSid;
    formFields.ContentVariables = JSON.stringify({ 1: body });
  } else {
    formFields.Body = body;
  }
  const response = await fetchImpl(
    `https://api.twilio.com/2010-04-01/Accounts/${encodeURIComponent(accountSid)}/Messages.json`,
    {
      method: 'POST',
      headers: {
        Authorization: `Basic ${Buffer.from(`${accountSid}:${authToken}`).toString('base64')}`,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams(formFields),
      signal: AbortSignal.timeout(10000),
    },
  );
  const result = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(`Twilio message delivery failed (${response.status}).`);
  }
  return { id: result.sid || '', status: result.status || 'queued' };
}

async function sendSendGridEmail({
  apiKey,
  fromEmail,
  fromName,
  to,
  subject,
  body,
  replyTo,
  fetchImpl = fetch,
}) {
  if (!apiKey || !fromEmail) {
    throw new Error('SendGrid sender configuration is incomplete.');
  }
  const response = await fetchImpl('https://api.sendgrid.com/v3/mail/send', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      personalizations: [{ to: [{ email: to }] }],
      from: { email: fromEmail, ...(fromName ? { name: fromName } : {}) },
      reply_to: replyTo ? { email: replyTo } : undefined,
      subject,
      content: [{ type: 'text/plain', value: body }],
    }),
    signal: AbortSignal.timeout(10000),
  });
  if (!response.ok) {
    throw new Error(`SendGrid message delivery failed (${response.status}).`);
  }
  return {
    id: response.headers.get('x-message-id') || '',
    status: 'accepted',
  };
}

module.exports = {
  isValidE164,
  isValidReplyAddress,
  sendSendGridEmail,
  sendTwilioMessage,
  validateMessage,
  verifyTwilioSignature,
};
