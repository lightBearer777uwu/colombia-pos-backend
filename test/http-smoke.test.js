const assert = require('node:assert/strict');
const test = require('node:test');

const app = require('../server');

test('serves health and CORS preflight, and requires a session for the inbox', async (context) => {
  const server = app.listen(0);
  context.after(() => new Promise((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
  }));
  await new Promise((resolve) => server.once('listening', resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;

  const health = await fetch(`${origin}/health`);
  assert.equal(health.status, 200);
  assert.equal((await health.json()).status, 'ok');

  const preflight = await fetch(`${origin}/api/public/businesses/test-shop`, {
    method: 'OPTIONS',
    headers: {
      Origin: 'https://shop.example.com',
      'Access-Control-Request-Method': 'POST',
      'Access-Control-Request-Headers': 'content-type',
    },
  });
  assert.equal(preflight.status, 204);
  assert.equal(preflight.headers.get('access-control-allow-origin'), '*');

  const inbox = await fetch(`${origin}/api/business/conversations`);
  assert.equal(inbox.status, 401);
  const campaigns = await fetch(`${origin}/api/business/marketing-campaigns`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ channel: 'email', text: 'Sale', subject: 'Sale' }),
  });
  assert.equal(campaigns.status, 401);

  const channelStatus = await fetch(`${origin}/api/business/communications/status`);
  assert.equal(channelStatus.status, 401);

  const previousSecret = process.env.REMINDER_JOB_SECRET;
  process.env.REMINDER_JOB_SECRET = 'test-reminder-job-secret-with-32-chars';
  context.after(() => {
    if (previousSecret === undefined) {
      delete process.env.REMINDER_JOB_SECRET;
    } else {
      process.env.REMINDER_JOB_SECRET = previousSecret;
    }
  });
  const unauthorizedJob = await fetch(
    `${origin}/api/internal/appointment-reminders`,
    { method: 'POST', headers: { Authorization: 'Bearer invalid' } },
  );
  assert.equal(unauthorizedJob.status, 401);
});
