const assert = require('node:assert/strict');
const test = require('node:test');

const app = require('../server');

test('serves health, CORS preflight, and keeps inbox behind Firebase auth', async (context) => {
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
});
