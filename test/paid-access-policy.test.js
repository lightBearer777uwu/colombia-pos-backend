const assert = require('node:assert/strict');
const test = require('node:test');

const {
  hasActivePosSubscription,
  isPaidAccessEnforcementEnabled,
} = require('../paid-access-policy');

test('paid-access enforcement is off when the control document is absent', () => {
  assert.equal(isPaidAccessEnforcementEnabled(null), false);
  assert.equal(isPaidAccessEnforcementEnabled(undefined), false);
});

test('paid-access enforcement requires an explicit boolean true', () => {
  assert.equal(
    isPaidAccessEnforcementEnabled({ paidAccessEnforcementEnabled: false }),
    false,
  );
  assert.equal(
    isPaidAccessEnforcementEnabled({ paidAccessEnforcementEnabled: 'true' }),
    false,
  );
  assert.equal(
    isPaidAccessEnforcementEnabled({ paidAccessEnforcementEnabled: true }),
    true,
  );
});

test('only active and trialing subscriptions grant paid POS access', () => {
  assert.equal(hasActivePosSubscription({ status: 'active' }), true);
  assert.equal(hasActivePosSubscription({ status: 'trialing' }), true);
  assert.equal(hasActivePosSubscription({ status: 'pending' }), false);
  assert.equal(hasActivePosSubscription({ status: 'past_due' }), false);
  assert.equal(hasActivePosSubscription({ status: 'canceled' }), false);
  assert.equal(hasActivePosSubscription(null), false);
});
