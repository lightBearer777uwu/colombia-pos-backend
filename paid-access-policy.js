function isPaidAccessEnforcementEnabled(settings) {
  return settings?.paidAccessEnforcementEnabled === true;
}

function hasActivePosSubscription(subscription) {
  return ['active', 'trialing'].includes(subscription?.status);
}

module.exports = {
  hasActivePosSubscription,
  isPaidAccessEnforcementEnabled,
};
