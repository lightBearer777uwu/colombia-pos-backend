const assert = require('node:assert/strict');
const test = require('node:test');

const {
  getPublicAppointmentSlots,
  isValidPublicBookingSlug,
  localDateTimeToUtc,
  validatePublicBooking,
} = require('../public-customer');

const settings = {
  timeZone: 'America/Bogota',
  weeklyHours: { mon: [{ start: '09:00', end: '10:00' }] },
};

test('public booking slugs are URL-safe and bounded', () => {
  assert.equal(isValidPublicBookingSlug('moto-detailing-1'), true);
  assert.equal(isValidPublicBookingSlug('ab'), false);
  assert.equal(isValidPublicBookingSlug('../business'), false);
  assert.equal(isValidPublicBookingSlug('Uppercase'), false);
});

test('converts business local appointment times to UTC', () => {
  assert.equal(
    localDateTimeToUtc('2026-11-09', '09:00', 'America/Bogota').toISOString(),
    '2026-11-09T14:00:00.000Z',
  );
  assert.equal(localDateTimeToUtc('2026-02-30', '09:00', 'America/Bogota'), null);
  assert.equal(localDateTimeToUtc('2026-03-08', '02:30', 'America/New_York'), null);
});

test('builds only duration-compatible public availability slots', () => {
  const slots = getPublicAppointmentSlots(
    '2026-11-09',
    { durationMinutes: 30 },
    settings,
  );
  assert.equal(slots.length, 3);
  assert.equal(slots[0].toISOString(), '2026-11-09T14:00:00.000Z');
  assert.equal(slots[2].toISOString(), '2026-11-09T14:30:00.000Z');
});

test('public booking requires explicit valid message consent and rejects honeypots', () => {
  const booking = {
    serviceId: 'wash',
    startAt: '2026-11-09T14:00:00.000Z',
    name: 'Customer',
    phone: '+573001234567',
    email: '',
    channels: ['whatsapp'],
    serviceMessagesConsent: true,
    marketingConsent: false,
  };
  assert.equal(validatePublicBooking(booking), null);
  assert.match(
    validatePublicBooking({ ...booking, serviceMessagesConsent: false }),
    /explicit permission/,
  );
  assert.match(
    validatePublicBooking({ ...booking, aiConsent: 'yes' }),
    /private AI-assisted/,
  );
  assert.match(
    validatePublicBooking({ ...booking, website: 'spam' }),
    /could not be completed/,
  );
  assert.match(
    validatePublicBooking({ ...booking, startAt: '2026-11-09T14:07:00.000Z' }),
    /15-minute interval/,
  );
});
