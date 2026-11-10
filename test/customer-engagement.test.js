const assert = require('node:assert/strict');
const test = require('node:test');

const {
  getAppointmentSlotIds,
  isWithinBusinessHours,
  validateCustomerContact,
  validateCustomerEngagementSettings,
} = require('../customer-engagement');

const defaultSettings = {
  timeZone: 'America/Bogota',
  bookingMode: 'auto_confirm',
  bookingEnabled: true,
  weeklyHours: {
    mon: [{ start: '09:00', end: '17:00' }],
    tue: [{ start: '09:00', end: '17:00' }],
    wed: [{ start: '09:00', end: '17:00' }],
    thu: [{ start: '09:00', end: '17:00' }],
    fri: [{ start: '09:00', end: '17:00' }],
    sat: [],
    sun: [],
  },
  services: [{
    id: 'consultation',
    name: 'Consultation',
    durationMinutes: 30,
    priceCop: 50000,
    enabled: true,
  }],
};

test('validates vendor-controlled booking settings', () => {
  assert.equal(validateCustomerEngagementSettings(defaultSettings), null);
  assert.equal(validateCustomerEngagementSettings({
    ...defaultSettings,
    publicBookingEnabled: true,
    publicBookingSlug: 'moto-detailing',
  }), null);
  assert.match(validateCustomerEngagementSettings({
    ...defaultSettings,
    publicBookingEnabled: true,
    publicBookingSlug: '',
  }), /public booking link/);
  assert.match(validateCustomerEngagementSettings({
    ...defaultSettings,
    bookingEnabled: false,
    publicBookingEnabled: true,
    publicBookingSlug: 'moto-detailing',
  }), /Enable customer bookings/);
  assert.match(validateCustomerEngagementSettings({
    ...defaultSettings,
    publicBookingEnabled: true,
    publicBookingSlug: 'moto-detailing',
    services: defaultSettings.services.map((service) => ({
      ...service,
      enabled: false,
    })),
  }), /at least one service/);
  assert.match(validateCustomerEngagementSettings({
    ...defaultSettings,
    publicBookingEnabled: true,
    publicBookingSlug: 'moto-detailing',
    weeklyHours: {
      mon: [],
      tue: [],
      wed: [],
      thu: [],
      fri: [],
      sat: [],
      sun: [],
    },
  }), /Set business hours/);
  assert.match(
    validateCustomerEngagementSettings({
      ...defaultSettings,
      bookingMode: 'always',
    }),
    /vendor approval/,
  );
  assert.match(
    validateCustomerEngagementSettings({
      ...defaultSettings,
      weeklyHours: {
        ...defaultSettings.weeklyHours,
        mon: [{ start: '16:00', end: '10:00' }],
      },
    }),
    /valid, ordered, and non-overlapping/,
  );
  assert.match(
    validateCustomerEngagementSettings({
      ...defaultSettings,
      services: [{ ...defaultSettings.services[0], durationMinutes: 20 }],
    }),
    /15-minute duration/,
  );
});

test('validates customer appointment reminder preferences', () => {
  assert.equal(validateCustomerEngagementSettings({
    ...defaultSettings,
    customerReminderEnabled: true,
    customerReminderMinutesBefore: 120,
  }), null);
  assert.match(validateCustomerEngagementSettings({
    ...defaultSettings,
    customerReminderEnabled: 'yes',
  }), /automatic customer appointment reminders/);
  assert.match(validateCustomerEngagementSettings({
    ...defaultSettings,
    customerReminderMinutesBefore: 10,
  }), /supported customer reminder/);
});

test('requires explicit service-message and separate marketing consent', () => {
  const contact = {
    name: 'Customer',
    phone: '+573001234567',
    email: 'customer@example.com',
    channels: ['whatsapp', 'email'],
    serviceMessagesConsent: true,
    marketingConsent: false,
  };
  assert.equal(validateCustomerContact(contact), null);
  assert.match(
    validateCustomerContact({ ...contact, serviceMessagesConsent: false }),
    /explicit permission/,
  );
  assert.match(
    validateCustomerContact({ ...contact, channels: ['sms'], phone: '3001234567' }),
    /valid contact details/,
  );
  assert.match(
    validateCustomerContact({ ...contact, marketingConsent: undefined }),
    /separately agreed/,
  );
});

test('requires appointment duration to be covered by same-day configured hours', () => {
  const hours = { mon: [{ start: '09:00', end: '17:00' }] };
  assert.equal(
    isWithinBusinessHours(
      new Date('2026-11-09T15:00:00Z'),
      new Date('2026-11-09T15:30:00Z'),
      'America/Bogota',
      hours,
    ),
    true,
  );
  assert.equal(
    isWithinBusinessHours(
      new Date('2026-11-09T22:00:00Z'),
      new Date('2026-11-09T22:30:00Z'),
      'America/Bogota',
      hours,
    ),
    false,
  );
});

test('appointment locks reserve each 15-minute slot and reject unaligned starts', () => {
  const ids = getAppointmentSlotIds(
    new Date('2026-11-09T15:00:00Z'),
    45,
  );
  assert.deepEqual(ids, ['1993596', '1993597', '1993598']);
  assert.equal(
    getAppointmentSlotIds(new Date('2026-11-09T15:05:00Z'), 30),
    null,
  );
});
