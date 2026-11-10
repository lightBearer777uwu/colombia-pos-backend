const assert = require('node:assert/strict');
const test = require('node:test');

const {
  CUSTOMER_REMINDER_OPTIONS,
  getCustomerReminderAt,
  validateReminderSettings,
  validateVendorReminder,
} = require('../reminder-policy');

const now = new Date('2026-11-09T15:00:00.000Z');

test('only allows supported customer reminder intervals', () => {
  assert.equal(validateReminderSettings({
    customerReminderEnabled: true,
    customerReminderMinutesBefore: 1440,
  }), null);
  assert.match(validateReminderSettings({
    customerReminderEnabled: 'yes',
  }), /Specify whether/);
  assert.match(validateReminderSettings({
    customerReminderMinutesBefore: 10,
  }), /supported customer reminder/);
  assert.deepEqual(CUSTOMER_REMINDER_OPTIONS, [30, 120, 1440]);
});

test('queues on-time customer reminders but skips stale ones', () => {
  assert.equal(
    getCustomerReminderAt(new Date('2026-11-10T15:00:00.000Z'), 1440, now)
      .toISOString(),
    now.toISOString(),
  );
  assert.equal(
    getCustomerReminderAt(new Date('2026-11-10T17:05:00.000Z'), 120, now)
      .toISOString(),
    '2026-11-10T15:05:00.000Z',
  );
  assert.equal(
    getCustomerReminderAt(new Date('2026-11-10T17:00:00.000Z'), 15, now),
    null,
  );
  assert.equal(
    getCustomerReminderAt(
      new Date('2026-11-10T14:40:00.000Z'),
      1440,
      now,
    ),
    null,
  );
});

test('validates vendor reminder content and future schedule', () => {
  const reminder = {
    title: 'Order supplies',
    note: 'Pick up detailing products',
    remindAt: '2026-11-10T15:00:00.000Z',
  };
  assert.equal(validateVendorReminder(reminder, now), null);
  assert.match(
    validateVendorReminder({ ...reminder, title: 'x' }, now),
    /future date/,
  );
  assert.match(
    validateVendorReminder({
      ...reminder,
      remindAt: '2026-11-09T14:00:00.000Z',
    }, now),
    /future date/,
  );
});
