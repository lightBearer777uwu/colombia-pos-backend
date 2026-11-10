const CUSTOMER_REMINDER_OPTIONS = [30, 120, 1440];

function validateReminderSettings(settings) {
  if (settings.customerReminderEnabled !== undefined &&
      typeof settings.customerReminderEnabled !== 'boolean') {
    return 'Specify whether automatic customer appointment reminders are enabled.';
  }
  if (settings.customerReminderMinutesBefore !== undefined &&
      !CUSTOMER_REMINDER_OPTIONS.includes(settings.customerReminderMinutesBefore)) {
    return 'Choose a supported customer reminder time.';
  }
  return null;
}

function getCustomerReminderAt(startAt, minutesBefore, now = new Date()) {
  if (!(startAt instanceof Date) || !Number.isFinite(startAt.getTime()) ||
      !CUSTOMER_REMINDER_OPTIONS.includes(minutesBefore)) {
    return null;
  }
  const reminderAt = new Date(startAt.getTime() - minutesBefore * 60 * 1000);
  return reminderAt.getTime() >= now.getTime() - 5 * 60 * 1000
    ? reminderAt
    : null;
}

function validateVendorReminder(payload, now = new Date()) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    return 'Reminder details are required.';
  }
  const title = typeof payload.title === 'string' ? payload.title.trim() : '';
  const note = typeof payload.note === 'string' ? payload.note.trim() : '';
  const remindAt = typeof payload.remindAt === 'string'
    ? new Date(payload.remindAt)
    : null;
  if ((payload.note !== undefined && typeof payload.note !== 'string') ||
      title.length < 2 || title.length > 120 || note.length > 500 ||
      !remindAt || !Number.isFinite(remindAt.getTime()) ||
      remindAt <= now ||
      remindAt > new Date(now.getTime() + 366 * 24 * 60 * 60 * 1000)) {
    return 'Enter a reminder title and a future date within the next year.';
  }
  return null;
}

module.exports = {
  CUSTOMER_REMINDER_OPTIONS,
  getCustomerReminderAt,
  validateReminderSettings,
  validateVendorReminder,
};
