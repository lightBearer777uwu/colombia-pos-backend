const CHANNELS = new Set(['whatsapp', 'sms', 'email']);
const WEEKDAYS = ['sun', 'mon', 'tue', 'wed', 'thu', 'fri', 'sat'];
const { validateReminderSettings } = require('./reminder-policy');

function isValidTimezone(timeZone) {
  if (typeof timeZone !== 'string' || timeZone.length > 100) return false;
  try {
    new Intl.DateTimeFormat('en-US', { timeZone }).format();
    return true;
  } catch {
    return false;
  }
}

function parseTime(value) {
  if (typeof value !== 'string' || !/^([01]\d|2[0-3]):[0-5]\d$/.test(value)) {
    return null;
  }
  const [hours, minutes] = value.split(':').map(Number);
  return hours * 60 + minutes;
}

function validateCustomerEngagementSettings(settings) {
  if (!settings || typeof settings !== 'object' || Array.isArray(settings)) {
    return 'Customer engagement settings are required.';
  }
  if (!isValidTimezone(settings.timeZone)) {
    return 'Choose a valid business time zone.';
  }
  if (!['manual_approval', 'auto_confirm'].includes(settings.bookingMode)) {
    return 'Choose whether bookings require vendor approval.';
  }
  if (typeof settings.bookingEnabled !== 'boolean') {
    return 'Specify whether customer bookings are enabled.';
  }
  if (settings.publicBookingEnabled !== undefined &&
      typeof settings.publicBookingEnabled !== 'boolean') {
    return 'Specify whether the public booking page is enabled.';
  }
  if (settings.publicBookingSlug !== undefined &&
      settings.publicBookingSlug !== '' &&
      (typeof settings.publicBookingSlug !== 'string' ||
        !/^[a-z0-9](?:[a-z0-9-]{1,48}[a-z0-9])?$/.test(settings.publicBookingSlug))) {
    return 'Use a public booking link with 3 to 50 lowercase letters, numbers, or hyphens.';
  }
  if (settings.publicBookingEnabled === true &&
      (typeof settings.publicBookingSlug !== 'string' ||
        !/^[a-z0-9](?:[a-z0-9-]{1,48}[a-z0-9])?$/.test(settings.publicBookingSlug))) {
    return 'Set a public booking link before enabling customer bookings.';
  }
  if (settings.publicBookingEnabled === true && settings.bookingEnabled !== true) {
    return 'Enable customer bookings before publishing the booking page.';
  }
  for (const number of [settings.smsNumber, settings.whatsappNumber]) {
    if (number !== undefined && number !== '' &&
        (typeof number !== 'string' || !/^\+[1-9]\d{7,14}$/.test(number))) {
      return 'Messaging sender numbers must use international E.164 format.';
    }
  }
  if (settings.aiEnabled !== undefined && typeof settings.aiEnabled !== 'boolean') {
    return 'Specify whether the private AI assistant is enabled.';
  }
  const reminderError = validateReminderSettings(settings);
  if (reminderError) return reminderError;

  const hours = settings.weeklyHours;
  if (!hours || typeof hours !== 'object' || Array.isArray(hours) ||
      Object.keys(hours).some((day) => !WEEKDAYS.includes(day))) {
    return 'Set valid weekly business hours.';
  }
  for (const day of WEEKDAYS) {
    const intervals = hours[day];
    if (!Array.isArray(intervals) || intervals.length > 3) {
      return 'Each weekday may have up to three opening-hour intervals.';
    }
    let previousEnd = -1;
    for (const interval of intervals) {
      const start = parseTime(interval?.start);
      const end = parseTime(interval?.end);
      if (start === null || end === null || start >= end || start < previousEnd) {
        return 'Business-hour intervals must be valid, ordered, and non-overlapping.';
      }
      previousEnd = end;
    }
  }

  if (!Array.isArray(settings.services) || settings.services.length > 100) {
    return 'Add between zero and 100 bookable services.';
  }
  const serviceIds = new Set();
  for (const service of settings.services) {
    if (!service || typeof service !== 'object' ||
        typeof service.id !== 'string' || !/^[a-zA-Z0-9_-]{1,60}$/.test(service.id) ||
        serviceIds.has(service.id) ||
        typeof service.name !== 'string' || service.name.trim().length < 2 ||
        service.name.trim().length > 100 ||
        !Number.isInteger(service.durationMinutes) ||
        service.durationMinutes < 15 || service.durationMinutes > 480 ||
        service.durationMinutes % 15 !== 0 ||
        typeof service.enabled !== 'boolean' ||
        (service.priceCop != null &&
          (!Number.isSafeInteger(service.priceCop) || service.priceCop < 0))) {
      return 'Each service needs a unique ID, name, 15-minute duration, and optional whole-COP price.';
    }
    serviceIds.add(service.id);
  }
  if (settings.publicBookingEnabled === true &&
      !settings.services.some((service) => service.enabled)) {
    return 'Enable at least one service before publishing online bookings.';
  }
  if (settings.publicBookingEnabled === true &&
      !WEEKDAYS.some((day) => settings.weeklyHours[day].length > 0)) {
    return 'Set business hours before publishing online bookings.';
  }
  return null;
}

function validateCustomerContact(contact) {
  if (!contact || typeof contact !== 'object' || Array.isArray(contact)) {
    return 'Customer contact details are required.';
  }
  const name = typeof contact.name === 'string' ? contact.name.trim() : '';
  const phone = typeof contact.phone === 'string' ? contact.phone.trim() : '';
  const email = typeof contact.email === 'string' ? contact.email.trim().toLowerCase() : '';
  const channels = contact.channels;
  if (name.length < 2 || name.length > 100 ||
      (phone && !/^\+[1-9]\d{7,14}$/.test(phone)) ||
      (email && !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) ||
      !Array.isArray(channels) || channels.length === 0 ||
      new Set(channels).size !== channels.length ||
      channels.some((channel) => !CHANNELS.has(channel)) ||
      channels.some((channel) =>
        (channel === 'whatsapp' || channel === 'sms') ? !phone : !email,
      )) {
    return 'Enter a name and valid contact details for each selected channel.';
  }
  if (contact.serviceMessagesConsent !== true) {
    return 'Record the customer’s explicit permission for service-related messages.';
  }
  if (typeof contact.marketingConsent !== 'boolean') {
    return 'Record whether the customer separately agreed to marketing messages.';
  }
  return null;
}

function getLocalDateParts(date, timeZone) {
  const parts = new Intl.DateTimeFormat('en-US', {
    timeZone,
    weekday: 'short',
    hour: '2-digit',
    minute: '2-digit',
    hourCycle: 'h23',
  }).formatToParts(date);
  const values = Object.fromEntries(parts.map(({ type, value }) => [type, value]));
  return {
    day: values.weekday.slice(0, 3).toLowerCase(),
    minutes: Number(values.hour) * 60 + Number(values.minute),
  };
}

function isWithinBusinessHours(start, end, timeZone, weeklyHours) {
  const localStart = getLocalDateParts(start, timeZone);
  const localEnd = getLocalDateParts(new Date(end.getTime() - 1), timeZone);
  if (localStart.day !== localEnd.day) return false;
  return (weeklyHours[localStart.day] || []).some((interval) => {
    const opening = parseTime(interval.start);
    const closing = parseTime(interval.end);
    return opening !== null && closing !== null &&
      localStart.minutes >= opening && localEnd.minutes < closing;
  });
}

function getAppointmentSlotIds(start, durationMinutes) {
  const startMs = start.getTime();
  if (startMs % (15 * 60 * 1000) !== 0) return null;
  const slotCount = durationMinutes / 15;
  return Array.from({ length: slotCount }, (_, index) =>
    String(startMs / (15 * 60 * 1000) + index),
  );
}

module.exports = {
  CHANNELS,
  getAppointmentSlotIds,
  isWithinBusinessHours,
  validateCustomerContact,
  validateCustomerEngagementSettings,
};
