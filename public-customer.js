const {
  getAppointmentSlotIds,
  isWithinBusinessHours,
  validateCustomerContact,
} = require('./customer-engagement');

const WEEKDAYS = ['sun', 'mon', 'tue', 'wed', 'thu', 'fri', 'sat'];

function isValidPublicBookingSlug(value) {
  return typeof value === 'string' &&
    /^[a-z0-9](?:[a-z0-9-]{1,48}[a-z0-9])?$/.test(value);
}

function zonedParts(date, timeZone) {
  const parts = new Intl.DateTimeFormat('en-CA', {
    timeZone,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    hourCycle: 'h23',
  }).formatToParts(date);
  return Object.fromEntries(parts.map(({ type, value }) => [type, value]));
}

function localDateTimeToUtc(date, time, timeZone) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date) ||
      !/^([01]\d|2[0-3]):[0-5]\d$/.test(time)) return null;
  const [year, month, day] = date.split('-').map(Number);
  const [hour, minute] = time.split(':').map(Number);
  const target = Date.UTC(year, month - 1, day, hour, minute);
  const normalized = new Date(target);
  if (normalized.getUTCFullYear() !== year ||
      normalized.getUTCMonth() !== month - 1 ||
      normalized.getUTCDate() !== day) return null;

  let guess = target;
  for (let attempt = 0; attempt < 4; attempt += 1) {
    const parts = zonedParts(new Date(guess), timeZone);
    const observed = Date.UTC(
      Number(parts.year),
      Number(parts.month) - 1,
      Number(parts.day),
      Number(parts.hour),
      Number(parts.minute),
    );
    guess += target - observed;
  }
  const result = new Date(guess);
  const parts = zonedParts(result, timeZone);
  if (Number(parts.year) !== year || Number(parts.month) !== month ||
      Number(parts.day) !== day || Number(parts.hour) !== hour ||
      Number(parts.minute) !== minute) return null;
  return result;
}

function getPublicAppointmentSlots(date, service, settings) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) return [];
  const [year, month, day] = date.split('-').map(Number);
  const weekday = WEEKDAYS[new Date(Date.UTC(year, month - 1, day)).getUTCDay()];
  const slots = [];
  for (const interval of settings.weeklyHours[weekday] || []) {
    const [startHour, startMinute] = interval.start.split(':').map(Number);
    const [endHour, endMinute] = interval.end.split(':').map(Number);
    const opening = startHour * 60 + startMinute;
    const closing = endHour * 60 + endMinute;
    for (let minute = opening; minute + service.durationMinutes <= closing; minute += 15) {
      const start = localDateTimeToUtc(
        date,
        `${String(Math.floor(minute / 60)).padStart(2, '0')}:${String(minute % 60).padStart(2, '0')}`,
        settings.timeZone,
      );
      if (!start) continue;
      const end = new Date(start.getTime() + service.durationMinutes * 60 * 1000);
      if (!getAppointmentSlotIds(start, service.durationMinutes) ||
          !isWithinBusinessHours(start, end, settings.timeZone, settings.weeklyHours)) continue;
      slots.push(start);
    }
  }
  return slots;
}

function validatePublicBooking(payload) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    return 'Booking details are required.';
  }
  if (typeof payload.serviceId !== 'string' ||
      payload.serviceId.length < 1 || payload.serviceId.length > 60) {
    return 'Choose a valid service.';
  }
  if (payload.aiConsent !== undefined && typeof payload.aiConsent !== 'boolean') {
    return 'Specify whether the customer agrees to private AI-assisted message drafts.';
  }
  const start = typeof payload.startAt === 'string' ? new Date(payload.startAt) : null;
  if (!start || !Number.isFinite(start.getTime()) || !getAppointmentSlotIds(start, 15)) {
    return 'Choose a valid appointment time in a 15-minute interval.';
  }
  const contactError = validateCustomerContact({
    name: payload.name,
    phone: payload.phone,
    email: payload.email,
    channels: payload.channels,
    serviceMessagesConsent: payload.serviceMessagesConsent,
    marketingConsent: payload.marketingConsent ?? false,
  });
  if (contactError) return contactError;
  if (payload.website) return 'Booking could not be completed.';
  return null;
}

module.exports = {
  getPublicAppointmentSlots,
  isValidPublicBookingSlug,
  localDateTimeToUtc,
  validatePublicBooking,
};
