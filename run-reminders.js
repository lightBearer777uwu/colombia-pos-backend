async function run() {
  const url = process.env.REMINDER_JOB_URL;
  const secret = process.env.REMINDER_JOB_SECRET;
  if (!url || !secret || secret.length < 32) {
    throw new Error('Configure REMINDER_JOB_URL and a 32-character REMINDER_JOB_SECRET.');
  }
  const target = new URL(url);
  if (target.protocol !== 'https:' || target.username || target.password) {
    throw new Error('REMINDER_JOB_URL must be an HTTPS URL without embedded credentials.');
  }

  const response = await fetch(target, {
    method: 'POST',
    headers: { Authorization: `Bearer ${secret}` },
    signal: AbortSignal.timeout(60000),
  });
  const body = await response.text();
  if (!response.ok) {
    throw new Error(`Reminder worker returned HTTP ${response.status}: ${body.slice(0, 500)}`);
  }
  console.log(body);
}

run().catch((error) => {
  console.error('Appointment reminder job failed:', error.message);
  process.exitCode = 1;
});
