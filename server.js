const express = require('express');
const Busboy = require('busboy');
const app = express();
const { cert, initializeApp } = require('firebase-admin/app');
const { getAuth } = require('firebase-admin/auth');
const { FieldValue, getFirestore: getAdminFirestore } = require('firebase-admin/firestore');
const crypto = require('crypto');
const {
  hasActivePosSubscription,
  isPaidAccessEnforcementEnabled,
} = require('./paid-access-policy');
const {
  getAppointmentSlotIds,
  isWithinBusinessHours,
  validateCustomerContact,
  validateCustomerEngagementSettings,
} = require('./customer-engagement');
const {
  getPublicAppointmentSlots,
  isValidPublicBookingSlug,
  validatePublicBooking,
} = require('./public-customer');
const {
  isValidE164,
  isValidReplyAddress,
  sendSendGridEmail,
  sendTwilioMessage,
  validateMessage,
  verifyTwilioSignature,
} = require('./messaging');

const stripe = process.env.STRIPE_SECRET_KEY
  ? require('stripe')(process.env.STRIPE_SECRET_KEY)
  : null;

app.set('trust proxy', 1);
const allowedWebOrigins = (process.env.WEB_APP_ORIGINS || '')
  .split(',')
  .map((origin) => origin.trim())
  .filter(Boolean);
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (!origin || allowedWebOrigins.length === 0 || allowedWebOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', allowedWebOrigins.length
      ? origin || allowedWebOrigins[0]
      : '*');
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type, X-Twilio-Signature');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
  }
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

function publicRateLimit({ limit, windowMs }) {
  const buckets = new Map();
  return (req, res, next) => {
    const now = Date.now();
    const key = `${req.ip}:${req.route?.path || req.path}`;
    let bucket = buckets.get(key);
    if (!bucket || now >= bucket.expiresAt) {
      bucket = { count: 0, expiresAt: now + windowMs };
      buckets.set(key, bucket);
    }
    bucket.count += 1;
    if (buckets.size > 20000) {
      for (const [candidate, value] of buckets) {
        if (now >= value.expiresAt) buckets.delete(candidate);
      }
    }
    res.setHeader('RateLimit-Limit', limit);
    res.setHeader('RateLimit-Remaining', Math.max(0, limit - bucket.count));
    if (bucket.count > limit) {
      res.setHeader('Retry-After', Math.ceil((bucket.expiresAt - now) / 1000));
      return res.status(429).json({ error: 'Too many requests. Please try again later.' });
    }
    next();
  };
}

let firebaseApp;
try {
  const serviceAccount = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
  if (serviceAccount) {
    firebaseApp = initializeApp({
      credential: cert(JSON.parse(serviceAccount)),
    });
  }
} catch (error) {
  console.error('Firebase Admin configuration is invalid:', error.message);
}

function getFirestore() {
  if (!firebaseApp) {
    const error = new Error('Firebase Admin is not configured on the server.');
    error.status = 503;
    throw error;
  }
  return getAdminFirestore(firebaseApp);
}

function requireStripe() {
  if (!stripe) {
    const error = new Error('Stripe is not configured on the server.');
    error.status = 503;
    throw error;
  }
  return stripe;
}

async function requireFirebaseAuth(req, res, next) {
  const authorization = req.headers.authorization || '';
  const match = authorization.match(/^Bearer (.+)$/i);
  if (!match) {
    return res.status(401).json({ error: 'A Firebase sign-in is required.' });
  }

  try {
    req.authUser = await getAuth(firebaseApp).verifyIdToken(match[1], true);
    next();
  } catch (error) {
    console.error('Firebase token verification failed:', error.message);
    res.status(401).json({ error: 'Your session is invalid or expired. Please sign in again.' });
  }
}

async function requireBusinessMember(req, res, next) {
  try {
    const db = getFirestore();
    const businessId = req.authUser.businessId || req.authUser.uid;
    const [business, membership] = await Promise.all([
      db.collection('businesses').doc(businessId).get(),
      db.collection('businesses').doc(businessId)
        .collection('members').doc(req.authUser.uid).get(),
    ]);

    if (!business.exists || !membership.exists || membership.data().active !== true) {
      return res.status(403).json({ error: 'This account is not an active member of a business.' });
    }

    req.businessId = businessId;
    req.business = business.data();
    req.memberRole = membership.data().role;
    req.memberPermissions = membership.data().permissions || {};
    next();
  } catch (error) {
    console.error('Business membership check failed:', error.message);
    res.status(error.status || 500).json({ error: error.message });
  }
}

function allowRoles(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.memberRole)) {
      return res.status(403).json({ error: 'Your business role does not allow this action.' });
    }
    next();
  };
}

function requirePermission(permission) {
  return (req, res, next) => {
    if (req.memberRole !== 'owner' && req.memberPermissions[permission] !== true) {
      return res.status(403).json({ error: `Your role does not have the ${permission} permission.` });
    }
    next();
  };
}

async function isPaidAccessEnforced() {
  const control = await getFirestore()
    .collection('platformSettings')
    .doc('accessControl')
    .get();
  return isPaidAccessEnforcementEnabled(control.exists ? control.data() : null);
}

async function requirePaidAccess(req, res, next) {
  try {
    if (!(await isPaidAccessEnforced())) {
      return next();
    }

    const subscription = req.business.subscription;
    if (!hasActivePosSubscription(subscription)) {
      return res.status(402).json({
        error: 'An active POS subscription is required to use paid business tools.',
        code: 'subscription_required',
        subscriptionStatus: subscription?.status || 'inactive',
      });
    }
    return next();
  } catch (error) {
    console.error('Paid-access policy lookup failed:', error);
    return res.status(503).json({
      error: 'Unable to verify POS subscription access. Please retry.',
    });
  }
}

async function getBusinessPaymentReadiness(businessId, business) {
  const db = getFirestore();
  const businessRef = db.collection('businesses').doc(businessId);
  const [wompiSnapshot, nequiSnapshot] = await Promise.all([
    businessRef.collection('privateIntegrations').doc('wompi').get(),
    businessRef.collection('privateIntegrations').doc('nequi').get(),
  ]);
  const providers = business.providers || {};
  const mercadoPago = providers.mercadoPago || {};
  const stripeAccount = providers.stripe || {};
  const bankTransfer = providers.bankTransfer || {};
  const wompi = wompiSnapshot.data() || {};
  const nequi = nequiSnapshot.data() || {};
  const mercadoPagoConnected = mercadoPago.status === 'connected' &&
    Boolean(mercadoPago.userId && mercadoPago.accessTokenEncrypted);
  const wompiConfigured = Boolean(
    wompiSnapshot.exists && wompi.publicKey && wompi.credentialsEncrypted,
  );
  const stripeOnboardingComplete = Boolean(stripeAccount.accountId) &&
    stripeAccount.status === 'active' &&
    stripeAccount.chargesEnabled === true &&
    stripeAccount.payoutsEnabled === true;

  return {
    mercado_pago: {
      ready: false,
      status: mercadoPagoConnected ? 'pending_verification' : 'not_connected',
      reason: mercadoPagoConnected
        ? 'The seller is connected, but live merchant approval and production payment capability are not verified.'
        : 'Connect a Mercado Pago seller account; a saved or incomplete connection is not payment verification.',
    },
    wompi: {
      ready: false,
      status: !wompiConfigured
        ? wompiSnapshot.exists ? 'configuration_incomplete' : 'not_configured'
        : wompi.environment === 'production'
          ? 'pending_verification'
          : wompi.environment === 'test'
            ? 'test_only'
            : 'configuration_incomplete',
      reason: !wompiConfigured
        ? wompiSnapshot.exists
          ? 'The Wompi configuration is incomplete.'
          : 'Wompi merchant credentials are not configured.'
        : wompi.environment === 'production'
          ? 'Production credentials are stored, but merchant approval and live payment readiness are not verified.'
          : wompi.environment === 'test'
            ? 'Wompi credentials are configured for testing, not production.'
            : 'The Wompi environment is not verified.',
    },
    stripe: {
      ready: false,
      status: stripeOnboardingComplete
        ? 'pending_verification'
        : stripeAccount.accountId ? 'onboarding' : 'not_connected',
      reason: stripeOnboardingComplete
        ? 'Stripe account flags are present, but Stripe Connect capability for Colombian connected accounts is not verified.'
        : stripeAccount.accountId
          ? 'Stripe account onboarding is not verified as complete for payments.'
          : 'No Stripe connected account is configured.',
    },
    nequi: {
      ready: false,
      status: nequiSnapshot.exists && nequi.credentialsEncrypted
        ? 'not_implemented'
        : 'not_configured',
      reason: nequiSnapshot.exists && nequi.credentialsEncrypted
        ? 'Saved credentials do not enable Nequi Push; this backend does not initiate payments or verify Nequi callbacks.'
        : 'Nequi merchant credentials are not configured, and Push payment verification is not implemented.',
    },
    bank_transfer: {
      ready: false,
      status: bankTransfer.alias ? 'manual_verification_required' : 'not_configured',
      reason: bankTransfer.alias
        ? 'A receiving key is stored, but it is not provider-verified and each deposit must be checked manually.'
        : 'No bank receiving key is configured.',
    },
  };
}

function requirePaymentProviderReadiness(providerId) {
  return async (req, res, next) => {
    try {
      const providers = await getBusinessPaymentReadiness(
        req.businessId,
        req.business,
      );
      const provider = providers[providerId];
      if (!provider?.ready) {
        return res.status(409).json({
          error: 'This payment method is unavailable until the provider confirms merchant readiness.',
          status: provider?.status || 'not_configured',
        });
      }
      next();
    } catch (error) {
      console.error(`Payment readiness check failed for ${providerId}:`, error);
      res.status(error.status || 500).json({
        error: 'Unable to verify this payment method.',
      });
    }
  };
}

function encryptProviderToken(value) {
  const key = Buffer.from(process.env.PROVIDER_TOKEN_ENCRYPTION_KEY || '', 'base64');
  if (key.length !== 32) {
    const error = new Error('Configure a 32-byte base64 PROVIDER_TOKEN_ENCRYPTION_KEY in Render.');
    error.status = 503;
    throw error;
  }
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]);
  return [iv, cipher.getAuthTag(), ciphertext].map((part) => part.toString('base64')).join('.');
}

function decryptProviderToken(value) {
  const key = Buffer.from(process.env.PROVIDER_TOKEN_ENCRYPTION_KEY || '', 'base64');
  const [iv, tag, ciphertext] = value.split('.').map((part) => Buffer.from(part, 'base64'));
  if (key.length !== 32 || !iv || !tag || !ciphertext) {
    throw new Error('Mercado Pago credentials are unavailable or invalid.');
  }
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
}

function signOAuthState(payload) {
  const secret = process.env.OAUTH_STATE_SECRET || '';
  if (secret.length < 32) {
    const error = new Error('Configure a 32-character OAUTH_STATE_SECRET in Render.');
    error.status = 503;
    throw error;
  }
  const encoded = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signature = crypto.createHmac('sha256', secret).update(encoded).digest('base64url');
  return `${encoded}.${signature}`;
}

function verifyOAuthState(state) {
  const secret = process.env.OAUTH_STATE_SECRET || '';
  if (secret.length < 32 || typeof state !== 'string') return null;
  const [encoded, signature] = state.split('.');
  if (!encoded || !signature) return null;
  const expected = crypto.createHmac('sha256', secret).update(encoded).digest();
  let received;
  try {
    received = Buffer.from(signature, 'base64url');
  } catch (_) {
    return null;
  }
  if (received.length !== expected.length || !crypto.timingSafeEqual(received, expected)) return null;
  try {
    const payload = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));
    if (Date.now() - payload.issuedAt > 10 * 60 * 1000) return null;
    return payload;
  } catch (_) {
    return null;
  }
}

async function getMercadoPagoAccessToken(businessId, provider) {
  if (!provider?.accessTokenEncrypted) {
    const error = new Error('Connect Mercado Pago before creating a checkout.');
    error.status = 409;
    throw error;
  }
  if (provider.expiresAt > Date.now() + 60_000) {
    return decryptProviderToken(provider.accessTokenEncrypted);
  }
  if (!provider.refreshTokenEncrypted) {
    const error = new Error('The Mercado Pago connection expired. Reconnect the seller account.');
    error.status = 409;
    throw error;
  }

  const response = await fetch('https://api.mercadopago.com/oauth/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      client_id: process.env.MERCADO_PAGO_CLIENT_ID,
      client_secret: process.env.MERCADO_PAGO_CLIENT_SECRET,
      grant_type: 'refresh_token',
      refresh_token: decryptProviderToken(provider.refreshTokenEncrypted),
    }),
  });
  const data = await response.json();
  if (!response.ok || !data.access_token) {
    const error = new Error('Mercado Pago could not refresh the seller connection.');
    error.status = 502;
    throw error;
  }
  await getFirestore().collection('businesses').doc(businessId).set({
    providers: {
      mercadoPago: {
        accessTokenEncrypted: encryptProviderToken(data.access_token),
        refreshTokenEncrypted: data.refresh_token
          ? encryptProviderToken(data.refresh_token)
          : provider.refreshTokenEncrypted,
        expiresAt: Date.now() + (Number(data.expires_in) || 0) * 1000,
        updatedAt: FieldValue.serverTimestamp(),
      },
    },
  }, { merge: true });
  return data.access_token;
}

// ==========================================
// STRIPE WEBHOOK HANDLER (MUST be before express.json())
// ==========================================
app.post('/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  if (!stripe || !process.env.STRIPE_WEBHOOK_SECRET) {
    return res.status(503).send('Stripe webhook is not configured.');
  }
  const sig = req.headers['stripe-signature'];
  let event;

  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error(`Webhook signature verification failed: ${err.message}`);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  try {
    switch (event.type) {
    case 'checkout.session.completed':
      console.log(`Checkout Session Completed! ID: ${event.data.object.id}`);
      if (event.data.object.mode === 'subscription' && event.data.object.metadata?.businessId) {
        await getFirestore().collection('businesses')
          .doc(event.data.object.metadata.businessId)
          .set({
            subscription: {
              status: event.data.object.payment_status === 'paid' ? 'active' : 'pending',
              checkoutSessionId: event.data.object.id,
              customerId: event.data.object.customer,
              subscriptionId: event.data.object.subscription,
              planId: event.data.object.metadata?.planId || null,
              updatedAt: FieldValue.serverTimestamp(),
            },
          }, { merge: true });
      }
      break;
    case 'invoice.paid':
      console.log(`Invoice Paid Successfully! ID: ${event.data.object.id}`);
      if (event.data.object.subscription) {
        const subscription = await stripe.subscriptions.retrieve(event.data.object.subscription);
        const businessId = subscription.metadata?.businessId;
        if (businessId) {
          await getFirestore().collection('businesses').doc(businessId).set({
            subscription: {
              status: 'active',
              subscriptionId: subscription.id,
              customerId: subscription.customer,
              planId: subscription.metadata?.planId || null,
              updatedAt: FieldValue.serverTimestamp(),
            },
          }, { merge: true });
        }
      }
      break;
    case 'customer.subscription.updated':
    case 'customer.subscription.deleted':
      console.log(`Subscription Cancelled/Ended: ${event.data.object.id}`);
      if (event.data.object.metadata?.businessId) {
        await getFirestore().collection('businesses')
          .doc(event.data.object.metadata.businessId)
          .set({
            subscription: {
              status: event.data.object.status,
              subscriptionId: event.data.object.id,
              planId: event.data.object.metadata?.planId || null,
              updatedAt: FieldValue.serverTimestamp(),
            },
          }, { merge: true });
      }
      break;
    case 'account.updated': {
      const account = event.data.object;
      const accounts = await getFirestore().collection('businesses')
        .where('providers.stripe.accountId', '==', account.id).limit(1).get();
      if (!accounts.empty) {
        const status = account.details_submitted && account.charges_enabled && account.payouts_enabled
          ? 'active'
          : 'onboarding';
        await accounts.docs[0].ref.set({
          providers: {
            stripe: {
              status,
              chargesEnabled: account.charges_enabled,
              payoutsEnabled: account.payouts_enabled,
              updatedAt: FieldValue.serverTimestamp(),
            },
          },
        }, { merge: true });
      }
      break;
    }
    case 'payment_intent.succeeded': {
      const intent = event.data.object;
      const businessId = intent.metadata?.businessId;
      if (businessId) {
        await getFirestore().collection('businesses').doc(businessId)
          .collection('transactions').doc(intent.id).set({
            service: intent.metadata.service || 'Servicio',
            vehicle: intent.metadata.vehicle || '',
            amount: intent.amount,
            currency: intent.currency.toUpperCase(),
            method: intent.metadata.paymentMethod || 'Stripe',
            provider: 'stripe',
            providerPaymentId: intent.id,
            status: 'paid',
            createdAt: FieldValue.serverTimestamp(),
            confirmedAt: FieldValue.serverTimestamp(),
          }, { merge: true });
      }
      break;
    }
      default:
        console.log(`Unhandled event type ${event.type}`);
    }
  } catch (error) {
    console.error('Stripe webhook processing failed:', error);
    return res.status(500).json({ error: 'Webhook processing failed.' });
  }

  res.json({ received: true });
});

app.use(express.json());

const publicReadLimit = publicRateLimit({ limit: 60, windowMs: 60 * 1000 });
const publicWriteLimit = publicRateLimit({ limit: 8, windowMs: 60 * 1000 });

async function recordInboundMessage({ db, businessId, customerSnapshot, channel, text }) {
  const customer = customerSnapshot.data();
  const conversation = await createConversation(
    db,
    businessId,
    customerSnapshot.id,
    channel,
    customer.name,
  );
  const conversationRef = db.collection('businesses').doc(businessId)
    .collection('conversations').doc(conversation.id);
  const messageRef = conversationRef.collection('messages').doc();
  await messageRef.create({
    channel,
    direction: 'inbound',
    text: text.slice(0, 4000),
    status: 'received',
    createdAt: FieldValue.serverTimestamp(),
  });
  await conversationRef.update({
    lastMessage: text.slice(0, 4000),
    lastMessageAt: FieldValue.serverTimestamp(),
    updatedAt: FieldValue.serverTimestamp(),
    unreadCount: FieldValue.increment(1),
  });
}

app.post('/webhook/twilio/inbound',
  express.urlencoded({ extended: false, limit: '64kb' }),
  async (req, res) => {
    try {
      const signature = req.headers['x-twilio-signature'];
      let webhookUrl;
      try {
        const origin = new URL(process.env.DOMAIN);
        if (origin.protocol !== 'https:' || origin.pathname !== '/' ||
            origin.search || origin.hash) throw new Error('Invalid DOMAIN');
        webhookUrl = `${origin.origin}/webhook/twilio/inbound`;
      } catch {
        return res.status(503).send('Webhook URL is not configured.');
      }
      if (!verifyTwilioSignature(
        process.env.TWILIO_AUTH_TOKEN,
        webhookUrl,
        req.body,
        signature,
      )) {
        return res.status(403).send('Invalid webhook signature.');
      }
      const rawFrom = req.body.From || '';
      const rawTo = req.body.To || '';
      const channel = rawFrom.startsWith('whatsapp:') ? 'whatsapp' : 'sms';
      const from = rawFrom.replace(/^whatsapp:/, '');
      const to = rawTo.replace(/^whatsapp:/, '');
      if (!isValidE164(from) || !isValidE164(to)) {
        return res.status(400).send('Invalid sender or recipient.');
      }
      const field = channel === 'whatsapp' ? 'whatsappNumber' : 'smsNumber';
      const db = getFirestore();
      const businesses = await db.collection('businesses')
        .where(`customerEngagement.${field}`, '==', to)
        .limit(2)
        .get();
      if (businesses.size !== 1) {
        return res.status(200).type('text/xml').send('<Response/>');
      }
      const business = businesses.docs[0];
      const customers = await business.ref.collection('customers')
        .where('phone', '==', from).limit(2).get();
      const customer = customers.docs.length === 1 ? customers.docs[0] : null;
      if (!customer) return res.status(200).type('text/xml').send('<Response/>');
      const permissions = customer.data();
      const normalizedBody = typeof req.body.Body === 'string'
        ? req.body.Body.trim().slice(0, 4000)
        : '';
      const stopWords = new Set(['STOP', 'STOPALL', 'UNSUBSCRIBE', 'CANCEL', 'END', 'QUIT']);
      if (stopWords.has(normalizedBody.toUpperCase())) {
        await customer.ref.update({
          channels: (permissions.channels || []).filter((item) => item !== channel),
          [`${channel}RevokedAt`]: FieldValue.serverTimestamp(),
          updatedAt: FieldValue.serverTimestamp(),
        });
        if (permissions.serviceMessagesConsent === true &&
            (permissions.channels || []).filter((item) => item !== channel).length === 0) {
          await customer.ref.update({
            serviceMessagesConsent: false,
            serviceMessagesRevokedAt: FieldValue.serverTimestamp(),
          });
        }
        return res.status(200).type('text/xml').send(
          '<Response><Message>You have been unsubscribed.</Message></Response>',
        );
      }
      if (permissions.serviceMessagesConsent !== true ||
          !(permissions.channels || []).includes(channel)) {
        return res.status(200).type('text/xml').send('<Response/>');
      }
      if (!normalizedBody) return res.status(200).type('text/xml').send('<Response/>');
      await recordInboundMessage({
        db,
        businessId: business.id,
        customerSnapshot: customer,
        channel,
        text: normalizedBody,
      });
      return res.status(200).type('text/xml').send('<Response/>');
    } catch (error) {
      console.error('Twilio inbound webhook failed:', error);
      return res.status(500).send('Webhook processing failed.');
    }
  });

app.post('/webhook/sendgrid/inbound/:secret',
  express.raw({ type: 'multipart/form-data', limit: '1mb' }),
  async (req, res) => {
    const expected = process.env.SENDGRID_INBOUND_WEBHOOK_SECRET || '';
    const actual = req.params.secret || '';
    const expectedBuffer = Buffer.from(expected);
    const actualBuffer = Buffer.from(actual);
    if (expectedBuffer.length < 32 || expectedBuffer.length !== actualBuffer.length ||
        !crypto.timingSafeEqual(expectedBuffer, actualBuffer)) {
      return res.status(403).send('Invalid webhook secret.');
    }
    if (!Buffer.isBuffer(req.body)) {
      return res.status(400).send('Expected a multipart message.');
    }
    try {
      const fields = {};
      await new Promise((resolve, reject) => {
        const parser = Busboy({ headers: req.headers, limits: { fieldSize: 64 * 1024, files: 5 } });
        parser.on('field', (name, value) => { fields[name] = value; });
        parser.on('file', (name, stream) => {
          stream.resume();
          stream.on('limit', () => reject(new Error('Inbound email attachment is too large.')));
        });
        parser.on('error', reject);
        parser.on('close', resolve);
        parser.end(req.body);
      });
      const domain = process.env.SENDGRID_INBOUND_DOMAIN || '';
      const recipients = String(fields.to || '').match(/[\w.+-]+@[\w.-]+/g) || [];
      const replyAddress = recipients.find((recipient) =>
        isValidReplyAddress(recipient, domain),
      );
      if (!replyAddress) return res.status(200).send('Message ignored.');
      const replyToken = replyAddress.match(/^reply\+([a-f0-9]{32})@/i)?.[1];
      if (!replyToken) return res.status(200).send('Message ignored.');
      const db = getFirestore();
      const route = await db.collection('conversationRoutes').doc(replyToken).get();
      if (!route.exists || route.data().channel !== 'email') {
        return res.status(200).send('Message ignored.');
      }
      const { businessId, conversationId } = route.data();
      const businessRef = db.collection('businesses').doc(businessId);
      const conversationRef = businessRef.collection('conversations').doc(conversationId);
      const [conversation, sender] = await Promise.all([
        conversationRef.get(),
        Promise.resolve(String(fields.from || '').match(/[\w.+-]+@[\w.-]+/)?.[0] || ''),
      ]);
      if (!conversation.exists || !sender) return res.status(200).send('Message ignored.');
      const customerRef = businessRef.collection('customers').doc(conversation.data().customerId);
      const customer = await customerRef.get();
      if (!customer.exists ||
          String(customer.data().email || '').toLowerCase() !== sender.toLowerCase() ||
          customer.data().serviceMessagesConsent !== true ||
          !(customer.data().channels || []).includes('email')) {
        return res.status(200).send('Message ignored.');
      }
      const text = String(fields.text || '').trim();
      if (!text) return res.status(200).send('Message ignored.');
      if (['stop', 'unsubscribe', 'remove me', 'cancel'].includes(text.toLowerCase())) {
        const remainingChannels = (customer.data().channels || [])
          .filter((channel) => channel !== 'email');
        await customerRef.update({
          channels: remainingChannels,
          emailRevokedAt: FieldValue.serverTimestamp(),
          marketingConsent: false,
          marketingRevokedAt: FieldValue.serverTimestamp(),
          ...(remainingChannels.length === 0 ? {
            serviceMessagesConsent: false,
            serviceMessagesRevokedAt: FieldValue.serverTimestamp(),
          } : {}),
          updatedAt: FieldValue.serverTimestamp(),
        });
        return res.status(200).send('Email contact permission removed.');
      }
      await recordInboundMessage({
        db,
        businessId,
        customerSnapshot: customer,
        channel: 'email',
        text,
      });
      return res.status(200).send('Message received.');
    } catch (error) {
      console.error('SendGrid inbound webhook failed:', error);
      return res.status(500).send('Webhook processing failed.');
    }
  });

app.get('/api/business/providers/wompi/credentials',
  requireFirebaseAuth, requireBusinessMember, allowRoles('owner'), requirePaidAccess,
  async (req, res) => {
    try {
      const snapshot = await getFirestore().collection('businesses').doc(req.businessId)
        .collection('privateIntegrations').doc('wompi').get();
      const integration = snapshot.data();
      res.json({
        configured: snapshot.exists,
        publicKey: integration?.publicKey || null,
        environment: integration?.environment || null,
        webhookUrl: integration?.webhookRoute
          ? `${new URL(process.env.DOMAIN).origin}/webhook/wompi/${integration.webhookRoute}`
          : null,
        updatedAt: integration?.updatedAt?.toDate?.()?.toISOString() || null,
      });
    } catch (error) {
      console.error('Wompi credential status check failed:', error);
      res.status(error.status || 500).json({ error: 'Unable to load Wompi setup status.' });
    }
  });

app.put('/api/business/providers/wompi/credentials',
  requireFirebaseAuth, requireBusinessMember, allowRoles('owner'), requirePaidAccess,
  async (req, res) => {
    const { publicKey, privateKey, integritySecret, eventsSecret } = req.body;
    const environment = typeof publicKey === 'string' && publicKey.startsWith('pub_test_')
      ? 'test'
      : typeof publicKey === 'string' && publicKey.startsWith('pub_prod_')
        ? 'production'
        : null;
    const secretPrefix = environment === 'test' ? 'test_' : 'prod_';
    if (!environment ||
        publicKey.trim().length > 500 ||
        typeof privateKey !== 'string' ||
        !privateKey.trim().startsWith(
          environment === 'test' ? 'prv_test_' : 'prv_prod_',
        ) ||
        privateKey.trim().length < 20 ||
        privateKey.length > 500 ||
        typeof integritySecret !== 'string' ||
        !integritySecret.trim().startsWith(`${secretPrefix}integrity_`) ||
        integritySecret.trim().length < 20 ||
        integritySecret.length > 500 ||
        typeof eventsSecret !== 'string' ||
        !eventsSecret.trim().startsWith(`${secretPrefix}events_`) ||
        eventsSecret.trim().length < 20 ||
        eventsSecret.length > 500) {
      return res.status(400).json({
        error: 'Enter the Wompi public key, integrity secret, and event secret for the same environment.',
      });
    }
    let webhookOrigin;
    try {
      webhookOrigin = new URL(process.env.DOMAIN);
    } catch (_) {
      return res.status(503).json({ error: 'Configure DOMAIN as the backend public HTTPS origin.' });
    }
    if (webhookOrigin.protocol !== 'https:' || webhookOrigin.pathname !== '/' ||
        webhookOrigin.search || webhookOrigin.hash) {
      return res.status(503).json({ error: 'Configure DOMAIN as the backend public HTTPS origin.' });
    }

    try {
      const db = getFirestore();
      const pendingPayments = await db.collection('businesses').doc(req.businessId)
        .collection('transactions').where('status', '==', 'pending').get();
      if (pendingPayments.docs.some((payment) => payment.data().provider === 'wompi')) {
        return res.status(409).json({
          error: 'Resolve pending Wompi payments before replacing merchant credentials.',
        });
      }
      const integrationRef = db.collection('businesses').doc(req.businessId)
        .collection('privateIntegrations').doc('wompi');
      const credentialsEncrypted = encryptProviderToken(JSON.stringify({
        privateKey: privateKey.trim(),
        integritySecret: integritySecret.trim(),
        eventsSecret: eventsSecret.trim(),
      }));
      const webhookRoute = await db.runTransaction(async (transaction) => {
        const previous = await transaction.get(integrationRef);
        const route = previous.data()?.webhookRoute || crypto.randomBytes(32).toString('hex');
        transaction.set(integrationRef, {
          publicKey: publicKey.trim(),
          environment,
          credentialsEncrypted,
          webhookRoute: route,
          updatedAt: FieldValue.serverTimestamp(),
        });
        transaction.set(db.collection('wompiWebhookRoutes').doc(route), {
          businessId: req.businessId,
        });
        return route;
      });
      res.json({
        configured: true,
        publicKey: publicKey.trim(),
        environment,
        webhookUrl: `${webhookOrigin.origin}/webhook/wompi/${webhookRoute}`,
      });
    } catch (error) {
      console.error('Wompi credentials could not be saved:', error.message);
      res.status(error.status || 500).json({
        error: error.status === 503
          ? error.message
          : 'Unable to securely save Wompi credentials.',
      });
    }
  });

app.delete('/api/business/providers/wompi/credentials',
  requireFirebaseAuth, requireBusinessMember, allowRoles('owner'), requirePaidAccess,
  async (req, res) => {
    try {
      const db = getFirestore();
      const pendingPayments = await db.collection('businesses').doc(req.businessId)
        .collection('transactions').where('status', '==', 'pending').get();
      if (pendingPayments.docs.some((payment) => payment.data().provider === 'wompi')) {
        return res.status(409).json({
          error: 'Resolve pending Wompi payments before disconnecting the merchant account.',
        });
      }
      const integrationRef = db.collection('businesses').doc(req.businessId)
        .collection('privateIntegrations').doc('wompi');
      const snapshot = await integrationRef.get();
      const webhookRoute = snapshot.data()?.webhookRoute;
      await integrationRef.delete();
      if (webhookRoute) {
        await db.collection('wompiWebhookRoutes').doc(webhookRoute).delete();
      }
      if (req.business.defaultPaymentMethod === 'wompi') {
        await db.collection('businesses').doc(req.businessId).set({
          defaultPaymentMethod: '',
          updatedAt: FieldValue.serverTimestamp(),
        }, { merge: true });
      }
      res.json({ configured: false });
    } catch (error) {
      console.error('Wompi credentials could not be removed:', error);
      res.status(error.status || 500).json({ error: 'Unable to remove Wompi credentials.' });
    }
  });

app.post('/api/business/wompi/create-payment', requireFirebaseAuth, requireBusinessMember,
  allowRoles('owner', 'cashier'), requirePermission('charge'), requirePaidAccess,
  requirePaymentProviderReadiness('wompi'), async (req, res) => {
    const { service, vehicle, amount } = req.body;
    if (typeof service !== 'string' || !service.trim() ||
        !Number.isSafeInteger(amount) || amount <= 0 ||
        !Number.isSafeInteger(amount * 100)) {
      return res.status(400).json({ error: 'A service and positive whole-COP amount are required.' });
    }

    let transactionRef;
    let reference;
    try {
      const db = getFirestore();
      const integrationSnapshot = await db.collection('businesses').doc(req.businessId)
        .collection('privateIntegrations').doc('wompi').get();
      const integration = integrationSnapshot.data();
      if (!integration?.publicKey || !integration.credentialsEncrypted) {
        return res.status(409).json({ error: 'Configure Wompi merchant credentials before creating a checkout.' });
      }

      const { integritySecret } = JSON.parse(decryptProviderToken(integration.credentialsEncrypted));
      transactionRef = db.collection('businesses').doc(req.businessId)
        .collection('transactions').doc();
      reference = `pos_${req.businessId}_${transactionRef.id}`;
      const amountInCents = amount * 100;
      const integritySignature = crypto.createHash('sha256')
        .update(`${reference}${amountInCents}COP${integritySecret}`)
        .digest('hex');
      const checkoutUrl = new URL('https://checkout.wompi.co/p/');
      checkoutUrl.searchParams.set('public-key', integration.publicKey);
      checkoutUrl.searchParams.set('currency', 'COP');
      checkoutUrl.searchParams.set('amount-in-cents', String(amountInCents));
      checkoutUrl.searchParams.set('reference', reference);
      checkoutUrl.searchParams.set('signature:integrity', integritySignature);

      await db.runTransaction(async (transaction) => {
        transaction.create(transactionRef, {
          service: service.trim(),
          vehicle: typeof vehicle === 'string' ? vehicle.trim() : '',
          amount,
          amountInCents,
          currency: 'COP',
          method: 'Wompi',
          provider: 'wompi',
          paymentEnvironment: integration.environment,
          providerReference: reference,
          status: 'pending',
          createdAt: FieldValue.serverTimestamp(),
        });
        transaction.create(db.collection('wompiPaymentReferences').doc(reference), {
          businessId: req.businessId,
          transactionId: transactionRef.id,
          createdAt: FieldValue.serverTimestamp(),
        });
      });

      res.status(201).json({
        transactionId: transactionRef.id,
        status: 'pending',
        checkoutUrl: checkoutUrl.toString(),
      });
    } catch (error) {
      if (transactionRef && reference) {
        await transactionRef.set({
          status: 'failed',
          updatedAt: FieldValue.serverTimestamp(),
        }, { merge: true }).catch((updateError) => {
          console.error('Failed to mark Wompi checkout as failed:', updateError);
        });
      }
      console.error('Wompi checkout creation failed:', error);
      res.status(error.status || 500).json({
        error: error.status === 503
          ? error.message
          : 'Wompi could not create checkout for this seller.',
      });
    }
  });

app.post('/webhook/wompi/:routeToken', async (req, res) => {
  try {
    if (!/^[a-f0-9]{64}$/.test(req.params.routeToken)) {
      return res.status(404).json({ error: 'Wompi webhook route was not found.' });
    }
    const db = getFirestore();
    const routeSnapshot = await db.collection('wompiWebhookRoutes')
      .doc(req.params.routeToken).get();
    if (!routeSnapshot.exists) {
      return res.status(404).json({ error: 'Wompi webhook route was not found.' });
    }

    const businessId = routeSnapshot.data().businessId;
    const integrationSnapshot = await db.collection('businesses').doc(businessId)
      .collection('privateIntegrations').doc('wompi').get();
    const integration = integrationSnapshot.data();
    if (!integration?.credentialsEncrypted) {
      return res.status(404).json({ error: 'Wompi merchant configuration was not found.' });
    }

    const { privateKey, eventsSecret } = JSON.parse(
      decryptProviderToken(integration.credentialsEncrypted),
    );
    const signature = req.body?.signature;
    const data = req.body?.data;
    if (    !Array.isArray(signature?.properties) || signature.properties.length === 0 ||
    signature.properties.length > 20 ||
    !Number.isSafeInteger(signature.timestamp) ||
        typeof signature.checksum !== 'string' ||
        !data || typeof data !== 'object') {
      return res.status(400).json({ error: 'Invalid Wompi event signature data.' });
    }

    const values = [];
    for (const property of signature.properties) {
      if (typeof property !== 'string' || !property || property.length > 200) {
        return res.status(400).json({ error: 'Invalid Wompi signature property.' });
      }
      const value = property.split('.').reduce(
        (current, key) => current && typeof current === 'object' ? current[key] : undefined,
        data,
      );
      if (value === undefined || value === null) {
        return res.status(400).json({ error: 'Wompi event is missing a signed property.' });
      }
      values.push(String(value));
    }

    const expected = crypto.createHash('sha256')
      .update(`${values.join('')}${signature.timestamp}${eventsSecret}`)
      .digest();
    const received = Buffer.from(signature.checksum, 'hex');
    if (received.length !== expected.length || !crypto.timingSafeEqual(received, expected)) {
      return res.status(401).json({ error: 'Wompi event signature verification failed.' });
    }

    if (req.body.event !== 'transaction.updated') {
      return res.json({ received: true });
    }
    if (!signature.properties.includes('transaction.id')) {
      return res.status(400).json({ error: 'Wompi transaction ID is not covered by the event signature.' });
    }
    const eventTransactionId = data.transaction?.id;
    if (typeof eventTransactionId !== 'string' || !eventTransactionId) {
      return res.status(400).json({ error: 'Wompi transaction ID is missing.' });
    }

    const apiOrigin = integration.environment === 'test'
      ? 'https://sandbox.wompi.co'
      : 'https://production.wompi.co';
    const providerResponse = await fetch(
      `${apiOrigin}/v1/transactions/${encodeURIComponent(eventTransactionId)}`,
      {
        headers: {
          Accept: 'application/json',
          Authorization: `Bearer ${privateKey}`,
        },
        signal: AbortSignal.timeout(10_000),
      },
    );
    const providerResult = await providerResponse.json();
    const providerTransaction = providerResult?.data;
    if (!providerResponse.ok || providerTransaction?.id !== eventTransactionId) {
      console.error('Wompi transaction lookup failed:', providerResponse.status);
      return res.status(502).json({ error: 'Unable to verify the Wompi transaction.' });
    }
    if (typeof providerTransaction.reference !== 'string') {
      return res.status(400).json({ error: 'Verified Wompi transaction reference is missing.' });
    }

    const referenceSnapshot = await db.collection('wompiPaymentReferences')
      .doc(providerTransaction.reference).get();
    if (!referenceSnapshot.exists || referenceSnapshot.data().businessId !== businessId) {
      return res.status(404).json({ error: 'Wompi payment reference was not found.' });
    }

    const referenceData = referenceSnapshot.data();
    const transactionRef = db.collection('businesses').doc(businessId)
      .collection('transactions').doc(referenceData.transactionId);
    await db.runTransaction(async (transaction) => {
      const paymentSnapshot = await transaction.get(transactionRef);
      if (!paymentSnapshot.exists || paymentSnapshot.data().provider !== 'wompi' ||
          paymentSnapshot.data().providerReference !== providerTransaction.reference) {
        const error = new Error('Wompi payment transaction does not match its reference.');
        error.status = 409;
        throw error;
      }

      const payment = paymentSnapshot.data();
      if (providerTransaction.amount_in_cents !== payment.amountInCents ||
          providerTransaction.currency !== 'COP') {
        const error = new Error('Wompi transaction amount does not match the requested payment.');
        error.status = 409;
        throw error;
      }
      if (payment.status === 'paid') return;

      const status = {
        APPROVED: integration.environment === 'test' ? 'test_paid' : 'paid',
        DECLINED: 'failed',
        ERROR: 'failed',
        VOIDED: 'failed',
        PENDING: 'pending',
      }[providerTransaction.status];
      if (!status) {
        console.error('Wompi sent an unsupported transaction status:', providerTransaction.status);
        return;
      }

      transaction.set(transactionRef, {
        status,
        providerPaymentId: String(providerTransaction.id || ''),
        updatedAt: FieldValue.serverTimestamp(),
        ...(status === 'paid' ? { confirmedAt: FieldValue.serverTimestamp() } : {}),
      }, { merge: true });
    });

    return res.json({ received: true });
  } catch (error) {
    console.error('Wompi webhook processing failed:', error);
    return res.status(error.status || 500).json({ error: 'Wompi webhook processing failed.' });
  }
});

app.post('/webhook/mercado-pago', async (req, res) => {
  const secret = process.env.MERCADO_PAGO_WEBHOOK_SECRET;
  const paymentId = String(req.query['data.id'] || req.body?.data?.id || '');
  const requestId = req.headers['x-request-id'];
  const signatureHeader = req.headers['x-signature'];
  if (!secret) return res.status(503).json({ error: 'Mercado Pago webhook is not configured.' });
  if (!paymentId || typeof requestId !== 'string' || typeof signatureHeader !== 'string') {
    return res.status(400).json({ error: 'Invalid Mercado Pago notification.' });
  }

  const signatureParts = Object.fromEntries(
    signatureHeader.split(',').map((part) => part.trim().split('=', 2)),
  );
  const manifest = `id:${paymentId};request-id:${requestId};ts:${signatureParts.ts};`;
  const expected = crypto.createHmac('sha256', secret).update(manifest).digest();
  const received = Buffer.from(signatureParts.v1 || '', 'hex');
  if (received.length !== expected.length || !crypto.timingSafeEqual(received, expected)) {
    return res.status(401).json({ error: 'Mercado Pago signature verification failed.' });
  }

  try {
    const db = getFirestore();
    const sellerId = req.body?.user_id || req.query.user_id;
    if (!sellerId) return res.status(400).json({ error: 'Missing Mercado Pago seller ID.' });
    const businesses = await db.collection('businesses')
      .where('providers.mercadoPago.userId', '==', String(sellerId)).limit(1).get();
    if (businesses.empty) return res.status(404).json({ error: 'Connected seller was not found.' });

    const business = businesses.docs[0];
    const provider = business.data().providers?.mercadoPago;
    const token = await getMercadoPagoAccessToken(business.id, provider);
    const paymentResponse = await fetch(`https://api.mercadopago.com/v1/payments/${encodeURIComponent(paymentId)}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    const payment = await paymentResponse.json();
    if (!paymentResponse.ok || String(payment.collector_id) !== String(sellerId)) {
      return res.status(502).json({ error: 'Could not verify payment with Mercado Pago.' });
    }
    const [paymentBusinessId, transactionId] = String(payment.external_reference || '').split(':');
    if (paymentBusinessId !== business.id || !transactionId) {
      return res.status(400).json({ error: 'Payment reference does not match this business.' });
    }

    const transactionRef = business.ref.collection('transactions').doc(transactionId);
    let resultStatus;
    await db.runTransaction(async (firestoreTransaction) => {
      const currentSnapshot = await firestoreTransaction.get(transactionRef);
      if (!currentSnapshot.exists || currentSnapshot.data().provider !== 'mercado_pago') {
        const error = new Error('Payment transaction was not found.');
        error.status = 404;
        throw error;
      }

      const currentPayment = currentSnapshot.data();
      const matchesOrder = String(payment.id) === paymentId &&
        payment.transaction_amount === currentPayment.amount &&
        payment.currency_id === currentPayment.currency;
      if (!matchesOrder) {
        resultStatus = 'review';
        firestoreTransaction.set(transactionRef, {
          status: 'review',
          reviewReason: 'mercado_pago_amount_or_currency_mismatch',
          providerPaymentId: String(payment.id),
          confirmedAt: FieldValue.delete(),
          updatedAt: FieldValue.serverTimestamp(),
        }, { merge: true });
        return;
      }

      if (currentPayment.status === 'paid') {
        resultStatus = 'paid';
        return;
      }

      resultStatus = payment.status === 'approved' ? 'paid' : payment.status || 'pending';
      firestoreTransaction.set(transactionRef, {
        status: resultStatus,
        reviewReason: FieldValue.delete(),
        providerPaymentId: String(payment.id),
        ...(resultStatus === 'paid' ? { confirmedAt: FieldValue.serverTimestamp() } : {}),
        updatedAt: FieldValue.serverTimestamp(),
      }, { merge: true });
    });
    res.json({ received: true, status: resultStatus });
  } catch (error) {
    console.error('Mercado Pago webhook processing failed:', error);
    res.status(error.status || 500).json({ error: 'Webhook processing failed.' });
  }
});

app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    revision: process.env.RENDER_GIT_COMMIT || null,
    firebaseConfigured: Boolean(firebaseApp),
    stripeConfigured: Boolean(stripe),
  });
});

app.post('/api/business/bootstrap', requireFirebaseAuth, async (req, res) => {
  try {
    const db = getFirestore();
    const uid = req.authUser.uid;
    const claimedBusinessId = req.authUser.businessId;
    if (typeof claimedBusinessId === 'string' && claimedBusinessId.length > 0) {
      const [business, membership] = await Promise.all([
        db.collection('businesses').doc(claimedBusinessId).get(),
        db.collection('businesses').doc(claimedBusinessId)
          .collection('members').doc(uid).get(),
      ]);
      if (!business.exists || !membership.exists || membership.data().active !== true) {
        return res.status(403).json({ error: 'This account is not an active member of a business.' });
      }
      return res.json({ businessId: claimedBusinessId, role: membership.data().role });
    }

    const businessRef = db.collection('businesses').doc(uid);
    const memberRef = businessRef.collection('members').doc(uid);
    await db.runTransaction(async (transaction) => {
      const [business, membership] = await Promise.all([
        transaction.get(businessRef),
        transaction.get(memberRef),
      ]);

      if (business.exists || membership.exists) {
        if (business.exists && membership.exists && membership.data().active === true) return;
        const error = new Error('This account has an incomplete or inactive business membership.');
        error.status = 403;
        throw error;
      }

      transaction.create(businessRef, {
        ownerUid: uid,
        name: (req.authUser.name || req.authUser.email || 'Mi negocio').trim(),
        createdAt: FieldValue.serverTimestamp(),
        updatedAt: FieldValue.serverTimestamp(),
      });
      transaction.create(memberRef, {
        uid,
        email: req.authUser.email || '',
        role: 'owner',
        active: true,
        permissions: {
          charge: true,
          viewInventory: true,
          manageInventory: true,
          viewReports: true,
          managePayments: true,
        },
      });
    });

    res.json({ businessId: uid, role: 'owner' });
  } catch (error) {
    console.error('Business bootstrap failed:', error);
    res.status(error.status || 500).json({ error: error.message });
  }
});

app.get('/api/business/me', requireFirebaseAuth, requireBusinessMember, async (req, res) => {
  try {
    const wompiIntegration = await getFirestore().collection('businesses')
      .doc(req.businessId).collection('privateIntegrations').doc('wompi').get();
    res.json({
      businessId: req.businessId,
      name: req.business.name,
      role: req.memberRole,
      permissions: req.memberPermissions,
      providers: {
        ...(req.business.providers || {}),
        wompi: {
          configured: wompiIntegration.exists,
          environment: wompiIntegration.data()?.environment || null,
        },
      },
      businessProfile: req.business.businessProfile || {},
      defaultPaymentMethod: req.business.defaultPaymentMethod || '',
      subscription: req.business.subscription || { status: 'inactive' },
    });
  } catch (error) {
    console.error('Business context lookup failed:', error);
    res.status(error.status || 500).json({ error: 'Unable to load the business profile.' });
  }
});

app.get('/api/business/payment-readiness',
  requireFirebaseAuth, requireBusinessMember, async (req, res) => {
    try {
      const providers = await getBusinessPaymentReadiness(
        req.businessId,
        req.business,
      );
      res.json({ providers });
    } catch (error) {
      console.error('Payment readiness lookup failed:', error);
      res.status(error.status || 500).json({ error: 'Unable to load payment readiness.' });
    }
  });

function getCustomerEngagementSettings(business) {
  return business.customerEngagement || {
    timeZone: 'America/Bogota',
    bookingEnabled: false,
    bookingMode: 'manual_approval',
    publicBookingEnabled: false,
    publicBookingSlug: '',
    weeklyHours: {
      sun: [],
      mon: [],
      tue: [],
      wed: [],
      thu: [],
      fri: [],
      sat: [],
    },
    services: [],
    smsNumber: '',
    whatsappNumber: '',
    aiEnabled: false,
  };
}

app.get('/api/business/customer-engagement/settings',
  requireFirebaseAuth, requireBusinessMember, requirePaidAccess, async (req, res) => {
    const settings = getCustomerEngagementSettings(req.business);
    res.json({
      settings,
      aiStatus: settings.aiEnabled ? 'drafts_only' : 'disabled',
      publicBookingUrl: req.business.customerEngagement?.publicBookingEnabled === true &&
        process.env.PUBLIC_APP_URL
        ? `${process.env.PUBLIC_APP_URL.replace(/\/$/, '')}/book/${req.business.customerEngagement.publicBookingSlug}`
        : null,
      aiAvailable: process.env.PRIVATE_AI_ENABLED === 'true' &&
        Boolean(process.env.PRIVATE_AI_URL && process.env.PRIVATE_AI_API_KEY),
      messagingChannels: ['whatsapp', 'email', 'sms'],
    });
  });

app.put('/api/business/customer-engagement/settings',
  requireFirebaseAuth, requireBusinessMember, allowRoles('owner'), requirePaidAccess,
  async (req, res) => {
    const validationError = validateCustomerEngagementSettings(req.body);
    if (validationError) return res.status(400).json({ error: validationError });

    const settings = {
      timeZone: req.body.timeZone,
      bookingEnabled: req.body.bookingEnabled,
      bookingMode: req.body.bookingMode,
      publicBookingEnabled: req.body.publicBookingEnabled === true,
      publicBookingSlug: req.body.publicBookingSlug || '',
      weeklyHours: req.body.weeklyHours,
      smsNumber: req.body.smsNumber || '',
      whatsappNumber: req.body.whatsappNumber || '',
      services: req.body.services.map((service) => ({
        id: service.id,
        name: service.name.trim(),
        durationMinutes: service.durationMinutes,
        priceCop: service.priceCop ?? null,
        enabled: service.enabled,
      })),
      aiEnabled: req.body.aiEnabled === true &&
        process.env.PRIVATE_AI_ENABLED === 'true' &&
        Boolean(process.env.PRIVATE_AI_URL && process.env.PRIVATE_AI_API_KEY),
    };
    try {
      const db = getFirestore();
      const businessRef = db.collection('businesses').doc(req.businessId);
      const oldSlug = req.business.customerEngagement?.publicBookingSlug || '';
      const newSlug = settings.publicBookingEnabled
        ? settings.publicBookingSlug
        : '';
      const oldSlugRef = oldSlug
        ? db.collection('publicBookingSlugs').doc(oldSlug)
        : null;
      const newSlugRef = newSlug
        ? db.collection('publicBookingSlugs').doc(newSlug)
        : null;
      await db.runTransaction(async (transaction) => {
        const [oldSlugSnapshot, newSlugSnapshot] = await Promise.all([
          oldSlugRef ? transaction.get(oldSlugRef) : Promise.resolve(null),
          newSlugRef ? transaction.get(newSlugRef) : Promise.resolve(null),
        ]);
        if (newSlugSnapshot?.exists &&
            newSlugSnapshot.data().businessId !== req.businessId) {
          const error = new Error('That public booking link is already in use.');
          error.status = 409;
          throw error;
        }
        transaction.set(businessRef, {
          customerEngagement: settings,
          updatedAt: FieldValue.serverTimestamp(),
        }, { merge: true });
        if (newSlugRef) {
          transaction.set(newSlugRef, { businessId: req.businessId });
        }
        if (oldSlugRef && oldSlug !== newSlug &&
            oldSlugSnapshot?.data()?.businessId === req.businessId) {
          transaction.delete(oldSlugRef);
        }
      });
      res.json({
        settings,
        aiStatus: settings.aiEnabled ? 'drafts_only' : 'disabled',
        aiAvailable: process.env.PRIVATE_AI_ENABLED === 'true' &&
          Boolean(process.env.PRIVATE_AI_URL && process.env.PRIVATE_AI_API_KEY),
        publicBookingUrl: settings.publicBookingEnabled && process.env.PUBLIC_APP_URL
          ? `${process.env.PUBLIC_APP_URL.replace(/\/$/, '')}/book/${settings.publicBookingSlug}`
          : null,
      });
    } catch (error) {
      console.error('Customer engagement settings could not be saved:', error);
      res.status(error.status || 500).json({ error: error.status ? error.message : 'Unable to save customer engagement settings.' });
    }
  });

async function findPublicBusiness(db, slug) {
  if (!isValidPublicBookingSlug(slug)) return null;
  const slugSnapshot = await db.collection('publicBookingSlugs').doc(slug).get();
  if (!slugSnapshot.exists) return null;
  const businessSnapshot = await db.collection('businesses')
    .doc(slugSnapshot.data().businessId).get();
  if (!businessSnapshot.exists) return null;
  const business = businessSnapshot.data();
  const settings = getCustomerEngagementSettings(business);
  if (!settings.publicBookingEnabled || !settings.bookingEnabled) return null;
  return {
    businessId: businessSnapshot.id,
    business,
    settings,
  };
}

async function publicBusinessHasPaidAccess(business) {
  if (!(await isPaidAccessEnforced())) return true;
  return hasActivePosSubscription(business.business.subscription);
}

async function createConversation(db, businessId, customerId, channel, customerName) {
  const businessRef = db.collection('businesses').doc(businessId);
  const conversationRef = businessRef.collection('conversations')
    .doc(`${customerId}_${channel}`);
  const existing = await conversationRef.get();
  if (existing.exists) return existing;

  const replyToken = crypto.randomBytes(16).toString('hex');
  const conversation = {
    customerId,
    customerName,
    channel,
    status: 'open',
    unreadCount: 0,
    replyToken,
    createdAt: FieldValue.serverTimestamp(),
    updatedAt: FieldValue.serverTimestamp(),
  };
  await db.runTransaction(async (transaction) => {
    const current = await transaction.get(conversationRef);
    if (current.exists) return;
    transaction.create(conversationRef, conversation);
    transaction.create(
      db.collection('conversationRoutes').doc(replyToken),
      { businessId, conversationId: conversationRef.id, channel },
    );
  });
  return conversationRef.get();
}

async function sendBusinessMessage({
  db,
  businessId,
  customerId,
  customer,
  channel,
  text,
  senderUid,
}) {
  const validationError = validateMessage(text);
  if (validationError) {
    const error = new Error(validationError);
    error.status = 400;
    throw error;
  }
  if (!['whatsapp', 'sms', 'email'].includes(channel) ||
      customer.serviceMessagesConsent !== true ||
      !(customer.channels || []).includes(channel)) {
    const error = new Error('The customer has not consented to this service-message channel.');
    error.status = 403;
    throw error;
  }
  const target = channel === 'email' ? customer.email : customer.phone;
  if (!target) {
    const error = new Error('The customer has no contact address for this channel.');
    error.status = 400;
    throw error;
  }

  const businessRef = db.collection('businesses').doc(businessId);
  const businessSnapshot = await businessRef.get();
  if (!businessSnapshot.exists) {
    const error = new Error('Business not found.');
    error.status = 404;
    throw error;
  }
  const business = businessSnapshot.data();
  const settings = getCustomerEngagementSettings(business);
  const conversation = await createConversation(
    db,
    businessId,
    customerId,
    channel,
    customer.name,
  );
  const messageRef = businessRef.collection('conversations')
    .doc(conversation.id).collection('messages').doc();
  const initialMessage = {
    channel,
    direction: 'outbound',
    text: text.trim(),
    status: 'sending',
    senderUid,
    createdAt: FieldValue.serverTimestamp(),
  };
  await messageRef.create(initialMessage);

  try {
    let delivery;
    if (channel === 'email') {
      if (!process.env.SENDGRID_INBOUND_DOMAIN) {
        throw new Error('SendGrid inbound reply domain is not configured.');
      }
      delivery = await sendSendGridEmail({
        apiKey: process.env.SENDGRID_API_KEY,
        fromEmail: process.env.SENDGRID_FROM_EMAIL,
        fromName: business.name || 'Tienda',
        to: target,
        subject: `Mensaje de ${business.name || 'tu negocio'}`,
        body: text.trim(),
        replyTo: `reply+${conversation.data().replyToken}@${process.env.SENDGRID_INBOUND_DOMAIN}`,
      });
    } else {
      const from = channel === 'whatsapp'
        ? settings.whatsappNumber
        : settings.smsNumber;
      delivery = await sendTwilioMessage({
        accountSid: process.env.TWILIO_ACCOUNT_SID,
        authToken: process.env.TWILIO_AUTH_TOKEN,
        from,
        to: target,
        body: text.trim(),
        channel,
        whatsappContentSid: process.env.TWILIO_WHATSAPP_CONTENT_SID,
      });
    }
    await messageRef.update({
      status: delivery.status,
      providerMessageId: delivery.id || '',
      deliveredAt: FieldValue.serverTimestamp(),
    });
    await conversation.ref.update({
      lastMessage: text.trim(),
      lastMessageAt: FieldValue.serverTimestamp(),
      updatedAt: FieldValue.serverTimestamp(),
    });
    return { conversationId: conversation.id, messageId: messageRef.id, status: delivery.status };
  } catch (error) {
    await messageRef.update({
      status: 'failed',
      deliveryError: error.message,
      failedAt: FieldValue.serverTimestamp(),
    });
    await conversation.ref.update({
      lastMessage: text.trim(),
      lastMessageAt: FieldValue.serverTimestamp(),
      updatedAt: FieldValue.serverTimestamp(),
    });
    throw error;
  }
}

async function notifyAppointmentCustomer(db, businessId, appointment) {
  try {
    const customerSnapshot = await db.collection('businesses').doc(businessId)
      .collection('customers').doc(appointment.customerId).get();
    if (!customerSnapshot.exists || customerSnapshot.data().serviceMessagesConsent !== true) {
      return 'not_sent';
    }
    const customer = customerSnapshot.data();
    const channel = (customer.channels || []).find((item) =>
      ['whatsapp', 'sms', 'email'].includes(item),
    );
    if (!channel) return 'not_sent';
    const startsAt = appointment.startAt.toDate
      ? appointment.startAt.toDate()
      : new Date(appointment.startAt);
    const localTime = new Intl.DateTimeFormat('es-CO', {
      timeZone: appointment.timeZone,
      dateStyle: 'long',
      timeStyle: 'short',
    }).format(startsAt);
    const statusText = {
      confirmed: 'confirmed',
      pending_vendor: 'awaiting business approval',
      declined: 'was declined',
      cancelled: 'was cancelled',
    }[appointment.status] || appointment.status;
    const result = await sendBusinessMessage({
      db,
      businessId,
      customerId: appointment.customerId,
      customer,
      channel,
      text: `Your ${appointment.serviceName} appointment ${statusText}: ${localTime} (${appointment.timeZone}).`,
      senderUid: 'system:appointment',
    });
    return result.status;
  } catch (error) {
    console.error('Appointment status message could not be delivered:', error.message);
    return 'failed';
  }
}

app.get('/api/public/businesses/:slug',
  publicReadLimit, async (req, res) => {
    try {
      const business = await findPublicBusiness(getFirestore(), req.params.slug);
      if (!business) return res.status(404).json({ error: 'Public booking page not found.' });
      res.json({
        business: {
          name: business.business.name || 'Business',
          timeZone: business.settings.timeZone,
          services: business.settings.services
            .filter((service) => service.enabled)
            .map(({ id, name, durationMinutes, priceCop }) => ({
              id, name, durationMinutes, priceCop,
            })),
          aiAvailable: business.settings.aiEnabled === true &&
            process.env.PRIVATE_AI_ENABLED === 'true' &&
            Boolean(process.env.PRIVATE_AI_URL && process.env.PRIVATE_AI_API_KEY),
        },
      });
    } catch (error) {
      console.error('Public business page lookup failed:', error);
      res.status(error.status || 500).json({ error: 'Unable to load this booking page.' });
    }
  });

app.get('/api/public/businesses/:slug/availability',
  publicReadLimit, async (req, res) => {
    try {
      const db = getFirestore();
      const business = await findPublicBusiness(db, req.params.slug);
      if (!business) return res.status(404).json({ error: 'Public booking page not found.' });
      if (!(await publicBusinessHasPaidAccess(business))) {
        return res.status(402).json({ error: 'This business is temporarily unable to accept online bookings.' });
      }
      const service = business.settings.services.find(
        (item) => item.id === req.query.serviceId && item.enabled,
      );
      if (!service) return res.status(404).json({ error: 'Service is not available.' });
      const date = req.query.date;
      if (typeof date !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(date)) {
        return res.status(400).json({ error: 'Choose a valid appointment date.' });
      }
      const dayStart = new Date(`${date}T00:00:00Z`);
      if (!Number.isFinite(dayStart.getTime()) ||
          dayStart.toISOString().slice(0, 10) !== date ||
          dayStart < new Date(Date.now() - 24 * 60 * 60 * 1000) ||
          dayStart > new Date(Date.now() + 90 * 24 * 60 * 60 * 1000)) {
        return res.status(400).json({ error: 'Choose a date within the next 90 days.' });
      }
      const candidates = getPublicAppointmentSlots(date, service, business.settings)
        .filter((slot) => slot.getTime() >= Date.now() + 15 * 60 * 1000 &&
          slot.getTime() <= Date.now() + 90 * 24 * 60 * 60 * 1000);
      const slotIds = new Set(candidates.flatMap((start) =>
        getAppointmentSlotIds(start, service.durationMinutes),
      ));
      const refs = [...slotIds].map((id) =>
        db.collection('businesses').doc(business.businessId)
          .collection('appointmentSlots').doc(id),
      );
      const occupied = new Set();
      for (let offset = 0; offset < refs.length; offset += 100) {
        const snapshots = await db.getAll(...refs.slice(offset, offset + 100));
        snapshots.forEach((snapshot) => {
          if (snapshot.exists) occupied.add(snapshot.id);
        });
      }
      const slots = candidates.filter((start) =>
        getAppointmentSlotIds(start, service.durationMinutes)
          .every((id) => !occupied.has(id)),
      );
      res.json({
        date,
        timeZone: business.settings.timeZone,
        slots: slots.map((slot) => ({
          startAt: slot.toISOString(),
          label: new Intl.DateTimeFormat('es-CO', {
            timeZone: business.settings.timeZone,
            hour: 'numeric',
            minute: '2-digit',
          }).format(slot),
        })),
      });
    } catch (error) {
      console.error('Public availability lookup failed:', error);
      res.status(error.status || 500).json({ error: 'Unable to load appointment availability.' });
    }
  });

app.post('/api/public/businesses/:slug/book',
  publicWriteLimit, async (req, res) => {
    const validationError = validatePublicBooking(req.body);
    if (validationError) return res.status(400).json({ error: validationError });
    try {
      const db = getFirestore();
      const business = await findPublicBusiness(db, req.params.slug);
      if (!business) return res.status(404).json({ error: 'Public booking page not found.' });
      if (!(await publicBusinessHasPaidAccess(business))) {
        return res.status(402).json({ error: 'This business is temporarily unable to accept online bookings.' });
      }
      const settings = business.settings;
      const service = settings.services.find(
        (item) => item.id === req.body.serviceId && item.enabled,
      );
      if (!service) return res.status(404).json({ error: 'Service is not available.' });
      const startAt = new Date(req.body.startAt);
      const endAt = new Date(startAt.getTime() + service.durationMinutes * 60 * 1000);
      const slotIds = getAppointmentSlotIds(startAt, service.durationMinutes);
      if (!slotIds || startAt.getTime() < Date.now() + 15 * 60 * 1000 ||
          startAt.getTime() > Date.now() + 90 * 24 * 60 * 60 * 1000 ||
          !isWithinBusinessHours(startAt, endAt, settings.timeZone, settings.weeklyHours)) {
        return res.status(400).json({ error: 'Choose an available appointment time.' });
      }

      const businessRef = db.collection('businesses').doc(business.businessId);
      const customerRef = businessRef.collection('customers').doc();
      const appointmentRef = businessRef.collection('appointments').doc();
      const slotRefs = slotIds.map((id) =>
        businessRef.collection('appointmentSlots').doc(id),
      );
      const customer = {
        name: req.body.name.trim(),
        phone: req.body.phone?.trim() || '',
        email: req.body.email?.trim().toLowerCase() || '',
        channels: [...req.body.channels],
        serviceMessagesConsent: true,
        marketingConsent: req.body.marketingConsent === true,
        aiConsent: req.body.aiConsent === true,
        consentSource: 'customer_form',
        consentVersion: '2026-11-v1',
        consentCapturedAt: FieldValue.serverTimestamp(),
        createdAt: FieldValue.serverTimestamp(),
        updatedAt: FieldValue.serverTimestamp(),
      };
      const booking = await db.runTransaction(async (transaction) => {
        const [liveBusiness, ...slots] = await Promise.all([
          transaction.get(businessRef),
          ...slotRefs.map((ref) => transaction.get(ref)),
        ]);
        const liveSettings = getCustomerEngagementSettings(liveBusiness.data() || {});
        const liveService = liveSettings.services.find(
          (item) => item.id === service.id && item.enabled,
        );
        if (!liveSettings.bookingEnabled || !liveSettings.publicBookingEnabled ||
            liveSettings.publicBookingSlug !== req.params.slug ||
            !liveService || liveService.durationMinutes !== service.durationMinutes ||
            !isWithinBusinessHours(
              startAt, endAt, liveSettings.timeZone, liveSettings.weeklyHours,
            )) {
          const error = new Error('Booking settings changed; reload available times.');
          error.status = 409;
          throw error;
        }
        if (slots.some((slot) => slot.exists)) {
          const error = new Error('That appointment time is no longer available.');
          error.status = 409;
          throw error;
        }
        const status = liveSettings.bookingMode === 'auto_confirm'
          ? 'confirmed'
          : 'pending_vendor';
        transaction.create(customerRef, customer);
        transaction.create(appointmentRef, {
          customerId: customerRef.id,
          customerName: customer.name,
          serviceId: liveService.id,
          serviceName: liveService.name,
          durationMinutes: liveService.durationMinutes,
          priceCop: liveService.priceCop ?? null,
          timeZone: liveSettings.timeZone,
          startAt,
          endAt,
          bookingMode: liveSettings.bookingMode,
          status,
          source: 'public_booking',
          createdAt: FieldValue.serverTimestamp(),
          updatedAt: FieldValue.serverTimestamp(),
        });
        for (const slotRef of slotRefs) {
          transaction.create(slotRef, { appointmentId: appointmentRef.id, startAt, endAt });
        }
        return {
          status,
          service: liveService,
          timeZone: liveSettings.timeZone,
          bookingMode: liveSettings.bookingMode,
        };
      });

      const appointment = {
        customerId: customerRef.id,
        serviceName: booking.service.name,
        status: booking.status,
        startAt,
        timeZone: booking.timeZone,
      };
      const confirmationStatus = await notifyAppointmentCustomer(
        db,
        business.businessId,
        appointment,
      );
      res.status(201).json({
        bookingId: appointmentRef.id,
        status: booking.status,
        confirmationMessageStatus: confirmationStatus,
      });
    } catch (error) {
      console.error('Public appointment could not be booked:', error);
      res.status(error.status || 500).json({
        error: error.status ? error.message : 'Unable to complete this booking.',
      });
    }
  });

app.get('/api/business/customers',
  requireFirebaseAuth, requireBusinessMember, allowRoles('owner', 'cashier'),
  requirePermission('charge'), requirePaidAccess,
  async (req, res) => {
    try {
      const snapshot = await getFirestore().collection('businesses').doc(req.businessId)
        .collection('customers').orderBy('updatedAt', 'desc').limit(200).get();
      res.json({
        customers: snapshot.docs.map((customer) => ({
          id: customer.id,
          ...customer.data(),
        })),
      });
    } catch (error) {
      console.error('Customer list could not be loaded:', error);
      res.status(error.status || 500).json({ error: 'Unable to load customer contacts.' });
    }
  });

app.post('/api/business/customers',
  requireFirebaseAuth, requireBusinessMember, allowRoles('owner', 'cashier'),
  requirePermission('charge'), requirePaidAccess,
  async (req, res) => {
    const validationError = validateCustomerContact(req.body);
    if (validationError) return res.status(400).json({ error: validationError });
    if (!['customer_form', 'in_person'].includes(req.body.consentSource)) {
      return res.status(400).json({
        error: 'Record whether the customer opted in through a customer form or in person.',
      });
    }

    try {
      const ref = getFirestore().collection('businesses').doc(req.businessId)
        .collection('customers').doc();
      const customer = {
        name: req.body.name.trim(),
        phone: req.body.phone?.trim() || '',
        email: req.body.email?.trim().toLowerCase() || '',
        channels: [...req.body.channels],
        serviceMessagesConsent: true,
        marketingConsent: req.body.marketingConsent,
        aiConsent: req.body.aiConsent === true,
        consentSource: req.body.consentSource,
        consentVersion: '2026-11-v1',
        consentCapturedAt: FieldValue.serverTimestamp(),
        createdAt: FieldValue.serverTimestamp(),
        updatedAt: FieldValue.serverTimestamp(),
      };
      await ref.create(customer);
      res.status(201).json({
        customer: {
          id: ref.id,
          ...customer,
          consentCapturedAt: new Date().toISOString(),
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
        },
      });
    } catch (error) {
      console.error('Customer contact could not be saved:', error);
      res.status(error.status || 500).json({ error: 'Unable to save customer contact.' });
    }
  });

app.patch('/api/business/customers/:customerId/consent',
  requireFirebaseAuth, requireBusinessMember, allowRoles('owner', 'cashier'),
  requirePermission('charge'), requirePaidAccess,
  async (req, res) => {
    const revokeChannels = req.body.revokeChannels;
    const revokeServiceMessages = req.body.revokeServiceMessages === true;
    const revokeMarketing = req.body.revokeMarketing === true;
    const revokeAi = req.body.revokeAi === true;
    if (!Array.isArray(revokeChannels) ||
        revokeChannels.some((channel) => !['whatsapp', 'email', 'sms'].includes(channel)) ||
        (!revokeChannels.length && !revokeServiceMessages && !revokeMarketing && !revokeAi)) {
      return res.status(400).json({ error: 'Choose at least one consent permission to revoke.' });
    }

    try {
      const ref = getFirestore().collection('businesses').doc(req.businessId)
        .collection('customers').doc(req.params.customerId);
      const snapshot = await ref.get();
      if (!snapshot.exists) {
        return res.status(404).json({ error: 'Customer contact not found.' });
      }
      const customer = snapshot.data();
      const revokedAt = FieldValue.serverTimestamp();
      const channels = (customer.channels || []).filter(
        (channel) => !revokeChannels.includes(channel),
      );
      await ref.update({
        channels,
        ...(revokeServiceMessages ? {
          serviceMessagesConsent: false,
          serviceMessagesRevokedAt: revokedAt,
        } : {}),
        ...(revokeMarketing ? {
          marketingConsent: false,
          marketingRevokedAt: revokedAt,
        } : {}),
        ...(revokeAi ? {
          aiConsent: false,
          aiRevokedAt: revokedAt,
        } : {}),
        updatedAt: FieldValue.serverTimestamp(),
      });
      res.json({
        id: snapshot.id,
        channels,
        serviceMessagesConsent: revokeServiceMessages
          ? false
          : customer.serviceMessagesConsent === true,
        marketingConsent: revokeMarketing
          ? false
          : customer.marketingConsent === true,
        aiConsent: revokeAi ? false : customer.aiConsent === true,
      });
    } catch (error) {
      console.error('Customer messaging consent could not be updated:', error);
      res.status(error.status || 500).json({ error: 'Unable to update customer consent.' });
    }
  });

app.get('/api/business/appointments',
  requireFirebaseAuth, requireBusinessMember, allowRoles('owner', 'cashier'),
  requirePermission('charge'), requirePaidAccess, async (req, res) => {
    try {
      const snapshot = await getFirestore().collection('businesses').doc(req.businessId)
        .collection('appointments').orderBy('startAt', 'asc').limit(200).get();
      res.json({
        appointments: snapshot.docs.map((appointment) => {
          const data = appointment.data();
          return {
            id: appointment.id,
            ...data,
            startAt: data.startAt?.toDate?.().toISOString() || '',
            endAt: data.endAt?.toDate?.().toISOString() || '',
          };
        }),
      });
    } catch (error) {
      console.error('Appointment list could not be loaded:', error);
      res.status(error.status || 500).json({ error: 'Unable to load appointments.' });
    }
  });

app.post('/api/business/appointments',
  requireFirebaseAuth, requireBusinessMember, allowRoles('owner', 'cashier'),
  requirePermission('charge'), requirePaidAccess, async (req, res) => {
    const customerId = typeof req.body.customerId === 'string'
      ? req.body.customerId.trim()
      : '';
    const serviceId = typeof req.body.serviceId === 'string'
      ? req.body.serviceId.trim()
      : '';
    const startAt = typeof req.body.startAt === 'string'
      ? new Date(req.body.startAt)
      : null;
    if (!customerId || !serviceId || !startAt || !Number.isFinite(startAt.getTime())) {
      return res.status(400).json({
        error: 'Choose a saved customer, bookable service, and valid appointment time.',
      });
    }
    if (startAt.getTime() < Date.now() + 5 * 60 * 1000 ||
        startAt.getTime() > Date.now() + 90 * 24 * 60 * 60 * 1000) {
      return res.status(400).json({ error: 'Choose an appointment within the next 90 days.' });
    }

    try {
      const db = getFirestore();
      const businessRef = db.collection('businesses').doc(req.businessId);
      const customerRef = businessRef.collection('customers').doc(customerId);
      const settings = getCustomerEngagementSettings(req.business);
      if (!settings.bookingEnabled) {
        return res.status(409).json({ error: 'Customer booking is disabled for this business.' });
      }
      const service = settings.services.find(
        (candidate) => candidate.id === serviceId && candidate.enabled,
      );
      if (!service) {
        return res.status(404).json({ error: 'This bookable service is not available.' });
      }
      const endAt = new Date(startAt.getTime() + service.durationMinutes * 60 * 1000);
      const slotIds = getAppointmentSlotIds(startAt, service.durationMinutes);
      if (!slotIds || !isWithinBusinessHours(
        startAt,
        endAt,
        settings.timeZone,
        settings.weeklyHours,
      )) {
        return res.status(400).json({
          error: 'Choose an available 15-minute slot fully within business hours.',
        });
      }

      const appointmentRef = businessRef.collection('appointments').doc();
      const slotRefs = slotIds.map((slotId) =>
        businessRef.collection('appointmentSlots').doc(slotId),
      );
      const booking = await db.runTransaction(async (transaction) => {
        const [businessSnapshot, customerSnapshot, ...slotSnapshots] = await Promise.all([
          transaction.get(businessRef),
          transaction.get(customerRef),
          ...slotRefs.map((slotRef) => transaction.get(slotRef)),
        ]);
        if (!customerSnapshot.exists) {
          const error = new Error('Customer contact not found.');
          error.status = 404;
          throw error;
        }
        const liveSettings = getCustomerEngagementSettings(businessSnapshot.data() || {});
        const liveService = liveSettings.services.find(
          (candidate) => candidate.id === serviceId && candidate.enabled,
        );
        if (!liveSettings.bookingEnabled || !liveService ||
            liveService.durationMinutes !== service.durationMinutes ||
            !isWithinBusinessHours(
              startAt,
              endAt,
              liveSettings.timeZone,
              liveSettings.weeklyHours,
            )) {
          const error = new Error('Business booking settings changed; reload and choose a new time.');
          error.status = 409;
          throw error;
        }
        if (slotSnapshots.some((slot) => slot.exists)) {
          const error = new Error('That appointment time is no longer available.');
          error.status = 409;
          throw error;
        }

        const status = liveSettings.bookingMode === 'auto_confirm'
          ? 'confirmed'
          : 'pending_vendor';
        transaction.create(appointmentRef, {
          customerId,
          customerName: customerSnapshot.data().name,
          serviceId: service.id,
          serviceName: liveService.name,
          durationMinutes: liveService.durationMinutes,
          priceCop: liveService.priceCop ?? null,
          timeZone: liveSettings.timeZone,
          startAt,
          endAt,
          bookingMode: liveSettings.bookingMode,
          status,
          createdBy: req.authUser.uid,
          createdAt: FieldValue.serverTimestamp(),
          updatedAt: FieldValue.serverTimestamp(),
        });
        for (const slotRef of slotRefs) {
          transaction.create(slotRef, {
            appointmentId: appointmentRef.id,
            startAt,
            endAt,
          });
        }
        return {
          status,
          service: liveService,
          timeZone: liveSettings.timeZone,
          bookingMode: liveSettings.bookingMode,
        };
      });
      const notificationStatus = await notifyAppointmentCustomer(db, req.businessId, {
        customerId,
        serviceName: booking.service.name,
        status: booking.status,
        startAt,
        timeZone: booking.timeZone,
      });
      res.status(201).json({
        id: appointmentRef.id,
        customerId,
        serviceId: booking.service.id,
        serviceName: booking.service.name,
        startAt: startAt.toISOString(),
        endAt: endAt.toISOString(),
        status: booking.status,
        bookingMode: booking.bookingMode,
        notificationStatus,
      });
    } catch (error) {
      console.error('Appointment could not be booked:', error);
      res.status(error.status || 500).json({
        error: error.status ? error.message : 'Unable to book this appointment.',
      });
    }
  });

app.patch('/api/business/appointments/:appointmentId/status',
  requireFirebaseAuth, requireBusinessMember, allowRoles('owner', 'cashier'),
  requirePermission('charge'), requirePaidAccess, async (req, res) => {
    const nextStatus = req.body.status;
    if (!['confirmed', 'declined', 'cancelled'].includes(nextStatus)) {
      return res.status(400).json({ error: 'Choose a valid appointment status.' });
    }

    try {
      const db = getFirestore();
      const businessRef = db.collection('businesses').doc(req.businessId);
      const appointmentRef = businessRef.collection('appointments')
        .doc(req.params.appointmentId);
      const snapshot = await appointmentRef.get();
      if (!snapshot.exists) {
        return res.status(404).json({ error: 'Appointment not found.' });
      }
      const appointment = snapshot.data();
      if (appointment.status === nextStatus) {
        return res.json({ id: snapshot.id, status: nextStatus });
      }
      if (appointment.status === 'cancelled' || appointment.status === 'declined' ||
          (appointment.status === 'confirmed' && nextStatus === 'declined')) {
        return res.status(409).json({ error: 'This appointment can no longer be changed.' });
      }

      const slotIds = getAppointmentSlotIds(
        appointment.startAt.toDate(),
        appointment.durationMinutes,
      );
      const slotRefs = slotIds.map((slotId) =>
        businessRef.collection('appointmentSlots').doc(slotId),
      );
      await db.runTransaction(async (transaction) => {
        const current = await transaction.get(appointmentRef);
        if (!current.exists || current.data().status !== appointment.status) {
          const error = new Error('Appointment status changed; reload before trying again.');
          error.status = 409;
          throw error;
        }
        const slots = await Promise.all(slotRefs.map((slotRef) => transaction.get(slotRef)));
        transaction.update(appointmentRef, {
          status: nextStatus,
          updatedAt: FieldValue.serverTimestamp(),
          ...(nextStatus === 'confirmed' ? {
            confirmedBy: req.authUser.uid,
            confirmedAt: FieldValue.serverTimestamp(),
          } : {}),
          ...(['declined', 'cancelled'].includes(nextStatus) ? {
            closedBy: req.authUser.uid,
            closedAt: FieldValue.serverTimestamp(),
          } : {}),
        });
        slots.forEach((slot, index) => {
          if (slot.exists && slot.data().appointmentId === appointmentRef.id) {
            transaction.delete(slotRefs[index]);
          }
        });
      });
      const notificationStatus = await notifyAppointmentCustomer(db, req.businessId, {
        ...appointment,
        status: nextStatus,
      });
      res.json({
        id: appointmentRef.id,
        status: nextStatus,
        notificationStatus,
      });
    } catch (error) {
      console.error('Appointment status could not be updated:', error);
      res.status(error.status || 500).json({
        error: error.status ? error.message : 'Unable to update appointment.',
      });
    }
  });

app.get('/api/business/conversations',
  requireFirebaseAuth, requireBusinessMember, allowRoles('owner', 'cashier'),
  requirePermission('charge'), requirePaidAccess, async (req, res) => {
    try {
      const snapshot = await getFirestore().collection('businesses').doc(req.businessId)
        .collection('conversations').orderBy('updatedAt', 'desc').limit(100).get();
      res.json({
        conversations: snapshot.docs.map((doc) => ({
          id: doc.id,
          customerId: doc.data().customerId,
          customerName: doc.data().customerName,
          channel: doc.data().channel,
          status: doc.data().status,
          unreadCount: doc.data().unreadCount || 0,
          lastMessage: doc.data().lastMessage || '',
          lastMessageAt: doc.data().lastMessageAt?.toDate?.().toISOString() || '',
        })),
      });
    } catch (error) {
      console.error('Conversation inbox could not be loaded:', error);
      res.status(error.status || 500).json({ error: 'Unable to load the message inbox.' });
    }
  });

app.get('/api/business/conversations/:conversationId/messages',
  requireFirebaseAuth, requireBusinessMember, allowRoles('owner', 'cashier'),
  requirePermission('charge'), requirePaidAccess, async (req, res) => {
    try {
      const conversationRef = getFirestore().collection('businesses')
        .doc(req.businessId).collection('conversations').doc(req.params.conversationId);
      const [conversation, messages] = await Promise.all([
        conversationRef.get(),
        conversationRef.collection('messages').orderBy('createdAt', 'asc').limit(200).get(),
      ]);
      if (!conversation.exists) return res.status(404).json({ error: 'Conversation not found.' });
      await conversationRef.update({ unreadCount: 0 });
      res.json({
        conversation: {
          id: conversation.id,
          customerId: conversation.data().customerId,
          customerName: conversation.data().customerName,
          channel: conversation.data().channel,
        },
        messages: messages.docs.map((doc) => ({
          id: doc.id,
          direction: doc.data().direction,
          text: doc.data().text,
          status: doc.data().status,
          createdAt: doc.data().createdAt?.toDate?.().toISOString() || '',
        })),
      });
    } catch (error) {
      console.error('Conversation messages could not be loaded:', error);
      res.status(error.status || 500).json({ error: 'Unable to load this conversation.' });
    }
  });

app.post('/api/business/conversations',
  requireFirebaseAuth, requireBusinessMember, allowRoles('owner', 'cashier'),
  requirePermission('charge'), requirePaidAccess, async (req, res) => {
    const customerId = typeof req.body.customerId === 'string'
      ? req.body.customerId.trim()
      : '';
    const channel = req.body.channel;
    const validationError = validateMessage(req.body.text);
    if (!customerId || !['whatsapp', 'sms', 'email'].includes(channel)) {
      return res.status(400).json({ error: 'Choose a saved customer and message channel.' });
    }
    if (validationError) return res.status(400).json({ error: validationError });
    try {
      const db = getFirestore();
      const customerRef = db.collection('businesses').doc(req.businessId)
        .collection('customers').doc(customerId);
      const customerSnapshot = await customerRef.get();
      if (!customerSnapshot.exists) return res.status(404).json({ error: 'Customer not found.' });
      const delivery = await sendBusinessMessage({
        db,
        businessId: req.businessId,
        customerId,
        customer: customerSnapshot.data(),
        channel,
        text: req.body.text,
        senderUid: req.authUser.uid,
      });
      res.status(201).json(delivery);
    } catch (error) {
      console.error('Business message could not be sent:', error.message);
      res.status(error.status || 502).json({
        error: error.status ? error.message : 'Message delivery failed; review its status in the inbox.',
      });
    }
  });

app.post('/api/business/conversations/:conversationId/ai-draft',
  requireFirebaseAuth, requireBusinessMember, allowRoles('owner', 'cashier'),
  requirePermission('charge'), requirePaidAccess, async (req, res) => {
    if (process.env.PRIVATE_AI_ENABLED !== 'true' ||
        !process.env.PRIVATE_AI_URL || !process.env.PRIVATE_AI_API_KEY) {
      return res.status(503).json({ error: 'The private AI assistant is not configured.' });
    }
    try {
      const endpoint = new URL(process.env.PRIVATE_AI_URL);
      if (endpoint.protocol !== 'https:' || endpoint.username || endpoint.password) {
        return res.status(503).json({ error: 'The private AI endpoint must be a secure HTTPS URL.' });
      }
      const db = getFirestore();
      const businessRef = db.collection('businesses').doc(req.businessId);
      const conversationRef = businessRef.collection('conversations')
        .doc(req.params.conversationId);
      const [businessSnapshot, conversationSnapshot, messagesSnapshot] = await Promise.all([
        businessRef.get(),
        conversationRef.get(),
        conversationRef.collection('messages').orderBy('createdAt', 'desc').limit(20).get(),
      ]);
      if (!conversationSnapshot.exists) return res.status(404).json({ error: 'Conversation not found.' });
      const conversation = conversationSnapshot.data();
      if (getCustomerEngagementSettings(businessSnapshot.data() || {}).aiEnabled !== true) {
        return res.status(403).json({ error: 'The business owner has not enabled private AI drafts.' });
      }
      const customerSnapshot = await businessRef.collection('customers')
        .doc(conversation.customerId).get();
      if (!customerSnapshot.exists ||
          customerSnapshot.data().serviceMessagesConsent !== true ||
          !(customerSnapshot.data().channels || []).includes(conversation.channel) ||
          customerSnapshot.data().aiConsent !== true) {
        return res.status(403).json({ error: 'Customer messaging consent is not active.' });
      }
      const recentMessages = messagesSnapshot.docs
        .reverse()
        .filter((doc) => ['inbound', 'outbound'].includes(doc.data().direction))
        .map((doc) => ({
          direction: doc.data().direction,
          text: doc.data().text,
        }));
      if (!recentMessages.some((message) => message.direction === 'inbound')) {
        return res.status(409).json({ error: 'Wait for a customer message before preparing a reply.' });
      }
      const response = await fetch(endpoint, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${process.env.PRIVATE_AI_API_KEY}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          task: 'draft_customer_reply',
          businessName: businessSnapshot.data().name || '',
          channel: conversation.channel,
          messages: recentMessages,
          instructions: 'Return JSON with one short reply string. Do not send messages or perform actions.',
        }),
        signal: AbortSignal.timeout(15000),
      });
      if (!response.ok) throw new Error(`Private AI returned HTTP ${response.status}.`);
      const result = await response.json();
      const draft = typeof result.reply === 'string' ? result.reply.trim() : '';
      if (validateMessage(draft)) {
        throw new Error('Private AI returned an invalid draft.');
      }
      const draftRef = conversationRef.collection('messages').doc();
      await draftRef.create({
        channel: conversation.channel,
        direction: 'draft',
        text: draft,
        status: 'needs_review',
        createdBy: req.authUser.uid,
        createdAt: FieldValue.serverTimestamp(),
      });
      res.json({ draftId: draftRef.id, text: draft, status: 'needs_review' });
    } catch (error) {
      console.error('Private AI draft failed:', error);
      res.status(error.status || 502).json({ error: 'Unable to create a private AI draft.' });
    }
  });

app.put('/api/business/profile', requireFirebaseAuth, requireBusinessMember,
  allowRoles('owner'), async (req, res) => {
    const name = typeof req.body.name === 'string'
      ? req.body.name.trim()
      : '';
    if (name.length < 2 || name.length > 100) {
      return res.status(400).json({
        error: 'Business name must be between 2 and 100 characters.',
      });
    }

    try {
      await getFirestore().collection('businesses').doc(req.businessId).set({
        name,
        updatedAt: FieldValue.serverTimestamp(),
      }, { merge: true });
      res.json({ name });
    } catch (error) {
      console.error('Business profile update failed:', error);
      res.status(error.status || 500).json({
        error: 'Unable to save the business name.',
      });
    }
  });

app.put('/api/business/profile/settings', requireFirebaseAuth, requireBusinessMember,
  allowRoles('owner'), async (req, res) => {
  const { name, businessType, operatingModel, locationCount } = req.body;
    const businessTypes = [
      'retail',
      'pharmacy',
      'restaurant',
      'supplier',
      'contractor',
      'chain',
      'other',
    ];
    const operatingModels = [
      'independent',
      'supplier_to_chain',
      'chain_store',
      'inventory_partner',
      'contractor',
    ];
    const businessName = typeof name === 'string' ? name.trim() : '';
    if (businessName.length < 2 ||
        businessName.length > 100 ||
        !businessTypes.includes(businessType) ||
        !operatingModels.includes(operatingModel) ||
        !Number.isInteger(locationCount) ||
        locationCount < 1 ||
        locationCount > 10000) {
      return res.status(400).json({
        error: 'Choose a supported business type, operating model, and location count.',
      });
    }

    try {
      const businessProfile = { businessType, operatingModel, locationCount };
      await getFirestore().collection('businesses').doc(req.businessId).set({
        name: businessName,
        businessProfile,
        updatedAt: FieldValue.serverTimestamp(),
      }, { merge: true });
      res.json({ name: businessName, businessProfile });
    } catch (error) {
      console.error('Business operating profile update failed:', error);
      res.status(error.status || 500).json({
        error: 'Unable to save the business operating profile.',
      });
    }
  });

app.put('/api/business/payment-method', requireFirebaseAuth, requireBusinessMember,
  allowRoles('owner'), requirePaidAccess, async (req, res) => {
    const { method } = req.body;
    const allowedMethods = ['bank_transfer', 'mercado_pago', 'stripe', 'wompi'];
    if (!allowedMethods.includes(method)) {
      return res.status(400).json({ error: 'Choose a supported payment method.' });
    }

    const providers = req.business.providers || {};
    let wompiConfigured = false;
    let wompiEnvironment = null;
    if (method === 'wompi') {
      try {
        const wompi = await getFirestore().collection('businesses').doc(req.businessId)
          .collection('privateIntegrations').doc('wompi').get();
        wompiConfigured = wompi.exists;
        wompiEnvironment = wompi.data()?.environment || null;
      } catch (error) {
        console.error('Wompi payment method status check failed:', error);
        return res.status(error.status || 500).json({
          error: 'Unable to verify the Wompi connection.',
        });
      }
    }
    const configured = {
      bank_transfer: Boolean(providers.bankTransfer?.alias),
      mercado_pago: providers.mercadoPago?.status === 'connected' &&
        Boolean(providers.mercadoPago?.accessTokenEncrypted),
      stripe: Boolean(providers.stripe?.accountId) &&
        providers.stripe?.status === 'active',
      wompi: wompiConfigured && wompiEnvironment === 'production',
    };
    if (!configured[method]) {
      return res.status(409).json({
        error: 'Connect and verify this payment method before making it the default.',
      });
    }

    try {
      await getFirestore().collection('businesses').doc(req.businessId).set({
        defaultPaymentMethod: method,
        updatedAt: FieldValue.serverTimestamp(),
      }, { merge: true });
      res.json({ defaultPaymentMethod: method });
    } catch (error) {
      console.error('Default payment method update failed:', error);
      res.status(error.status || 500).json({ error: 'Unable to save the default payment method.' });
    }
  });

app.get('/api/business/members', requireFirebaseAuth, requireBusinessMember,
  allowRoles('owner'), requirePaidAccess, async (req, res) => {
    try {
      const members = await getFirestore().collection('businesses').doc(req.businessId)
        .collection('members').get();
      res.json({
        members: members.docs.map((member) => {
          const data = member.data();
          return {
            uid: member.id,
            email: data.email || '',
            role: data.role,
            active: data.active === true,
            permissions: data.permissions || {},
          };
        }),
      });
    } catch (error) {
      res.status(500).json({ error: 'Unable to load business members.' });
    }
  });

app.post('/api/business/invitations', requireFirebaseAuth, requireBusinessMember,
  allowRoles('owner'), requirePaidAccess, async (req, res) => {
    if (req.authUser.email_verified !== true) {
      return res.status(403).json({
        error: 'Verify the owner email before inviting company users.',
      });
    }
    const email = typeof req.body.email === 'string'
      ? req.body.email.trim().toLowerCase()
      : '';
    const role = req.body.role;
    const permissions = req.body.permissions;
    const permittedRoles = ['cashier', 'inventory'];
    const permissionNames = ['charge', 'viewInventory', 'manageInventory', 'viewReports'];
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email) ||
        email === req.authUser.email?.toLowerCase() ||
        !permittedRoles.includes(role) ||
        !permissions ||
        typeof permissions !== 'object' ||
        Array.isArray(permissions) ||
        Object.keys(permissions).some((key) => !permissionNames.includes(key)) ||
        Object.values(permissions).some((value) => typeof value !== 'boolean')) {
      return res.status(400).json({
        error: 'Enter a different employee email, valid role, and explicit permissions.',
      });
    }

    try {
      const token = crypto.randomBytes(32).toString('base64url');
      const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
      await getFirestore().collection('businessInvitations').doc(tokenHash).create({
        businessId: req.businessId,
        email,
        role,
        permissions: Object.fromEntries(
          permissionNames.map((name) => [name, permissions[name] === true]),
        ),
        status: 'pending',
        createdBy: req.authUser.uid,
        createdAt: FieldValue.serverTimestamp(),
        expiresAt: Date.now() + 7 * 24 * 60 * 60 * 1000,
      });
      res.status(201).json({
        invitationCode: token,
        email,
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
      });
    } catch (error) {
      console.error('Creating business invitation failed:', error);
      res.status(error.status || 500).json({
        error: 'Unable to create the company invitation.',
      });
    }
  });

app.post('/api/business/invitations/accept', requireFirebaseAuth, async (req, res) => {
  const invitationCode = typeof req.body.invitationCode === 'string'
    ? req.body.invitationCode.trim()
    : '';
  if (!/^[A-Za-z0-9_-]{40,50}$/.test(invitationCode)) {
    return res.status(400).json({ error: 'Enter a valid invitation code.' });
  }
  if (req.authUser.email_verified !== true || !req.authUser.email) {
    return res.status(403).json({
      error: 'Verify your work email before accepting a company invitation.',
    });
  }

  const tokenHash = crypto.createHash('sha256').update(invitationCode).digest('hex');
  const db = getFirestore();
  const invitationRef = db.collection('businessInvitations').doc(tokenHash);
  let acceptedBusinessId;
  try {
    const paidAccessEnforced = await isPaidAccessEnforced();
    await db.runTransaction(async (transaction) => {
      const invitationSnapshot = await transaction.get(invitationRef);
      if (!invitationSnapshot.exists) {
        const error = new Error('This invitation is invalid or has expired.');
        error.status = 404;
        throw error;
      }
      const invitation = invitationSnapshot.data();
      if (invitation.email !== req.authUser.email.toLowerCase()) {
        const error = new Error('Sign in with the work email this invitation was sent to.');
        error.status = 403;
        throw error;
      }
      acceptedBusinessId = invitation.businessId;
      if (invitation.status === 'accepted' &&
          invitation.acceptedBy === req.authUser.uid) {
        return;
      }
      if (invitation.status !== 'pending' || invitation.expiresAt < Date.now()) {
        const error = new Error('This invitation is invalid or has expired.');
        error.status = 410;
        throw error;
      }

      const targetBusinessRef = db.collection('businesses').doc(acceptedBusinessId);
      const targetMemberRef = targetBusinessRef.collection('members').doc(req.authUser.uid);
      const [targetBusiness, targetMember] = await Promise.all([
        transaction.get(targetBusinessRef),
        transaction.get(targetMemberRef),
      ]);
      if (!targetBusiness.exists) {
        const error = new Error('The inviting company is no longer available.');
        error.status = 404;
        throw error;
      }
      if (paidAccessEnforced &&
          !hasActivePosSubscription(targetBusiness.data().subscription)) {
        const error = new Error('An active POS subscription is required to join this business.');
        error.status = 402;
        throw error;
      }
      if (targetMember.exists && targetMember.data().active === true) {
        transaction.update(invitationRef, {
          status: 'accepted',
          acceptedBy: req.authUser.uid,
          acceptedAt: FieldValue.serverTimestamp(),
        });
        return;
      }

      const currentBusinessId = req.authUser.businessId || req.authUser.uid;
      if (currentBusinessId !== req.authUser.uid) {
        const error = new Error('This account is already connected to another company.');
        error.status = 409;
        throw error;
      }
      const currentBusinessRef = db.collection('businesses').doc(req.authUser.uid);
      const currentMemberRef = currentBusinessRef.collection('members').doc(req.authUser.uid);
      const ownTransactions = currentBusinessRef.collection('transactions').limit(1);
      const ownWompiRef = currentBusinessRef.collection('privateIntegrations').doc('wompi');
      const ownNequiRef = currentBusinessRef.collection('privateIntegrations').doc('nequi');
      const [
        currentBusiness,
        currentMember,
        transactions,
        wompi,
        nequi,
      ] = await Promise.all([
        transaction.get(currentBusinessRef),
        transaction.get(currentMemberRef),
        transaction.get(ownTransactions),
        transaction.get(ownWompiRef),
        transaction.get(ownNequiRef),
      ]);
      if (!currentBusiness.exists || !currentMember.exists ||
          currentBusiness.data().ownerUid !== req.authUser.uid ||
          currentMember.data().role !== 'owner' ||
          currentMember.data().active !== true ||
          transactions.size > 0 ||
          ['active', 'trialing'].includes(currentBusiness.data().subscription?.status) ||
          currentBusiness.data().providers?.stripe?.accountId ||
          currentBusiness.data().providers?.mercadoPago?.userId ||
          currentBusiness.data().providers?.bankTransfer?.alias ||
          currentBusiness.data().providers?.bankTransfer?.qrImageBase64 ||
          wompi.exists ||
          nequi.exists) {
        const error = new Error(
          'This account already has a company, payment setup, subscription, or sales. ' +
          'Use a separate verified work account to join another company.',
        );
        error.status = 409;
        throw error;
      }
      const memberPermissions = invitation.permissions || {};
      transaction.set(targetMemberRef, {
        uid: req.authUser.uid,
        email: req.authUser.email.toLowerCase(),
        role: invitation.role,
        active: true,
        permissions: memberPermissions,
        invitedBy: invitation.createdBy,
        joinedAt: FieldValue.serverTimestamp(),
      });
      transaction.update(currentBusinessRef, {
        ownerUid: null,
        migratedTo: acceptedBusinessId,
        updatedAt: FieldValue.serverTimestamp(),
      });
      transaction.update(currentMemberRef, {
        active: false,
        migratedTo: acceptedBusinessId,
        revokedAt: FieldValue.serverTimestamp(),
      });
      transaction.update(invitationRef, {
        status: 'accepted',
        acceptedBy: req.authUser.uid,
        acceptedAt: FieldValue.serverTimestamp(),
      });
    });

    const user = await getAuth(firebaseApp).getUser(req.authUser.uid);
    await getAuth(firebaseApp).setCustomUserClaims(user.uid, {
      ...(user.customClaims || {}),
      businessId: acceptedBusinessId,
    });
    res.json({ businessId: acceptedBusinessId, accepted: true });
  } catch (error) {
    if (error.status) {
      return res.status(error.status).json({ error: error.message });
    }
    console.error('Accepting business invitation failed:', error);
    res.status(500).json({ error: 'Unable to accept the company invitation.' });
  }
});

app.post('/api/business/members', requireFirebaseAuth, requireBusinessMember,
  allowRoles('owner'), requirePaidAccess, async (req, res) => {
    if (req.authUser.email_verified !== true) {
      return res.status(403).json({
        error: 'Verify the owner email before managing company users.',
      });
    }
    const email = typeof req.body.email === 'string' ? req.body.email.trim().toLowerCase() : '';
    const role = req.body.role;
    const permissions = req.body.permissions;
    const permittedRoles = ['cashier', 'inventory'];
    const permissionNames = ['charge', 'viewInventory', 'manageInventory', 'viewReports'];
    if (!email.includes('@') || !permittedRoles.includes(role) ||
        !permissions || typeof permissions !== 'object' ||
        Object.keys(permissions).some((key) => !permissionNames.includes(key)) ||
        Object.values(permissions).some((value) => typeof value !== 'boolean')) {
      return res.status(400).json({ error: 'Enter an email, valid employee role and explicit permissions.' });
    }

    try {
      const user = await getAuth(firebaseApp).getUserByEmail(email);
      if (!user.emailVerified) {
        return res.status(409).json({
          error: 'The employee must verify their email address before being added.',
        });
      }
      if (user.uid === req.authUser.uid) {
        return res.status(400).json({ error: 'The business owner cannot change their own role.' });
      }
      if (user.customClaims?.businessId && user.customClaims.businessId !== req.businessId) {
        return res.status(409).json({ error: 'This employee already belongs to another business.' });
      }
      if (user.uid !== req.businessId) {
        const ownedBusiness = await getFirestore().collection('businesses').doc(user.uid).get();
        if (ownedBusiness.exists && ownedBusiness.data().ownerUid === user.uid) {
          return res.status(409).json({ error: 'A business owner cannot be added as an employee to another business.' });
        }
      }
      const ref = getFirestore().collection('businesses').doc(req.businessId)
        .collection('members').doc(user.uid);
      await ref.set({
        uid: user.uid,
        email,
        role,
        active: true,
        permissions: Object.fromEntries(permissionNames.map((name) => [name, permissions[name] === true])),
        updatedAt: FieldValue.serverTimestamp(),
      }, { merge: true });
      await getAuth(firebaseApp).setCustomUserClaims(user.uid, {
        ...(user.customClaims || {}),
        businessId: req.businessId,
      });
      res.status(201).json({ uid: user.uid, email, role, active: true });
    } catch (error) {
      if (error.code === 'auth/user-not-found') {
        return res.status(404).json({ error: 'The employee must create a sign-in account before being added.' });
      }
      console.error('Adding business member failed:', error);
      res.status(500).json({ error: 'Unable to add this employee.' });
    }
  });

app.delete('/api/business/members/:uid', requireFirebaseAuth, requireBusinessMember,
  allowRoles('owner'), async (req, res) => {
    if (req.params.uid === req.authUser.uid) {
      return res.status(400).json({ error: 'The business owner cannot remove their own access.' });
    }
    try {
      const member = getFirestore().collection('businesses').doc(req.businessId)
        .collection('members').doc(req.params.uid);
      await member.update({
        active: false,
        revokedAt: FieldValue.serverTimestamp(),
      });
      const user = await getAuth(firebaseApp).getUser(req.params.uid);
      const claims = { ...(user.customClaims || {}) };
      if (claims.businessId === req.businessId) {
        delete claims.businessId;
        await getAuth(firebaseApp).setCustomUserClaims(req.params.uid, claims);
      }
      res.json({ revoked: true });
    } catch (error) {
      console.error('Revoking business member failed:', error);
      res.status(500).json({ error: 'Unable to revoke this employee.' });
    }
  });

app.get('/api/business/transactions', requireFirebaseAuth, requireBusinessMember,
  requirePaidAccess, requirePermission('viewReports'), async (req, res) => {
  try {
    const snapshot = await getFirestore().collection('businesses').doc(req.businessId)
      .collection('transactions').orderBy('createdAt', 'desc').limit(250).get();
    res.json({
      transactions: snapshot.docs.map((doc) => {
        const data = doc.data();
        return {
          id: doc.id,
          ...data,
          date: data.createdAt?.toDate?.().toISOString() || '',
        };
      }),
    });
  } catch (error) {
    console.error('Transaction history lookup failed:', error);
    res.status(500).json({ error: 'Unable to load transaction history.' });
  }
});

app.post('/api/business/transactions/cash', requireFirebaseAuth, requireBusinessMember,
  allowRoles('owner', 'cashier'), requirePermission('charge'), requirePaidAccess, async (req, res) => {
    try {
      const { service, vehicle, amount, currency = 'COP' } = req.body;
      if (typeof service !== 'string' || !service.trim() ||
          typeof amount !== 'number' || !Number.isSafeInteger(amount) || amount <= 0 ||
          currency !== 'COP') {
        return res.status(400).json({ error: 'A service and positive whole-COP amount are required.' });
      }

      const ref = getFirestore().collection('businesses').doc(req.businessId)
        .collection('transactions').doc();
      await ref.create({
        service: service.trim(),
        vehicle: typeof vehicle === 'string' ? vehicle.trim() : '',
        amount,
        currency,
        method: 'Efectivo',
        provider: 'cash',
        status: 'paid',
        confirmedBy: req.authUser.uid,
        createdAt: FieldValue.serverTimestamp(),
        confirmedAt: FieldValue.serverTimestamp(),
      });
      res.status(201).json({ id: ref.id, status: 'paid' });
    } catch (error) {
      console.error('Cash transaction recording failed:', error);
      res.status(500).json({ error: 'Unable to record this cash transaction.' });
    }
  });

app.get('/api/business/providers', requireFirebaseAuth, requireBusinessMember,
  requirePaidAccess, async (req, res) => {
  const providers = req.business.providers || {};
  let stripeStatus = providers.stripe?.status || 'not_connected';
  if (stripe && providers.stripe?.accountId) {
    try {
      const account = await stripe.accounts.retrieve(providers.stripe.accountId);
      stripeStatus = account.details_submitted && account.charges_enabled && account.payouts_enabled
        ? 'active'
        : 'onboarding';
      await getFirestore().collection('businesses').doc(req.businessId).set({
        providers: {
          stripe: {
            status: stripeStatus,
            chargesEnabled: account.charges_enabled,
            payoutsEnabled: account.payouts_enabled,
            updatedAt: FieldValue.serverTimestamp(),
          },
        },
      }, { merge: true });
    } catch (error) {
      console.error('Stripe account status refresh failed:', error.message);
      return res.status(502).json({ error: 'Unable to refresh Stripe onboarding status.' });
    }
  }
  res.json({
    providers: {
      stripe: { connected: Boolean(providers.stripe?.accountId), status: stripeStatus },
      mercadoPago: { connected: Boolean(providers.mercadoPago?.userId), status: providers.mercadoPago?.status || 'not_connected' },
      bankTransfer: { connected: Boolean(providers.bankTransfer?.alias), status: providers.bankTransfer?.status || 'not_connected' },
    },
    subscription: req.business.subscription || { status: 'inactive' },
  });
});

app.put('/api/business/bank-transfer', requireFirebaseAuth, requireBusinessMember,
  allowRoles('owner'), requirePaidAccess, async (req, res) => {
  const { bank, keyType, alias, accountHolder } = req.body;
  const banks = [
    'Bancolombia',
    'Davivienda',
    'Nequi',
    'DaviPlata',
    'Banco de Bogotá',
    'Banco Agrario',
    'BBVA',
    'Banco de Occidente',
    'Banco Caja Social',
    'Banco Popular',
    'Banco AV Villas',
    'Scotiabank Colpatria',
    'Banco Falabella',
    'Nu',
    'Lulo Bank',
    'Banco Pichincha',
    'Bancoomeva',
    'Otro',
  ];
  const keyTypes = ['phone', 'email', 'national_id', 'merchant_code'];
  if (!banks.includes(bank) || !keyTypes.includes(keyType) ||
      typeof alias !== 'string' || alias.trim().length < 3 || alias.trim().length > 120 ||
      typeof accountHolder !== 'string' || accountHolder.trim().length < 2 || accountHolder.trim().length > 100) {
    return res.status(400).json({ error: 'Enter a valid bank, Bre-B key type, key and account holder.' });
  }

  try {
    const previousBank = req.business.providers?.bankTransfer?.bank;
    const clearPreviousMerchantQr =
      previousBank && previousBank !== bank;
    await getFirestore().collection('businesses').doc(req.businessId).set({
      providers: {
        bankTransfer: {
          bank,
          keyType,
          alias: alias.trim(),
          accountHolder: accountHolder.trim(),
          status: 'manual_transfer',
          updatedAt: FieldValue.serverTimestamp(),
          ...(clearPreviousMerchantQr
            ? {
                qrImageBase64: FieldValue.delete(),
                qrImageMimeType: FieldValue.delete(),
                qrBank: FieldValue.delete(),
                qrImageUpdatedAt: FieldValue.delete(),
              }
            : {}),
        },
      },
      defaultPaymentMethod: 'bank_transfer',
      updatedAt: FieldValue.serverTimestamp(),
    }, { merge: true });
    res.json({ status: 'manual_transfer', bank, keyType, alias: alias.trim() });
  } catch (error) {
    console.error('Bank transfer setup failed:', error);
    res.status(error.status || 500).json({ error: error.message });
  }
});

const MAX_MERCHANT_QR_BYTES = 600 * 1024;
const merchantQrImageBody = express.raw({
  type: ['image/png', 'image/jpeg'],
  limit: MAX_MERCHANT_QR_BYTES,
});

app.put(
  '/api/business/bank-transfer/qr',
  requireFirebaseAuth,
  requireBusinessMember,
  allowRoles('owner'),
  requirePaidAccess,
  merchantQrImageBody,
  async (req, res) => {
    const bankTransfer = req.business.providers?.bankTransfer;
    if (!['Bancolombia', 'Nequi'].includes(bankTransfer?.bank)) {
      return res.status(409).json({
        error: 'Provider QR image upload is available for Bancolombia or Nequi Negocios.',
      });
    }

    if (!Buffer.isBuffer(req.body) || req.body.length === 0) {
      return res.status(400).json({ error: 'Select a PNG or JPEG merchant QR image.' });
    }
    if (req.body.length > MAX_MERCHANT_QR_BYTES) {
      return res.status(413).json({ error: 'The QR image must be 600 KB or smaller.' });
    }

    const mimeType = req.headers['content-type']?.split(';')[0]?.trim();
    const isPng = req.body.subarray(0, 8).equals(
      Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]),
    );
    const isJpeg =
      req.body[0] === 0xff &&
      req.body[1] === 0xd8 &&
      req.body[2] === 0xff;
    if (
      !((mimeType === 'image/png' && isPng) ||
        (mimeType === 'image/jpeg' && isJpeg))
    ) {
      return res.status(400).json({ error: 'The file must be a valid PNG or JPEG image.' });
    }

    try {
      await getFirestore()
        .collection('businesses')
        .doc(req.businessId)
        .update({
          'providers.bankTransfer.qrImageBase64': req.body.toString('base64'),
          'providers.bankTransfer.qrImageMimeType': mimeType,
          'providers.bankTransfer.qrBank': bankTransfer.bank,
          'providers.bankTransfer.qrImageUpdatedAt':
            FieldValue.serverTimestamp(),
          updatedAt: FieldValue.serverTimestamp(),
        });
      res.json({ status: 'saved', bank: bankTransfer.bank });
    } catch (error) {
      console.error('Merchant QR image upload failed:', error);
      res.status(error.status || 500).json({ error: 'Unable to save the merchant QR image.' });
    }
  },
);

app.delete(
  '/api/business/bank-transfer/qr',
  requireFirebaseAuth,
  requireBusinessMember,
  allowRoles('owner'),
  requirePaidAccess,
  async (req, res) => {
    try {
      await getFirestore()
        .collection('businesses')
        .doc(req.businessId)
        .update({
          'providers.bankTransfer.qrImageBase64': FieldValue.delete(),
          'providers.bankTransfer.qrImageMimeType': FieldValue.delete(),
          'providers.bankTransfer.qrBank': FieldValue.delete(),
          'providers.bankTransfer.qrImageUpdatedAt': FieldValue.delete(),
          updatedAt: FieldValue.serverTimestamp(),
        });
      res.json({ status: 'removed' });
    } catch (error) {
      console.error('Merchant QR image removal failed:', error);
      res.status(error.status || 500).json({ error: 'Unable to remove the merchant QR image.' });
    }
  },
);

app.get(
  '/api/business/providers/nequi/credentials',
  requireFirebaseAuth,
  requireBusinessMember,
  allowRoles('owner'),
  requirePaidAccess,
  async (req, res) => {
    try {
      const config = await getFirestore()
        .collection('businesses')
        .doc(req.businessId)
        .collection('privateIntegrations')
        .doc('nequi');
      const snapshot = await config.get();
      const savedAt = snapshot.data()?.updatedAt?.toDate?.()?.toISOString() || null;
      res.json({
        configured: snapshot.exists,
        ready: false,
        status: 'not_implemented',
        reason: 'Stored credentials do not enable Nequi Push; payment initiation and callback verification are not implemented.',
        updatedAt: savedAt,
      });
    } catch (error) {
      console.error('Nequi credential status check failed:', error);
      res.status(error.status || 500).json({ error: 'Unable to load Nequi setup status.' });
    }
  },
);

app.put(
  '/api/business/providers/nequi/credentials',
  requireFirebaseAuth,
  requireBusinessMember,
  allowRoles('owner'),
  requirePaidAccess,
  async (req, res) => {
    const { clientId, clientSecret, apiKey } = req.body;
    const credentials = { clientId, clientSecret, apiKey };
    if (
      Object.values(credentials).some((value) =>
        typeof value !== 'string' || value.trim().length < 4 || value.length > 500,
      )
    ) {
      return res.status(400).json({
        error: 'Enter the Client ID, Client Secret, and API Key issued by Nequi.',
      });
    }

    try {
      const encryptedCredentials = encryptProviderToken(
        JSON.stringify({
          clientId: clientId.trim(),
          clientSecret: clientSecret.trim(),
          apiKey: apiKey.trim(),
        }),
      );
      await getFirestore()
        .collection('businesses')
        .doc(req.businessId)
        .collection('privateIntegrations')
        .doc('nequi')
        .set({
          credentialsEncrypted: encryptedCredentials,
          updatedAt: FieldValue.serverTimestamp(),
        });
      res.json({ configured: true });
    } catch (error) {
      console.error('Nequi credentials could not be saved:', error.message);
      res.status(error.status || 500).json({
        error: error.status === 503
          ? error.message
          : 'Unable to securely save Nequi credentials.',
      });
    }
  },
);

app.delete(
  '/api/business/providers/nequi/credentials',
  requireFirebaseAuth,
  requireBusinessMember,
  allowRoles('owner'),
  requirePaidAccess,
  async (req, res) => {
    try {
      await getFirestore()
        .collection('businesses')
        .doc(req.businessId)
        .collection('privateIntegrations')
        .doc('nequi')
        .delete();
      res.json({ configured: false });
    } catch (error) {
      console.error('Nequi credentials could not be removed:', error);
      res.status(error.status || 500).json({ error: 'Unable to remove Nequi credentials.' });
    }
  },
);

app.post('/api/business/bank-transfer/create', requireFirebaseAuth, requireBusinessMember,
  allowRoles('owner', 'cashier'), requirePermission('charge'), requirePaidAccess,
  requirePaymentProviderReadiness('bank_transfer'), async (req, res) => {
    const { service, vehicle, amount } = req.body;
    const bankTransfer = req.business.providers?.bankTransfer;
    if (!bankTransfer?.alias) {
      return res.status(409).json({ error: 'Set up a bank transfer key before accepting a transfer.' });
    }
    if (typeof service !== 'string' || !service.trim() ||
        !Number.isSafeInteger(amount) || amount <= 0) {
      return res.status(400).json({ error: 'A service and positive whole-COP amount are required.' });
    }

    try {
      const ref = getFirestore().collection('businesses').doc(req.businessId)
        .collection('transactions').doc();
      await ref.create({
        service: service.trim(),
        vehicle: typeof vehicle === 'string' ? vehicle.trim() : '',
        amount,
        currency: 'COP',
        method: `Transferencia ${bankTransfer.bank}`,
        provider: 'bank_transfer',
        status: 'pending',
        transferAlias: bankTransfer.alias,
        transferKeyType: bankTransfer.keyType,
        createdAt: FieldValue.serverTimestamp(),
      });
      res.status(201).json({
        transactionId: ref.id,
        status: 'pending',
        bank: bankTransfer.bank,
        keyType: bankTransfer.keyType,
        alias: bankTransfer.alias,
        accountHolder: bankTransfer.accountHolder,
      });
    } catch (error) {
      console.error('Bank transfer request creation failed:', error);
      res.status(500).json({ error: 'Unable to create a transfer request.' });
    }
  });

app.post('/api/business/mercado-pago/create-payment', requireFirebaseAuth, requireBusinessMember,
  allowRoles('owner', 'cashier'), requirePermission('charge'), requirePaidAccess,
  requirePaymentProviderReadiness('mercado_pago'), async (req, res) => {
    const { service, vehicle, amount } = req.body;
    if (typeof service !== 'string' || !service.trim() ||
        !Number.isSafeInteger(amount) || amount <= 0) {
      return res.status(400).json({ error: 'A service and positive whole-COP amount are required.' });
    }
    const provider = req.business.providers?.mercadoPago;
    if (!provider?.accessTokenEncrypted || provider.status !== 'connected') {
      return res.status(409).json({ error: 'Connect the seller Mercado Pago account first.' });
    }

    let transactionRef;
    try {
      const token = await getMercadoPagoAccessToken(req.businessId, provider);
      transactionRef = getFirestore().collection('businesses').doc(req.businessId)
        .collection('transactions').doc();
      const reference = `${req.businessId}:${transactionRef.id}`;
      await transactionRef.create({
        service: service.trim(),
        vehicle: typeof vehicle === 'string' ? vehicle.trim() : '',
        amount,
        currency: 'COP',
        method: 'Mercado Pago',
        provider: 'mercado_pago',
        status: 'pending',
        createdAt: FieldValue.serverTimestamp(),
      });

      const response = await fetch('https://api.mercadopago.com/checkout/preferences', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          items: [{
            title: service.trim(),
            quantity: 1,
            unit_price: amount,
            currency_id: 'COP',
          }],
          external_reference: reference,
          notification_url: `${process.env.DOMAIN}/webhook/mercado-pago`,
          back_urls: {
            success: `${process.env.DOMAIN}/success`,
            failure: `${process.env.DOMAIN}/success`,
            pending: `${process.env.DOMAIN}/success`,
          },
          auto_return: 'approved',
        }),
      });
      const preference = await response.json();
      if (!response.ok || !preference.init_point) {
        await transactionRef.update({
          status: 'failed',
          updatedAt: FieldValue.serverTimestamp(),
        });
        console.error('Mercado Pago preference creation failed:', preference.message || response.status);
        return res.status(502).json({ error: 'Mercado Pago could not create checkout for this seller.' });
      }
      res.status(201).json({
        transactionId: transactionRef.id,
        status: 'pending',
        checkoutUrl: preference.init_point,
      });
    } catch (error) {
      if (transactionRef) {
        await transactionRef.set({
          status: 'failed',
          updatedAt: FieldValue.serverTimestamp(),
        }, { merge: true });
      }
      console.error('Mercado Pago checkout failed:', error);
      res.status(error.status || 500).json({ error: error.message });
    }
  });

app.post('/api/business/transactions/:transactionId/confirm-transfer',
  requireFirebaseAuth, requireBusinessMember, allowRoles('owner', 'cashier'),
  requirePermission('charge'), requirePaidAccess, async (req, res) => {
    if (req.body.verifiedByVendor !== true) {
      return res.status(400).json({ error: 'Verify the deposit in the bank app before confirming.' });
    }
    try {
      const ref = getFirestore().collection('businesses').doc(req.businessId)
        .collection('transactions').doc(req.params.transactionId);
      const result = await getFirestore().runTransaction(async (transaction) => {
        const doc = await transaction.get(ref);
        if (!doc.exists || doc.data().provider !== 'bank_transfer') {
          const error = new Error('Bank transfer transaction not found.');
          error.status = 404;
          throw error;
        }
        if (doc.data().status !== 'pending') {
          const error = new Error('This transaction is no longer pending.');
          error.status = 409;
          throw error;
        }
        transaction.update(ref, {
          status: 'paid',
          confirmationSource: 'vendor_bank_verification',
          confirmedBy: req.authUser.uid,
          confirmedAt: FieldValue.serverTimestamp(),
        });
        return { id: doc.id, status: 'paid' };
      });
      res.json(result);
    } catch (error) {
      res.status(error.status || 500).json({ error: error.message });
    }
  });

app.post('/api/providers/mercadopago/connect', requireFirebaseAuth, requireBusinessMember,
  allowRoles('owner'), requirePaidAccess, async (req, res) => {
    const clientId = process.env.MERCADO_PAGO_CLIENT_ID;
    const redirectUri = process.env.MERCADO_PAGO_REDIRECT_URI;
    if (!clientId || !redirectUri) {
      return res.status(503).json({ error: 'Mercado Pago OAuth credentials are not configured on the server.' });
    }
    try {
      const state = signOAuthState({
        uid: req.authUser.uid,
        businessId: req.businessId,
        issuedAt: Date.now(),
      });
      const url = new URL('https://auth.mercadopago.com/authorization');
      url.searchParams.set('client_id', clientId);
      url.searchParams.set('response_type', 'code');
      url.searchParams.set('platform_id', 'mp');
      url.searchParams.set('redirect_uri', redirectUri);
      url.searchParams.set('state', state);
      res.json({ url: url.toString() });
    } catch (error) {
      res.status(error.status || 500).json({ error: error.message });
    }
  });

app.get('/oauth/mercado-pago/callback', async (req, res) => {
  const state = verifyOAuthState(req.query.state);
  const { code } = req.query;
  if (!state || typeof code !== 'string') {
    return res.status(400).send('Invalid or expired Mercado Pago connection request.');
  }
  try {
    const membership = await getFirestore().collection('businesses').doc(state.businessId)
      .collection('members').doc(state.uid).get();
    if (!membership.exists || membership.data().active !== true || membership.data().role !== 'owner') {
      return res.status(403).send('The business owner authorization is no longer active.');
    }
    const tokenResponse = await fetch('https://api.mercadopago.com/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client_id: process.env.MERCADO_PAGO_CLIENT_ID,
        client_secret: process.env.MERCADO_PAGO_CLIENT_SECRET,
        code,
        grant_type: 'authorization_code',
        redirect_uri: process.env.MERCADO_PAGO_REDIRECT_URI,
      }),
    });
    const tokenData = await tokenResponse.json();
    if (!tokenResponse.ok || !tokenData.access_token || !tokenData.user_id) {
      console.error('Mercado Pago OAuth exchange failed:', tokenData.error || tokenResponse.status);
      return res.status(502).send('Mercado Pago could not connect this seller account.');
    }
    await getFirestore().collection('businesses').doc(state.businessId).set({
      providers: {
        mercadoPago: {
          userId: String(tokenData.user_id),
          accessTokenEncrypted: encryptProviderToken(tokenData.access_token),
          refreshTokenEncrypted: tokenData.refresh_token
            ? encryptProviderToken(tokenData.refresh_token)
            : null,
          expiresAt: Date.now() + (Number(tokenData.expires_in) || 0) * 1000,
          status: 'connected',
          updatedAt: FieldValue.serverTimestamp(),
        },
      },
    }, { merge: true });
    res.redirect(`${process.env.DOMAIN}/onboarding-complete`);
  } catch (error) {
    console.error('Mercado Pago OAuth callback failed:', error);
    res.status(error.status || 500).send('Unable to save the Mercado Pago connection.');
  }
});

// ==========================================
// 1. STRIPE CONNECTED ACCOUNTS & ONBOARDING (v1 API)
// ==========================================

// Step 1: Create a new connected account using Stripe Accounts API
app.post('/create-connected-account', requireFirebaseAuth, requireBusinessMember,
  allowRoles('owner'), requirePaidAccess, async (req, res) => {
  try {
    requireStripe();
    const existingAccountId = req.business.providers?.stripe?.accountId;
    if (existingAccountId) {
      return res.json({ accountId: existingAccountId });
    }
    const { email } = req.body;
    const accountParams = {
      type: 'express',
      capabilities: {
        card_payments: { requested: true },
        transfers: { requested: true },
      },
    };

    if (email && typeof email === 'string' && email.trim() !== '') {
      accountParams.email = email.trim();
    }

    const account = await stripe.accounts.create(accountParams);

    await getFirestore().collection('businesses').doc(req.businessId).set({
      providers: {
        stripe: {
          accountId: account.id,
          status: 'onboarding',
          updatedAt: FieldValue.serverTimestamp(),
        },
      },
    }, { merge: true });
    res.json({ accountId: account.id });
  } catch (error) {
    console.error('Error creating connected account:', error);
    res.status(error.status || 500).json({ error: error.message });
  }
});

// Step 2: Generate a secure Stripe-hosted onboarding link
app.post('/create-account-link', requireFirebaseAuth, requireBusinessMember,
  allowRoles('owner'), requirePaidAccess, async (req, res) => {
  try {
    requireStripe();
    const targetAccount = req.business.providers?.stripe?.accountId;
    if (!targetAccount) {
      return res.status(409).json({ error: 'Create your Stripe account before requesting onboarding.' });
    }

    const accountLink = await stripe.accountLinks.create({
      account: targetAccount,
      refresh_url: `https://colombia-pos-backend.onrender.com/onboarding-refresh?accountId=${targetAccount}`,
      return_url: 'https://colombia-pos-backend.onrender.com/onboarding-complete',
      type: 'account_onboarding',
    });

    res.json({ url: accountLink.url });
  } catch (error) {
    console.error('Error creating account link:', error);
    res.status(error.status || 500).json({ error: error.message });
  }
});

// Route handler for Onboarding Refresh (when switching languages or refreshing Stripe page)
app.get('/onboarding-refresh', async (req, res) => {
  try {
    requireStripe();
    const accountId = req.query.accountId;
    if (typeof accountId !== 'string' || !accountId.startsWith('acct_')) {
      return res.status(400).send('Invalid onboarding account.');
    }
    const accounts = await getFirestore().collection('businesses')
      .where('providers.stripe.accountId', '==', accountId).limit(1).get();
    if (accounts.empty) {
      return res.status(404).send('Onboarding account not found.');
    }

    const accountLink = await stripe.accountLinks.create({
      account: accountId,
      refresh_url: `https://colombia-pos-backend.onrender.com/onboarding-refresh?accountId=${accountId}`,
      return_url: 'https://colombia-pos-backend.onrender.com/onboarding-complete',
      type: 'account_onboarding',
    });

    return res.redirect(accountLink.url);
  } catch (error) {
    console.error('Error in onboarding-refresh:', error);
    res.status(error.status || 500).send('Error refreshing onboarding session.');
  }
});

// Route handler for Onboarding Complete
app.get('/onboarding-complete', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>MOTO SPA S.S - Onboarding Completado</title>
        <style>
          body { font-family: system-ui, -apple-system, sans-serif; background: #0f172a; color: #f8fafc; text-align: center; padding: 40px 20px; }
          .card { background: #1e293b; max-width: 420px; margin: 0 auto; padding: 30px; border-radius: 16px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); }
          .icon { font-size: 48px; margin-bottom: 10px; }
          h2 { color: #22c55e; margin-bottom: 10px; }
          p { color: #94a3b8; font-size: 15px; line-height: 1.5; }
        </style>
      </head>
      <body>
        <div class="card">
          <div class="icon">✅</div>
          <h2>¡Registro de Stripe Completado!</h2>
          <p>Tu cuenta bancaria ha sido vinculada correctamente. Ya puedes regresar a la aplicación <strong>MOTO SPA S.S</strong>.</p>
        </div>
      </body>
    </html>
  `);
});

// Route handler for Subscription Success
app.get('/success', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>MOTO SPA S.S - Suscripción Exitosa</title>
        <style>
          body { font-family: system-ui, -apple-system, sans-serif; background: #0f172a; color: #f8fafc; text-align: center; padding: 40px 20px; }
          .card { background: #1e293b; max-width: 420px; margin: 0 auto; padding: 30px; border-radius: 16px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); }
          .icon { font-size: 48px; margin-bottom: 10px; }
          h2 { color: #3b82f6; margin-bottom: 10px; }
          p { color: #94a3b8; font-size: 15px; line-height: 1.5; }
        </style>
      </head>
      <body>
        <div class="card">
          <div class="icon">🎉</div>
          <h2>¡Suscripción Activada!</h2>
          <p>Tu terminal POS ha sido activada con éxito. Puedes regresar a la aplicación <strong>MOTO SPA S.S</strong>.</p>
        </div>
      </body>
    </html>
  `);
});

// ==========================================
// 2. WOMPI PAYMENT ENDPOINT
// ==========================================
app.post('/api/transactions', requireFirebaseAuth, requireBusinessMember,
  requirePaidAccess, (req, res) => {
  res.status(503).json({
    error: 'Wompi seller onboarding and signed payment notifications are not configured for this business.',
  });
});

// ==========================================
// 3. DEDICATED LOCAL PROVIDER ROUTES (Addi & Nequi)
// ==========================================
app.post('/api/local/addi/create-order', requireFirebaseAuth, requireBusinessMember,
  requirePaidAccess, async (req, res) => {
  res.status(503).json({ success: false, error: 'Addi checkout credentials and payment confirmation webhooks are not configured.' });
});

app.post('/api/local/nequi/qr', requireFirebaseAuth, requireBusinessMember,
  requirePaidAccess, async (req, res) => {
  res.status(503).json({ success: false, error: 'A Nequi-issued QR/payment request and verified callback are required.' });
});

app.post('/api/local/nequi/charge', requireFirebaseAuth, requireBusinessMember,
  allowRoles('owner', 'cashier'), requirePaidAccess, async (req, res) => {
  const { phoneNumber, value } = req.body;
  if (
    typeof phoneNumber !== 'string' ||
    !/^(?:\+?57)?3\d{9}$/.test(phoneNumber.replace(/\s|-/g, '')) ||
    !Number.isSafeInteger(value) ||
    value <= 0
  ) {
    return res.status(400).json({
      success: false,
      error: 'Enter a valid Colombian mobile number and positive whole-COP amount.',
    });
  }
  res.status(503).json({
    success: false,
    error: 'Nequi credentials can be saved securely, but this backend does not yet initiate Push payments or verify Nequi callbacks. No payment request was sent.',
  });
});

// ==========================================
// 4. STRIPE TERMINAL & PAYMENT INTENTS
// ==========================================
app.post('/connectionToken', requireFirebaseAuth, requireBusinessMember, allowRoles('owner', 'cashier'),
  requirePermission('charge'), requirePaidAccess,
  requirePaymentProviderReadiness('stripe'), async (req, res) => {
    try {
        requireStripe();
        const connectionToken = await stripe.terminal.connectionTokens.create();
        res.json({ secret: connectionToken.secret });
    } catch (error) {
        res.status(error.status || 500).send({ error: error.message });
    }
});

app.post('/connection-token', requireFirebaseAuth, requireBusinessMember, allowRoles('owner', 'cashier'),
  requirePermission('charge'), requirePaidAccess,
  requirePaymentProviderReadiness('stripe'), async (req, res) => {
    try {
        requireStripe();
        const connectionToken = await stripe.terminal.connectionTokens.create();
        res.json({ secret: connectionToken.secret });
    } catch (error) {
        res.status(error.status || 500).json({ error: error.message });
    }
});

app.post('/create-payment-intent', requireFirebaseAuth, requireBusinessMember, allowRoles('owner', 'cashier'),
  requirePermission('charge'), requirePaidAccess,
  requirePaymentProviderReadiness('stripe'), async (req, res) => {
    try {
        requireStripe();
        const { amount, service, vehicle } = req.body;
        const targetVendor = req.business.providers?.stripe?.accountId;
        if (!targetVendor || req.business.providers.stripe.status !== 'active') {
          return res.status(409).json({ error: 'Complete Stripe onboarding before accepting card payments.' });
        }
        if (!Number.isSafeInteger(amount) || amount <= 0) {
          return res.status(400).json({ error: 'Amount must be a positive whole-COP value.' });
        }

        const paymentIntent = await stripe.paymentIntents.create({
            amount: amount,
            currency: 'cop',
            payment_method_types: ['card'],
            capture_method: 'automatic',
            transfer_data: { destination: targetVendor },
            on_behalf_of: targetVendor,
            metadata: {
              businessId: req.businessId,
              service: typeof service === 'string' ? service : 'Servicio',
              vehicle: typeof vehicle === 'string' ? vehicle : '',
              paymentMethod: 'Stripe (Tarjeta)',
              feeStrategy: 'platform_absorbs',
            },
        });

        res.send({ clientSecret: paymentIntent.client_secret });
    } catch (error) {
        console.error('Stripe payment intent creation failed:', error);
        res.status(error.status || 500).send({ error: error.message });
    }
});

app.post('/create-terminal-intent', requireFirebaseAuth, requireBusinessMember, allowRoles('owner', 'cashier'),
  requirePermission('charge'), requirePaidAccess,
  requirePaymentProviderReadiness('stripe'), async (req, res) => {
  try {
    requireStripe();
    const { amount, service, vehicle } = req.body;
    const targetVendor = req.business.providers?.stripe?.accountId;
    if (!targetVendor || req.business.providers.stripe.status !== 'active') {
      return res.status(409).json({ error: 'Complete Stripe onboarding before accepting Tap to Pay.' });
    }
    if (!Number.isSafeInteger(amount) || amount <= 0) {
      return res.status(400).json({ error: 'Amount must be a positive whole-COP value.' });
    }
    const intent = await stripe.paymentIntents.create({
      amount,
      currency: 'cop',
      payment_method_types: ['card_present'],
      capture_method: 'automatic',
      transfer_data: { destination: targetVendor },
      on_behalf_of: targetVendor,
      metadata: {
        businessId: req.businessId,
        service: typeof service === 'string' ? service : 'Servicio',
        vehicle: typeof vehicle === 'string' ? vehicle : '',
        paymentMethod: 'Tap to Pay (NFC)',
        feeStrategy: 'platform_absorbs',
      },
    });
    res.json({ clientSecret: intent.client_secret });
  } catch (error) {
    console.error('Stripe Terminal intent creation failed:', error);
    res.status(error.status || 500).json({ error: error.message });
  }
});

app.post('/create-checkout-session', requireFirebaseAuth, requireBusinessMember, allowRoles('owner'), async (req, res) => {
  try {
    requireStripe();
    const plans = {
      barrio: process.env.STRIPE_PRICE_BARRIO,
      restaurant: process.env.STRIPE_PRICE_RESTAURANT,
      pharmacy: process.env.STRIPE_PRICE_PHARMACY,
      station: process.env.STRIPE_PRICE_STATION,
      chain: process.env.STRIPE_PRICE_CHAIN,
      legacy: process.env.STRIPE_PRICE_POS_MONTHLY,
    };
    const planId = typeof req.body.planId === 'string' ? req.body.planId : 'legacy';
    const priceId = plans[planId];
    if (!Object.hasOwn(plans, planId)) {
      return res.status(400).json({ error: 'Select a valid subscription plan.' });
    }
    if (!priceId) {
      return res.status(503).json({ error: `Configure the Stripe price for the ${planId} plan in the Render environment.` });
    }
    const expectedPlanAmounts = {
      barrio: 29900,
      restaurant: 54900,
      pharmacy: 54900,
      station: 94900,
      chain: 184900,
    };
    if (planId !== 'legacy') {
      const configuredPrice = await stripe.prices.retrieve(priceId);
      if (
        !configuredPrice.active ||
        configuredPrice.currency !== 'cop' ||
        configuredPrice.unit_amount !== expectedPlanAmounts[planId] ||
        configuredPrice.recurring?.interval !== 'month' ||
        configuredPrice.recurring?.interval_count !== 1
      ) {
        return res.status(503).json({
          error: `The Stripe price for the ${planId} plan must be active, monthly, and match its advertised COP amount.`,
        });
      }
    }
    const session = await stripe.checkout.sessions.create({
      ui_mode: 'hosted_page',
      mode: 'subscription',
      success_url: `${process.env.DOMAIN}/success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${process.env.DOMAIN}`,
      line_items: [{ price: priceId, quantity: 1 }],
      client_reference_id: req.businessId,
      metadata: { businessId: req.businessId, planId },
      subscription_data: { metadata: { businessId: req.businessId, planId } },
    });
    res.json({ url: session.url });
  } catch (error) {
    console.error('Subscription checkout creation failed:', error);
    res.status(error.status || 500).json({ error: error.message });
  }
});

app.use((error, req, res, next) => {
  if (error.type === 'entity.too.large') {
    return res.status(413).json({ error: 'The uploaded image exceeds the 600 KB limit.' });
  }
  if (error.type === 'entity.parse.failed') {
    return res.status(400).json({ error: 'The request body is invalid.' });
  }
  console.error('Unhandled request error:', error);
  res.status(500).json({ error: 'The server could not process this request.' });
});

if (require.main === module) {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`Backend server running on port ${PORT}`);
  });
}

module.exports = app;