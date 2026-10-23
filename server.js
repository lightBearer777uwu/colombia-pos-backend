const express = require('express');
const app = express();
const admin = require('firebase-admin');
const crypto = require('crypto');

const stripe = process.env.STRIPE_SECRET_KEY
  ? require('stripe')(process.env.STRIPE_SECRET_KEY)
  : null;

let firebaseApp;
try {
  const serviceAccount = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
  if (serviceAccount) {
    firebaseApp = admin.initializeApp({
      credential: admin.credential.cert(JSON.parse(serviceAccount)),
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
  return admin.firestore();
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
    req.authUser = await admin.auth().verifyIdToken(match[1], true);
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

function requireActiveSubscription(req, res, next) {
  const status = req.business.subscription?.status;
  if (!['active', 'trialing'].includes(status)) {
    return res.status(402).json({
      error: 'An active POS subscription is required to accept payments.',
      subscriptionStatus: status || 'inactive',
    });
  }
  next();
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
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
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
              updatedAt: admin.firestore.FieldValue.serverTimestamp(),
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
              updatedAt: admin.firestore.FieldValue.serverTimestamp(),
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
              updatedAt: admin.firestore.FieldValue.serverTimestamp(),
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
              updatedAt: admin.firestore.FieldValue.serverTimestamp(),
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
            createdAt: admin.firestore.FieldValue.serverTimestamp(),
            confirmedAt: admin.firestore.FieldValue.serverTimestamp(),
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
    const transaction = await transactionRef.get();
    if (!transaction.exists || transaction.data().provider !== 'mercado_pago') {
      return res.status(404).json({ error: 'Payment transaction was not found.' });
    }
    await transactionRef.set({
      status: payment.status === 'approved' ? 'paid' : payment.status || 'pending',
      providerPaymentId: String(payment.id),
      confirmedAt: payment.status === 'approved'
        ? admin.firestore.FieldValue.serverTimestamp()
        : null,
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    }, { merge: true });
    res.json({ received: true });
  } catch (error) {
    console.error('Mercado Pago webhook processing failed:', error);
    res.status(error.status || 500).json({ error: 'Webhook processing failed.' });
  }
});

app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
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
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
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

app.get('/api/business/me', requireFirebaseAuth, requireBusinessMember, (req, res) => {
  res.json({
    businessId: req.businessId,
    name: req.business.name,
    role: req.memberRole,
    permissions: req.memberPermissions,
    providers: req.business.providers || {},
    defaultPaymentMethod: req.business.defaultPaymentMethod || '',
    subscription: req.business.subscription || { status: 'inactive' },
  });
});

app.put('/api/business/payment-method', requireFirebaseAuth, requireBusinessMember,
  allowRoles('owner'), async (req, res) => {
    const { method } = req.body;
    const allowedMethods = ['bank_transfer', 'mercado_pago', 'stripe'];
    if (!allowedMethods.includes(method)) {
      return res.status(400).json({ error: 'Choose a supported payment method.' });
    }

    const providers = req.business.providers || {};
    const configured = {
      bank_transfer: Boolean(providers.bankTransfer?.alias),
      mercado_pago: providers.mercadoPago?.status === 'connected' &&
        Boolean(providers.mercadoPago?.accessTokenEncrypted),
      stripe: Boolean(providers.stripe?.accountId) &&
        providers.stripe?.status === 'active',
    };
    if (!configured[method]) {
      return res.status(409).json({
        error: 'Connect and verify this payment method before making it the default.',
      });
    }

    try {
      await getFirestore().collection('businesses').doc(req.businessId).set({
        defaultPaymentMethod: method,
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      }, { merge: true });
      res.json({ defaultPaymentMethod: method });
    } catch (error) {
      console.error('Default payment method update failed:', error);
      res.status(error.status || 500).json({ error: 'Unable to save the default payment method.' });
    }
  });

app.get('/api/business/members', requireFirebaseAuth, requireBusinessMember,
  allowRoles('owner'), async (req, res) => {
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

app.post('/api/business/members', requireFirebaseAuth, requireBusinessMember,
  allowRoles('owner'), async (req, res) => {
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
      const user = await admin.auth().getUserByEmail(email);
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
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      }, { merge: true });
      await admin.auth().setCustomUserClaims(user.uid, {
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
        revokedAt: admin.firestore.FieldValue.serverTimestamp(),
      });
      const user = await admin.auth().getUser(req.params.uid);
      const claims = { ...(user.customClaims || {}) };
      if (claims.businessId === req.businessId) {
        delete claims.businessId;
        await admin.auth().setCustomUserClaims(req.params.uid, claims);
      }
      res.json({ revoked: true });
    } catch (error) {
      console.error('Revoking business member failed:', error);
      res.status(500).json({ error: 'Unable to revoke this employee.' });
    }
  });

app.get('/api/business/transactions', requireFirebaseAuth, requireBusinessMember,
  requirePermission('viewReports'), async (req, res) => {
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
  allowRoles('owner', 'cashier'), requirePermission('charge'), requireActiveSubscription, async (req, res) => {
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
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
        confirmedAt: admin.firestore.FieldValue.serverTimestamp(),
      });
      res.status(201).json({ id: ref.id, status: 'paid' });
    } catch (error) {
      console.error('Cash transaction recording failed:', error);
      res.status(500).json({ error: 'Unable to record this cash transaction.' });
    }
  });

app.get('/api/business/providers', requireFirebaseAuth, requireBusinessMember, async (req, res) => {
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
            updatedAt: admin.firestore.FieldValue.serverTimestamp(),
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

app.put('/api/business/bank-transfer', requireFirebaseAuth, requireBusinessMember, allowRoles('owner'), async (req, res) => {
  const { bank, keyType, alias, accountHolder } = req.body;
  const banks = ['Bancolombia', 'Davivienda', 'Nequi', 'Banco de Bogotá', 'Banco Agrario', 'BBVA', 'Otro'];
  const keyTypes = ['phone', 'email', 'national_id', 'merchant_code'];
  if (!banks.includes(bank) || !keyTypes.includes(keyType) ||
      typeof alias !== 'string' || alias.trim().length < 3 || alias.trim().length > 120 ||
      typeof accountHolder !== 'string' || accountHolder.trim().length < 2 || accountHolder.trim().length > 100) {
    return res.status(400).json({ error: 'Enter a valid bank, Bre-B key type, key and account holder.' });
  }

  try {
    await getFirestore().collection('businesses').doc(req.businessId).set({
      providers: {
        bankTransfer: {
          bank,
          keyType,
          alias: alias.trim(),
          accountHolder: accountHolder.trim(),
          status: 'manual_transfer',
          updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        },
      },
      defaultPaymentMethod: 'bank_transfer',
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    }, { merge: true });
    res.json({ status: 'manual_transfer', bank, keyType, alias: alias.trim() });
  } catch (error) {
    console.error('Bank transfer setup failed:', error);
    res.status(error.status || 500).json({ error: error.message });
  }
});

app.post('/api/business/bank-transfer/create', requireFirebaseAuth, requireBusinessMember,
  allowRoles('owner', 'cashier'), requirePermission('charge'), requireActiveSubscription, async (req, res) => {
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
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
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
  allowRoles('owner', 'cashier'), requirePermission('charge'), requireActiveSubscription, async (req, res) => {
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
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
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
          updatedAt: admin.firestore.FieldValue.serverTimestamp(),
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
          updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        }, { merge: true });
      }
      console.error('Mercado Pago checkout failed:', error);
      res.status(error.status || 500).json({ error: error.message });
    }
  });

app.post('/api/business/transactions/:transactionId/confirm-transfer',
  requireFirebaseAuth, requireBusinessMember, allowRoles('owner', 'cashier'),
  requirePermission('charge'), async (req, res) => {
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
          confirmedAt: admin.firestore.FieldValue.serverTimestamp(),
        });
        return { id: doc.id, status: 'paid' };
      });
      res.json(result);
    } catch (error) {
      res.status(error.status || 500).json({ error: error.message });
    }
  });

app.post('/api/providers/mercadopago/connect', requireFirebaseAuth, requireBusinessMember,
  allowRoles('owner'), async (req, res) => {
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
          updatedAt: admin.firestore.FieldValue.serverTimestamp(),
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
app.post('/create-connected-account', requireFirebaseAuth, requireBusinessMember, allowRoles('owner'), async (req, res) => {
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
          updatedAt: admin.firestore.FieldValue.serverTimestamp(),
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
app.post('/create-account-link', requireFirebaseAuth, requireBusinessMember, allowRoles('owner'), async (req, res) => {
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
app.post('/api/transactions', requireFirebaseAuth, requireBusinessMember, (req, res) => {
  res.status(503).json({
    error: 'Wompi seller onboarding and signed payment notifications are not configured for this business.',
  });
});

// ==========================================
// 3. DEDICATED LOCAL PROVIDER ROUTES (Addi & Nequi)
// ==========================================
app.post('/api/local/addi/create-order', requireFirebaseAuth, requireBusinessMember, async (req, res) => {
  res.status(503).json({ success: false, error: 'Addi checkout credentials and payment confirmation webhooks are not configured.' });
});

app.post('/api/local/nequi/qr', requireFirebaseAuth, requireBusinessMember, async (req, res) => {
  res.status(503).json({ success: false, error: 'A Nequi-issued QR/payment request and verified callback are required.' });
});

app.post('/api/local/nequi/charge', requireFirebaseAuth, requireBusinessMember, allowRoles('owner', 'cashier'), async (req, res) => {
  try {
    const { phoneNumber, value, reference } = req.body;
    if (!phoneNumber || !value) {
      return res.status(400).json({ success: false, error: 'Phone number and value are required' });
    }

    const clientId = process.env.NEQUI_CLIENT_ID;
    const clientSecret = process.env.NEQUI_CLIENT_SECRET;
    const apiKey = process.env.NEQUI_API_KEY;

    if (!clientId || !clientSecret || !apiKey) {
      return res.status(503).json({
        success: false,
        error: 'Nequi merchant credentials and official payment status callbacks are not configured.',
      });
    }

    return res.status(503).json({
      success: false,
      error: 'Nequi payment initiation and webhook verification must be enabled for this merchant.',
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ==========================================
// 4. STRIPE TERMINAL & PAYMENT INTENTS
// ==========================================
app.post('/connectionToken', requireFirebaseAuth, requireBusinessMember, allowRoles('owner', 'cashier'),
  requirePermission('charge'), requireActiveSubscription, async (req, res) => {
    try {
        requireStripe();
        const connectionToken = await stripe.terminal.connectionTokens.create();
        res.json({ secret: connectionToken.secret });
    } catch (error) {
        res.status(error.status || 500).send({ error: error.message });
    }
});

app.post('/connection-token', requireFirebaseAuth, requireBusinessMember, allowRoles('owner', 'cashier'),
  requirePermission('charge'), requireActiveSubscription, async (req, res) => {
    try {
        requireStripe();
        const connectionToken = await stripe.terminal.connectionTokens.create();
        res.json({ secret: connectionToken.secret });
    } catch (error) {
        res.status(error.status || 500).json({ error: error.message });
    }
});

app.post('/create-payment-intent', requireFirebaseAuth, requireBusinessMember, allowRoles('owner', 'cashier'),
  requirePermission('charge'), requireActiveSubscription, async (req, res) => {
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
  requirePermission('charge'), requireActiveSubscription, async (req, res) => {
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

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Backend server running on port ${PORT}`);
});