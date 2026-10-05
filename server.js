const express = require('express');
const app = express();

// Initialize Stripe for payments and terminals
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
// ==========================================
// STRIPE WEBHOOK HANDLER (MUST be before express.json())
// ==========================================
app.post('/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;

  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error(`Webhook signature verification failed: ${err.message}`);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  switch (event.type) {
    case 'checkout.session.completed':
      const session = event.data.object;
      console.log(`Checkout Session Completed! ID: ${session.id}`);
      break;

    case 'invoice.paid':
      const invoice = event.data.object;
      console.log(`Invoice Paid Successfully! ID: ${invoice.id}`);
      break;

    case 'invoice.payment_failed':
      const failedInvoice = event.data.object;
      console.log(`Payment Failed for Invoice: ${failedInvoice.id}`);
      break;

    case 'customer.subscription.deleted':
      const subscription = event.data.object;
      console.log(`Subscription Cancelled/Ended: ${subscription.id}`);
      break;

    default:
      console.log(`Unhandled event type ${event.type}`);
  }

  res.json({ received: true });
});
app.use(express.json());

// Step 1: Create a new Express connected account for a vendor (Accounts v2)
app.post('/create-connected-account', async (req, res) => {
  try {
    const { email } = req.body;

    const account = await stripe.accounts.create({
      dashboard: 'express', // Replaces the legacy 'type: express'
      country: 'co', 
      email: email,
      defaults: {
        responsibilities: {
          losses_collector: 'stripe', // Sets losses collector to Stripe as required
        },
      },
      capabilities: {
        card_payments: { requested: true },
        transfers: { requested: true },
      },
    });

    res.json({ accountId: account.id });
  } catch (error) {
    console.error('Error creating account:', error);
    res.status(500).json({ error: error.message });
  }
});

// Step 2: Generate a secure Stripe-hosted onboarding link
app.post('/create-account-link', async (req, res) => {
  try {
    const { accountId } = req.body;

    const accountLink = await stripe.accountLinks.create({
      account: accountId,
      refresh_url: 'https://colombia-pos-backend.onrender.com/onboarding-refresh',
      return_url: 'https://colombia-pos-backend.onrender.com/onboarding-complete',
      type: 'account_onboarding',
    });

    res.json({ url: accountLink.url });
  } catch (error) {
    console.error('Error creating account link:', error);
    res.status(500).json({ error: error.message });
  }
});
// ==========================================
// 1. WOMPI PAYMENT ENDPOINT (Nequi, QR, etc.)
// ==========================================
app.post('/api/transactions', async (req, res) => {
    const { amount, currency, reference, paymentSourceId } = req.body;
    try {
        const wompiPrivateKey = process.env.WOMPI_PRIVATE_KEY;
        const wompiResponse = await fetch('https://production.wompi.co/v1/transactions', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${wompiPrivateKey}`,
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                acceptance_token: 'sample_token',
                amount_in_cents: amount * 100,
                currency: currency || 'COP',
                customer_email: 'cliente@correo.com',
                reference: reference,
                payment_source_id: paymentSourceId,
            }),
        });
        const data = await wompiResponse.json();
        if (wompiResponse.ok) {
            return res.status(201).json({ success: true, data: data.data });
        } else {
            return res.status(400).json({ success: false, error: data.error });
        }
    } catch (error) {
        console.error('Server Transaction Error:', error);
        return res.status(500).json({ success: false, error: 'Internal Server Error' });
    }
});
// ==========================================
// DEDICATED LOCAL PROVIDER ROUTES (Addi & Nequi)
// ==========================================

// 1. Process Addi (BNPL) Order Creation Route
app.post('/api/local/addi/create-order', async (req, res) => {
  try {
    const { amount, currency, orderId, customerDetails, items } = req.body;
    
    // Construct Addi payload for Colombian gateway processing
    const payload = {
      totalAmount: amount,
      currency: currency || 'COP',
      orderId: orderId,
      client: {
        id: customerDetails.id,
        idType: customerDetails.idType || 'CC',
        firstName: customerDetails.firstName,
        lastName: customerDetails.lastName,
        email: customerDetails.email,
        phone: customerDetails.phone
      },
      items: items,
      redirectionUrl: {
        success: `${process.env.FRONTEND_URL || 'https://your-app.com'}/payment-success`,
        rejected: `${process.env.FRONTEND_URL || 'https://your-app.com'}/payment-rejected`
      }
    };

    // Simulated/Production scaffold response
    res.status(200).json({
      success: true,
      provider: 'addi',
      redirectUrl: `https://checkout.addi.com/pay/${orderId}`,
      orderId: orderId
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});
// Process Nequi QR Code Generation Route
app.post('/api/local/nequi/qr', async (req, res) => {
  try {
    const { value, reference } = req.body;
    
    if (!value) {
      return res.status(400).json({ success: false, error: 'Value is required' });
    }

    // Return a mock or real QR code response depending on your Nequi API setup
    return res.status(200).json({
      success: true,
      qrCode: `NEQUI-QR-DATA-${reference || Date.now()}`,
      value: value
    });
  } catch (error) {
    console.error('Nequi QR Error:', error);
    return res.status(500).json({ success: false, error: error.message });
  }
});
// 2. Process Nequi Direct Push / Wallet Transaction Route
app.post('/api/local/nequi/charge', async (req, res) => {
  try {
    const { phoneNumber, value, reference } = req.body;

    // Validate that required fields are present
    if (!phoneNumber || !value) {
      return res.status(400).json({ success: false, error: 'Phone number and value are required' });
    }

    // 1. Check if the environment variables are set yet
    const clientId = process.env.NEQUI_CLIENT_ID;
    const clientSecret = process.env.NEQUI_CLIENT_SECRET;
    const apiKey = process.env.NEQUI_API_KEY;

    // If credentials haven't been provided by the vendor yet, fall back gracefully to a pending mock response
    if (!clientId || !clientSecret) {
      console.log(`[NEQUI MOCK MODE] Charge requested for phone: ${phoneNumber}, amount: $${value}`);
      return res.status(200).json({
        success: true,
        provider: 'nequi',
        status: 'PENDING_APPROVAL',
        message: `[Mock] Solicitud enviada al Nequi #${phoneNumber}. Configure las credenciales en Render para habilitar producción.`,
        reference: reference
      });
    }

    // 2. Request OAuth2 Access Token from Nequi / Gateway Auth Server
    const authResponse = await fetch('https://api.nequi.com/v1/security/oauth/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Basic ' + Buffer.from(`${clientId}:${clientSecret}`).toString('base64')
      },
      body: JSON.stringify({ grant_type: 'client_credentials' })
    });

    const authData = await authResponse.json();
    const accessToken = authData.access_token;

    if (!accessToken) {
      return res.status(500).json({ success: false, error: 'Failed to authenticate with Nequi API' });
    }

    // 3. Request Push Notification / Payment
    const nequiResponse = await fetch('https://api.nequi.com/v1/services/payments/push', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${accessToken}`,
        'X-API-Key': apiKey
      },
      body: JSON.stringify({
        phoneNumber: phoneNumber,
        value: value.toString(),
        reference: reference,
        franchise: 'NEQUI'
      })
    });

    const nequiResult = await nequiResponse.json();

    if (nequiResponse.ok) {
      return res.status(200).json({
        success: true,
        provider: 'nequi',
        status: 'SUCCESS',
        data: nequiResult
      });
    } else {
      return res.status(400).json({ success: false, error: nequiResult });
    }

  } catch (error) {
    console.error('Nequi API Error:', error);
    return res.status(500).json({ success: false, error: error.message });
  }
});
// ==========================================
// 2. STRIPE TERMINAL CONNECTION TOKEN (NFC Tap-to-Pay)
// ==========================================
app.post('/connectionToken', async (req, res) => {
    try {
        const connectionToken = await stripe.terminal.connectionTokens.create();
        res.json({ secret: connectionToken.secret });
    } catch (error) {
        console.error('Stripe Terminal Error:', error);
        res.status(500).send({ error: error.message });
    }
});

// ==========================================
// 3. MULTI-VENDOR STRIPE PAYMENT INTENT ENDPOINT
// ==========================================
app.post('/create-payment-intent', async (req, res) => {
    try {
        const { amount, currency, vendorAccountId } = req.body;

        // Default to MOTO SPA's connected account if no dynamic vendor ID is provided yet
        const targetVendor = vendorAccountId || 'acct_1UKnEG4DZRScEfeV';

        const paymentIntentConfig = {
            amount: amount, // Expected in cents (e.g., $45.00 = 4500)
            currency: currency || 'usd',
            payment_method_types: ['card_present'], // Required for NFC Tap-to-Pay hardware
            capture_method: 'automatic',
        };

        if (targetVendor) {
            paymentIntentConfig.transfer_data = {
                destination: targetVendor, 
            };
            paymentIntentConfig.on_behalf_of = targetVendor;
        }

        const paymentIntent = await stripe.paymentIntents.create(paymentIntentConfig);

        res.send({
            clientSecret: paymentIntent.client_secret,
        });
    } catch (error) {
        console.error('Stripe Payment Intent Error:', error);
        res.status(500).send({ error: error.message });
    }
});

// ==========================================
// 4. STRIPE VENDOR ONBOARDING LINK ENDPOINT
// ==========================================
app.post('/create-account-link', async (req, res) => {
    try {
        const { vendorAccountId } = req.body;
        const targetVendor = vendorAccountId || 'acct_1UKnEG4DZRScEfeV';

        // Generates a secure, one-time Stripe-hosted link for bank & business setup
        const accountLink = await stripe.accountLinks.create({
            account: targetVendor,
            refresh_url: 'https://your-render-backend-url.com/reauth', // fallback URL if link expires
            return_url: 'https://your-render-backend-url.com/return',   // URL when they finish setup
            type: 'account_onboarding',
        });

        res.json({ url: accountLink.url });
    } catch (error) {
        console.error('Stripe Account Link Error:', error);
        res.status(500).send({ error: error.message });
    }
});
// ==========================================
// 5. STRIPE SUBSCRIPTION CHECKOUT SESSION ENDPOINT
// ==========================================
app.post('/create-checkout-session', async (req, res) => {
  try {
    const session = await stripe.checkout.sessions.create({
      ui_mode: 'hosted_page',
      mode: 'subscription',
      billing_address_collection: 'auto',
      phone_number_collection: { enabled: true },
      automatic_tax: { enabled: false },
      allow_promotion_codes: false,
      payment_method_collection: 'always',
      submit_type: 'auto',
      name_collection: {
        individual: { enabled: true, optional: true },
        business: { enabled: true, optional: true }
      },
      integration_identifier: 'hosted_mobile_app_0001',
      origin_context: 'mobile_app',
      success_url: `${process.env.DOMAIN}/success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${process.env.DOMAIN}`,
      line_items: [{ price: 'price_1ULXHo4DzROVKhPKK29fyWTv', quantity: 1 }], // Replace with your actual Stripe Price ID for the 50k COP product
    });

    res.json({ url: session.url });
  } catch (error) {
    console.error('Error creating checkout session:', error);
    res.status(500).json({ error: error.message });
  }
});
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Backend server running on port ${PORT}`);
});