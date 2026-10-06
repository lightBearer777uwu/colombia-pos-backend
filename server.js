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
      console.log(`Checkout Session Completed! ID: ${event.data.object.id}`);
      break;
    case 'invoice.paid':
      console.log(`Invoice Paid Successfully! ID: ${event.data.object.id}`);
      break;
    case 'customer.subscription.deleted':
      console.log(`Subscription Cancelled/Ended: ${event.data.object.id}`);
      break;
    default:
      console.log(`Unhandled event type ${event.type}`);
  }

  res.json({ received: true });
});

app.use(express.json());

// ==========================================
// 1. STRIPE CONNECTED ACCOUNTS & ONBOARDING (v1 API)
// ==========================================

// Step 1: Create a new Express connected account using Stripe v1 API
app.post('/create-connected-account', async (req, res) => {
  try {
    const { email } = req.body;

    const account = await stripe.accounts.create({
      type: 'express',
      country: 'CO',
      email: email || 'vendor@moto-spa.com',
      capabilities: {
        card_payments: { requested: true },
        transfers: { requested: true },
      },
    });

    res.json({ accountId: account.id });
  } catch (error) {
    console.error('Error creating connected account:', error);
    res.status(500).json({ error: error.message });
  }
});

// Step 2: Generate a secure Stripe-hosted onboarding link
app.post('/create-account-link', async (req, res) => {
  try {
    const { accountId, vendorAccountId } = req.body;
    const targetAccount = accountId || vendorAccountId || 'acct_1UKnEG4DZRScEfeV';

    const accountLink = await stripe.accountLinks.create({
      account: targetAccount,
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
// 2. WOMPI PAYMENT ENDPOINT
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
// 3. DEDICATED LOCAL PROVIDER ROUTES (Addi & Nequi)
// ==========================================
app.post('/api/local/addi/create-order', async (req, res) => {
  try {
    const { amount, currency, orderId, customerDetails, items } = req.body;
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

app.post('/api/local/nequi/qr', async (req, res) => {
  try {
    const { value, reference } = req.body;
    return res.status(200).json({
      success: true,
      qrCode: `NEQUI-QR-DATA-${reference || Date.now()}`,
      value: value
    });
  } catch (error) {
    return res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/local/nequi/charge', async (req, res) => {
  try {
    const { phoneNumber, value, reference } = req.body;
    if (!phoneNumber || !value) {
      return res.status(400).json({ success: false, error: 'Phone number and value are required' });
    }

    const clientId = process.env.NEQUI_CLIENT_ID;
    const clientSecret = process.env.NEQUI_CLIENT_SECRET;
    const apiKey = process.env.NEQUI_API_KEY;

    if (!clientId || !clientSecret) {
      return res.status(200).json({
        success: true,
        provider: 'nequi',
        status: 'PENDING_APPROVAL',
        message: `[Mock] Solicitud enviada al Nequi #${phoneNumber}`,
        reference: reference
      });
    }

    // Nequi API flow...
    res.status(200).json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ==========================================
// 4. STRIPE TERMINAL & PAYMENT INTENTS
// ==========================================
app.post('/connectionToken', async (req, res) => {
    try {
        const connectionToken = await stripe.terminal.connectionTokens.create();
        res.json({ secret: connectionToken.secret });
    } catch (error) {
        res.status(500).send({ error: error.message });
    }
});

app.post('/create-payment-intent', async (req, res) => {
    try {
        const { amount, currency, vendorAccountId } = req.body;
        const targetVendor = vendorAccountId || 'acct_1UKnEG4DZRScEfeV';

        const paymentIntent = await stripe.paymentIntents.create({
            amount: amount,
            currency: currency || 'usd',
            payment_method_types: ['card_present'],
            capture_method: 'automatic',
            transfer_data: { destination: targetVendor },
            on_behalf_of: targetVendor,
        });

        res.send({ clientSecret: paymentIntent.client_secret });
    } catch (error) {
        res.status(500).send({ error: error.message });
    }
});

app.post('/create-checkout-session', async (req, res) => {
  try {
    const session = await stripe.checkout.sessions.create({
      ui_mode: 'hosted_page',
      mode: 'subscription',
      success_url: `${process.env.DOMAIN}/success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${process.env.DOMAIN}`,
      line_items: [{ price: 'price_1ULXHo4DzROVKhPKK29fyWTv', quantity: 1 }],
    });
    res.json({ url: session.url });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Backend server running on port ${PORT}`);
});