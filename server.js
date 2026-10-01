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

// Step 1: Create a new Express connected account for a vendor
app.post('/create-connected-account', async (req, res) => {
  try {
    const { email } = req.body;

    const account = await stripe.accounts.create({
      type: 'express',
      country: 'CO', // Set to Colombia or the relevant country code
      email: email,
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