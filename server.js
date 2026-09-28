const express = require('express');
const app = express();

// Initialize Stripe for payments and terminals
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

app.use(express.json());

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

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Backend server running on port ${PORT}`);
});