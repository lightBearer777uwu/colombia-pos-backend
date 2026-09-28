const express = require('express');
const app = express();

// Initialize Stripe for NFC Terminal tokens
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

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Backend server running on port ${PORT}`);
});