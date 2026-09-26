const express = require('express');
const app = express();

app.use(express.json());

// 1. Endpoint called by your mobile app to initiate a transaction
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

// 2. Webhook Endpoint: Listens for asynchronous payment confirmations from Wompi/Banks
app.post('/api/webhooks/wompi', (req, res) => {
  const event = req.body;

  if (event.event === 'transaction.updated') {
    const transaction = event.data.transaction;
    const status = transaction.status; 
    const reference = transaction.reference;

    console.log(`Webhook received! Transaction ${reference} is now: ${status}`);

    if (status === 'APPROVED') {
      // Logic when payment clears successfully
    }
  }

  return res.status(200).send('Webhook received successfully');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Backend server running on port ${PORT}`);
});