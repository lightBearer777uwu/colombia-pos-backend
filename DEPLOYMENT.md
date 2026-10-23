# Secure payment setup

## Firebase

1. Enable Firebase Authentication **Anonymous** sign-in for this no-sign-up test build. For a production release, use a recoverable business-owner sign-in and account-linking flow; anonymous test businesses are tied to one app installation and cannot be recovered after app data is cleared or the device is replaced. Configure email/password, Google, or Apple only if those login methods are intentionally reintroduced.
2. Create the Firestore database in the same Firebase project and deploy the app's `firestore.rules`. Keep transaction, membership, and inventory writes server-only; the Render service uses Firebase Admin.
3. Add the Firebase Admin service-account JSON to Render as `FIREBASE_SERVICE_ACCOUNT_JSON`. Never put this credential in the Flutter app or commit it.
4. Build Flutter with the Firebase-generated platform configuration and the Render API URL:

   ```powershell
   flutter run --dart-define=BACKEND_BASE_URL=https://YOUR-RENDER-DOMAIN
   ```

## Render environment

Configure the following values in the backend Render service. Use secrets for credentials and keep `DOMAIN` set to the public HTTPS origin without a trailing slash.

- `FIREBASE_SERVICE_ACCOUNT_JSON`
- `DOMAIN`
- `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, and `STRIPE_PRICE_POS_MONTHLY`
- `PROVIDER_TOKEN_ENCRYPTION_KEY`: base64 encoding of exactly 32 random bytes
- `OAUTH_STATE_SECRET`: a random secret of at least 32 characters
- `MERCADO_PAGO_CLIENT_ID`, `MERCADO_PAGO_CLIENT_SECRET`, `MERCADO_PAGO_REDIRECT_URI`, and `MERCADO_PAGO_WEBHOOK_SECRET`

Set `STRIPE_PRICE_BARRIO`, `STRIPE_PRICE_RESTAURANT`, `STRIPE_PRICE_PHARMACY`, `STRIPE_PRICE_STATION`, or `STRIPE_PRICE_CHAIN` only if those plans are offered. The app's monthly POS subscription button uses `STRIPE_PRICE_POS_MONTHLY`; the actual amount comes from that Stripe price.

In the Stripe dashboard, configure `/webhook` and subscribe to `checkout.session.completed`, `invoice.paid`, `customer.subscription.updated`, `customer.subscription.deleted`, `account.updated`, and `payment_intent.succeeded`. Verify Stripe Connect Express, destination charges, and COP settlement are available for the platform's registered country before enabling live payments. Build the Flutter app with the public publishable key:

```powershell
flutter run --dart-define=STRIPE_PUBLISHABLE_KEY=pk_live_REPLACE_ME
```

In Mercado Pago, register the exact OAuth redirect URI ending in `/oauth/mercado-pago/callback` and configure payment notifications to `https://YOUR-RENDER-DOMAIN/webhook/mercado-pago`. Set the webhook secret from Mercado Pago's application configuration.

## Payment limitations

Stripe and Mercado Pago payments stay pending until their signed provider webhooks verify them. Stripe Tap to Pay also needs a supported device, Stripe Terminal account configuration, and the provider's production approvals. Bre-B is Banco de la República's interoperable instant-payment system, not a bank account that a merchant opens with Banco de la República. The vendor needs to activate/register their receiving key with a participating bank, wallet, or payment provider. The app's Bancolombia, Davivienda, Nequi, and Bre-B information buttons are shortcuts to official information/channels; the vendor must complete sign-in and key registration with the chosen participant, then manually save only the public key and account-holder name in this app. This is **not** a bank OAuth/API connection and never asks for bank passwords, PINs, API keys, or permission tokens. Transfer setup gives customers manual instructions; it does **not** create a real dynamic Bre-B or Nequi QR, initiate a Nequi push request, or automatically verify a bank deposit. A business owner must verify the deposit in the bank's own app before using the explicit manual confirmation action. Addi and Wompi remain unavailable until official merchant credentials and verified callback integrations are implemented; setting placeholder credentials does not activate them.

Employees must first create a Firebase Auth account before an owner can add their email and permissions. The app does not currently send employee invitations.
