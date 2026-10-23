# Secure payment setup

## Firebase

1. The app has no vendor login, PIN, Face ID, fingerprint, or sign-in prompt. It reuses an existing Firebase session if present; otherwise, it creates a Firebase Anonymous session in the background to authenticate backend requests. Enable **Anonymous** in Firebase Authentication for new app installations. Anonymous business identity is tied to that app installation and can be lost after app data is cleared or the device is replaced. Do not make protected endpoints public to work around this limitation.
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

Stripe and Mercado Pago payments stay pending until their signed provider webhooks verify them. Mercado Pago displays a QR that encodes its hosted checkout URL; it is not a bank-generated QR, and payment is still pending until the Mercado Pago webhook confirms it. The Finance tab lets the owner choose a connected default method; that choice is saved on the business record and the matching checkout option is shown at charge time. Stripe Tap to Pay also needs a supported device, Stripe Terminal account configuration, and the provider's production approvals.

Bre-B is Banco de la República's interoperable instant-payment system, not a bank account that a merchant opens with Banco de la República. The vendor must activate/register a receiving key with a participating bank, wallet, or payment provider. Nequi Negocios and Bancolombia Negocios (Llaves) provide official merchant QR/key routes. The vendor obtains their permanent merchant QR directly from that provider, then may upload its original PNG/JPEG image in the Finance tab (maximum 600 KB); the server stores the image with that business's Firestore record. The app displays and can share that uploaded image without regenerating or modifying it. Only upload a permanent merchant display QR—not a temporary QR for a different sale. The app does not verify that the image is genuine, create per-sale bank QR codes, initiate a bank transfer, or receive automatic payment status for those fixed QR transfers. The vendor must verify each deposit in the provider's official app before manually confirming the pending transaction. Nequi API credentials issued to an approved merchant can be submitted in the owner-only Finance setup form; they are sent to Render over HTTPS, encrypted using `PROVIDER_TOKEN_ENCRYPTION_KEY`, stored outside the business profile, and never returned to the app. Do not enter bank passwords, PINs, or personal Nequi login credentials.

Nequi Push is a separate assisted payment flow, not the static merchant QR. Nequi's official API requires merchant onboarding, credentials issued after enablement/QA, and webhook/status verification. This backend safely stores the merchant's API credentials but does not yet initiate or verify Nequi Push payments; saving credentials does not make a charge succeed. Addi and Wompi remain unavailable until official merchant authorization and verified callback integrations are implemented.

If the public `/health` endpoint reports `firebaseConfigured: false`, this is a platform-owner deployment issue, not a vendor payment credential. The Firebase project administrator must add that project's Firebase Admin service-account JSON as Render's `FIREBASE_SERVICE_ACCOUNT_JSON` secret and redeploy/restart the service. Never ask a vendor to provide this platform service account or place it in the app. The owner must separately configure `PROVIDER_TOKEN_ENCRYPTION_KEY` (base64 of 32 random bytes) in Render before the app can save merchant API credentials.

Employees must first create a Firebase Auth account before an owner can add their email and permissions. The app does not currently send employee invitations.
