# Secure payment setup

## Firebase

1. The app has no general vendor sign-in or app-wide device-lock screen. It reuses an existing Firebase session if present; otherwise, it creates a Firebase Anonymous session in the background to authenticate backend requests. Enable **Anonymous** in Firebase Authentication for new app installations. Anonymous business identity is tied to that app installation and can be lost after app data is cleared or the device is replaced. Do not make protected endpoints public to work around this limitation. The Finance bank/provider setup area has a separate optional local OS-auth gate (Face ID, fingerprint, or device PIN); it does not replace backend authorization.
2. Create the Firestore database in the same Firebase project and deploy the app's `firestore.rules`. Keep transaction, membership, and inventory writes server-only; the Render service uses Firebase Admin.
3. Add the Firebase Admin service-account JSON to Render as `FIREBASE_SERVICE_ACCOUNT_JSON`. Never put this credential in the Flutter app or commit it.
4. Build Flutter with the Firebase-generated platform configuration and the Render API URL:

   ```powershell
   flutter run --dart-define=BACKEND_BASE_URL=https://YOUR-RENDER-DOMAIN
   ```

5. Enable **Email/Password** in Firebase Authentication. The app continues to
   open directly into the POS with an anonymous device session, and the owner
   can link that session to a verified work email from **Cuenta y empresa**;
   linking preserves that installation's existing business identity. Staff
   invitations require the owner's email and each employee's email to be
   verified. Configure Firebase's email verification and password-reset
   templates and authorized domains before rollout. Each user should have an
   individual account; do not share a cashier or administrator password.
6. A verified owner creates a seven-day employee invitation in Finance and
   shares its one-time code through a trusted channel. The invited person signs
   in or secures their account, verifies the invited email, and accepts the code
   in **Cuenta y empresa**. Acceptance uses explicit role permissions. If the
   invitee has an empty temporary bootstrap workspace, the backend deactivates
   that workspace and attaches the user to the invited business. It refuses to
   merge an account that already has sales, an active subscription, or payment
   provider setup; use a separate work account in that case. Codes are hashed
   at rest, expire after seven days, and can only be accepted by the invited
   verified email.

The **Cuenta y empresa** screen records the business category and operating
model (independent store, chain supplier, in-store chain operation, inventory
partner, or contractor), plus an indicative number of locations. This is
onboarding context only; it does not create chain access or change Stripe
subscription pricing/entitlements. The inventory and chain-readiness data
remain device-local until server synchronization is implemented.

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

## Wompi merchant setup

Each vendor must first activate a Wompi merchant account and obtain the public key, private key, integrity secret, and event secret for the same environment from Wompi's merchant dashboard. The owner setup API accepts these values at `PUT /api/business/providers/wompi/credentials`; the public key is stored for checkout and the private key plus two secrets are encrypted on the backend with `PROVIDER_TOKEN_ENCRYPTION_KEY`. The private key is used only by the backend to query Wompi's authoritative transaction status after a signed event. Never collect Wompi account passwords or put merchant secrets in Flutter configuration, source control, or customer-facing screens. The app submits secrets only over HTTPS and does not display them again.

After setup, the backend returns a vendor-specific webhook URL. The vendor must register that exact URL in the corresponding Wompi test or production dashboard. Wompi sends transaction events there; the backend verifies the checksum using the event's supplied `signature.properties`, timestamp, and encrypted event secret, then queries Wompi's server API using the encrypted private key. It matches the API-verified reference, business, currency, and amount to the pending sale; only an API-verified `APPROVED` transaction changes a sale to paid. The checkout redirect is informational and never confirms payment.

The owner-authorized `POST /api/business/wompi/create-payment` endpoint creates a pending transaction and a Wompi Web Checkout URL. It requires an active POS subscription and the employee's charge permission. Test transactions require test credentials; do not switch a vendor to live payments until Wompi has approved its account and the live event URL has been configured. Configure `DOMAIN` as the public HTTPS origin so the returned event URL is valid. The Flutter app exposes owner-only setup, webhook URL registration instructions, a checkout/QR action for connected vendors, and a default payment option. Changing or disconnecting credentials is blocked while that vendor has Wompi payments pending, so those events can still be verified.

## Payment limitations

Stripe and Mercado Pago payments stay pending until their signed provider webhooks verify them. Mercado Pago displays a QR that encodes its hosted checkout URL; it is not a bank-generated QR, and payment is still pending until the Mercado Pago webhook confirms it. The Finance tab lets the owner choose a connected default method; that choice is saved on the business record and the matching checkout option is shown at charge time. Stripe Tap to Pay also needs a supported device, Stripe Terminal account configuration, and the provider's production approvals.

Bre-B is Banco de la República's interoperable instant-payment system, not a bank account that a merchant opens with Banco de la República. The vendor must activate/register a receiving key with a participating bank, wallet, or payment provider. Nequi Negocios and Bancolombia Negocios (Llaves) provide official merchant QR/key routes. The vendor obtains their permanent merchant QR directly from that provider, then may upload its original PNG/JPEG image in the Finance tab (maximum 600 KB); the server stores the image with that business's Firestore record. The app displays and can share that uploaded image without regenerating or modifying it. Only upload a permanent merchant display QR—not a temporary QR for a different sale. The app does not verify that the image is genuine, create per-sale bank QR codes, initiate a bank transfer, or receive automatic payment status for those fixed QR transfers. The vendor must verify each deposit in the provider's official app before manually confirming the pending transaction. Nequi API credentials issued to an approved merchant can be submitted in the owner-only Finance setup form; they are sent to Render over HTTPS, encrypted using `PROVIDER_TOKEN_ENCRYPTION_KEY`, stored outside the business profile, and never returned to the app. Do not enter bank passwords, PINs, or personal Nequi login credentials.

The bank selector records the institution that holds the vendor's receiving key; it does not sign in to that bank or create a bank connection. A customer may initiate a Bre-B transfer from a participating bank or wallet using the vendor's key. Each provider's participation, limits, fees, and QR behavior remain subject to that provider. The Finance setup controls are additionally gated by the device's Face ID, fingerprint, or screen PIN; this local OS check is a UI lock, not a replacement for Firebase authorization or a merchant API connection.

The Finance tab's guided setup assistant lists provider-specific portal links, steps, and availability. Owners can set the business display name used in the guide and launch the supported in-app setup for a bank receiving key, Mercado Pago OAuth, Stripe Connect onboarding, or Wompi checkout. Nequi Push remains onboarding-only. The owner-only `PUT /api/business/profile` endpoint updates the business display name.

Nequi Push is a separate assisted payment flow, not the static merchant QR. Nequi's official API requires merchant onboarding, credentials issued after enablement/QA, and webhook/status verification. This backend safely stores the merchant's API credentials but does not yet initiate or verify Nequi Push payments; saving credentials does not make a charge succeed. Addi remains unavailable until an authorized integration is implemented.

If the public `/health` endpoint reports `firebaseConfigured: false`, this is a platform-owner deployment issue, not a vendor payment credential. The Firebase project administrator must add that project's Firebase Admin service-account JSON as Render's `FIREBASE_SERVICE_ACCOUNT_JSON` secret and redeploy/restart the service. Never ask a vendor to provide this platform service account or place it in the app. The owner must separately configure `PROVIDER_TOKEN_ENCRYPTION_KEY` (base64 of 32 random bytes) in Render before the app can save merchant API credentials.

The legacy owner-only `POST /api/business/members` endpoint remains available
for verified existing accounts. New staff setup should use the invitation-code
flow so the employee can join from the app without an administrator manually
adding an already-registered UID.
