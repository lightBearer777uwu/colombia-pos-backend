# Secure payment setup

## Combined app and backend repository

The Flutter app is in the repository root and the backend is in `backend/`.
When deploying this backend from the combined GitHub repository, configure
Render's root directory as `backend`, with `npm install` as the build command
and `npm start` as the start command. Keep backend environment variables and
credentials in the Render service, never in the app or repository. Existing
deployments connected to the standalone backend repository may continue using
that repository.

## Firebase

1. The app has no general vendor sign-in or app-wide device-lock screen. It reuses an existing Firebase session if present; otherwise, it creates a Firebase Anonymous session in the background to authenticate backend requests. Enable **Anonymous** in Firebase Authentication for new app installations. Anonymous business identity is tied to that app installation and can be lost after app data is cleared or the device is replaced. Do not make protected endpoints public to work around this limitation. The Finance bank/provider setup area has a separate optional local OS-auth gate (Face ID, fingerprint, or device PIN); it does not replace backend authorization.
2. Create the Firestore database in the same Firebase project and deploy the app's `firestore.rules`. Transaction and membership writes remain server-only. Inventory uses local SQLite as its source of truth and an authenticated, business-scoped Firestore mirror; the rules restrict mirror writes to authorized managers.
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
partner, or contractor), plus an indicative number of locations. Choosing a
subscription plan controls the Stripe price; the profile's location count does
not change it. Plan feature and staff/location limits are not yet enforced as
application entitlements, so confirm those features are implemented before
advertising or selling a plan.

## Render environment

Configure the following values in the backend Render service. Use secrets for credentials and keep `DOMAIN` set to the public HTTPS origin without a trailing slash.

- `FIREBASE_SERVICE_ACCOUNT_JSON`
- `DOMAIN`
- `STRIPE_SECRET_KEY` and `STRIPE_WEBHOOK_SECRET`
- `PROVIDER_TOKEN_ENCRYPTION_KEY`: base64 encoding of exactly 32 random bytes
- `OAUTH_STATE_SECRET`: a random secret of at least 32 characters
- `MERCADO_PAGO_CLIENT_ID`, `MERCADO_PAGO_CLIENT_SECRET`, `MERCADO_PAGO_REDIRECT_URI`, and `MERCADO_PAGO_WEBHOOK_SECRET`
- `PUBLIC_APP_URL` (public Flutter web origin) and `WEB_APP_ORIGINS` (comma-separated browser origins)
- `TWILIO_ACCOUNT_SID` and `TWILIO_AUTH_TOKEN`
- `TWILIO_WHATSAPP_CONTENT_SID` (approved one-variable WhatsApp utility template, required for business-initiated/out-of-window messages)
- `SENDGRID_API_KEY`, `SENDGRID_FROM_EMAIL`, `SENDGRID_INBOUND_DOMAIN`, and `SENDGRID_INBOUND_WEBHOOK_SECRET`
- `PRIVATE_AI_ENABLED` (keep `false` until your own HTTPS model is ready), `PRIVATE_AI_URL`, and `PRIVATE_AI_API_KEY`
- `REMINDER_JOB_SECRET` (a random secret of at least 32 characters, shared only with the scheduled worker)

The app presents these monthly plan choices, with the displayed amount taken
from the corresponding Stripe Price (the label in Flutter is informational):

- `STRIPE_PRICE_BARRIO` — Tienda de Barrio, COP 29,900/month
- `STRIPE_PRICE_RESTAURANT` — Restaurante / Café, COP 54,900/month
- `STRIPE_PRICE_PHARMACY` — Farmacia / Droguería, COP 54,900/month
- `STRIPE_PRICE_STATION` — Estación de Servicio, COP 94,900/month
- `STRIPE_PRICE_CHAIN` — Cadena de Locales, COP 184,900/month

Create each recurring Stripe Price in COP with the matching amount before
setting its environment variable. The webhook stores the selected plan ID on
the business subscription after checkout. Do not set `STRIPE_PRICE_POS_MONTHLY`
unless the legacy `planId: "legacy"` flow is intentionally still offered.
Before creating checkout, the backend retrieves each selected Stripe Price and
rejects it unless it is active, recurring monthly, COP-denominated, and matches
the advertised amount above.

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

Authenticated business members can call `GET /api/business/payment-readiness`. Its exact response shape is `{ "providers": { "<providerId>": { "ready": false, "status": "<status>", "reason": "<human-readable reason>" } } }`, with entries for `mercado_pago`, `wompi`, `stripe`, `nequi`, and `bank_transfer`. This backend reports all five as not ready unless it can verify readiness; currently merchant approval/production readiness is not provable for these providers. In particular, OAuth or stored credentials alone do not enable payments, Stripe account flags do not establish Stripe Connect support for Colombian connected accounts, and a stored Bre-B receiving key does not verify a deposit. The endpoint is informational and does not enable or disable checkout routes.
Authenticated business members can call `GET /api/business/payment-readiness`.
Its response contains `providers` entries for `mercado_pago`, `wompi`, `stripe`,
`nequi`, and `bank_transfer`, each with `ready`, `status`, and `reason`.
Currently all five remain not ready because merchant production approval is
not verified. In particular, OAuth or stored credentials alone do not enable
payments, Stripe account flags do not establish Stripe Connect support for
Colombian connected accounts, and a stored Bre-B receiving key does not verify
a deposit. The backend also checks readiness directly on each digital
checkout/terminal endpoint; a client cannot bypass the payment block by calling
an endpoint directly. Cash sales are unaffected. Do not enable a provider
until its readiness check is backed by the provider's authoritative approval
and payment capability.

Stripe and Mercado Pago payments stay pending until their signed provider webhooks verify them. The Mercado Pago webhook also matches the server-fetched payment amount and currency against the stored order; mismatches are marked `review` with `reviewReason: "mercado_pago_amount_or_currency_mismatch"` and are not marked paid. Mercado Pago displays a QR that encodes its hosted checkout URL; it is not a bank-generated QR, and payment is still pending until the Mercado Pago webhook confirms it. The Finance tab lets the owner choose a connected default method; that choice is saved on the business record and the matching checkout option is shown at charge time. Stripe Tap to Pay also needs a supported device, Stripe Terminal account configuration, and the provider's production approvals.

Bre-B is Banco de la República's interoperable instant-payment system, not a bank account that a merchant opens with Banco de la República. The vendor must activate/register a receiving key with a participating bank, wallet, or payment provider. Nequi Negocios and Bancolombia Negocios (Llaves) provide official merchant QR/key routes. The vendor obtains their permanent merchant QR directly from that provider, then may upload its original PNG/JPEG image in the Finance tab (maximum 600 KB); the server stores the image with that business's Firestore record. The app displays and can share that uploaded image without regenerating or modifying it. Only upload a permanent merchant display QR—not a temporary QR for a different sale. The app does not verify that the image is genuine, create per-sale bank QR codes, initiate a bank transfer, or receive automatic payment status for those fixed QR transfers. The vendor must verify each deposit in the provider's official app before manually confirming the pending transaction. Nequi API credentials issued to an approved merchant can be submitted in the owner-only Finance setup form; they are sent to Render over HTTPS, encrypted using `PROVIDER_TOKEN_ENCRYPTION_KEY`, stored outside the business profile, and never returned to the app. Do not enter bank passwords, PINs, or personal Nequi login credentials.

The bank selector records the institution that holds the vendor's receiving key; it does not sign in to that bank or create a bank connection. A customer may initiate a Bre-B transfer from a participating bank or wallet using the vendor's key. Each provider's participation, limits, fees, and QR behavior remain subject to that provider. The Finance setup controls are additionally gated by the device's Face ID, fingerprint, or screen PIN; this local OS check is a UI lock, not a replacement for Firebase authorization or a merchant API connection.

The Finance tab's guided setup assistant lists provider-specific portal links, steps, and availability. Owners can set the business display name used in the guide and launch the supported in-app setup for a bank receiving key, Mercado Pago OAuth, Stripe Connect onboarding, or Wompi checkout. Nequi Push remains onboarding-only. The owner-only `PUT /api/business/profile` endpoint updates the business display name.

Nequi Push is a separate assisted payment flow, not the static merchant QR. Nequi's official API requires merchant onboarding, credentials issued after enablement/QA, and webhook/status verification. This backend safely stores the merchant's API credentials but does not yet initiate or verify Nequi Push payments; saving credentials does not make a charge succeed. Addi remains unavailable until an authorized integration is implemented.

If the public `/health` endpoint reports `firebaseConfigured: false`, this is a platform-owner deployment issue, not a vendor payment credential. The Firebase project administrator must add that project's Firebase Admin service-account JSON as Render's `FIREBASE_SERVICE_ACCOUNT_JSON` secret and redeploy/restart the service. Never ask a vendor to provide this platform service account or place it in the app. The owner must separately configure `PROVIDER_TOKEN_ENCRYPTION_KEY` (base64 of 32 random bytes) in Render before the app can save merchant API credentials.

The legacy owner-only `POST /api/business/members` endpoint remains available
for verified existing accounts. New staff setup should use the invitation-code
flow so the employee can join from the app without an administrator manually
adding an already-registered UID.

## Paid-access enforcement (leave off during development)

The single global paid-access launch switch is intentionally off during
development. It is not a vendor opt-in: after the owner enables it for launch,
every vendor must have an active or trialing subscription to use paid POS
features, with no vendor-facing bypass.

Enforcement remains disabled unless the Firebase Admin-controlled
Firestore document `platformSettings/accessControl` exists with the boolean
field `paidAccessEnforcementEnabled` set to `true`. A missing document, a
missing field, or any value other than boolean `true` keeps the backend checks
off. **Do not create or enable this setting until the POS SaaS is ready for
vendors.** The app's Firebase client is explicitly denied access to this
control document; change it only through a trusted Firebase/administrative
channel.

When enabled, the server allows paid POS operations only when the business
subscription status is `active` or `trialing`. It protects sales and payment
creation, transaction history and transfer confirmation, provider setup, team
operations, and the Firestore inventory mirror. Member revocation remains
available for account security. Unpaid requests receive HTTP 402 with code
`subscription_required`. Business bootstrap/profile, business and subscription
status, payment readiness, and subscription checkout remain available so
vendors can register and purchase access. Subscription state continues to be
updated by verified Stripe webhooks; a checkout redirect is not proof of
payment. Firestore rules also prevent clients from creating or changing
server-managed subscription and payment-provider fields.

At launch, deploy the backend and Firestore rules, then set the exact boolean
field above to `true` in the production Firebase project. To turn enforcement
back off, set it to `false` or remove the control document. Test the switch in
a staging Firebase project first. This toggle does not enforce per-plan staff,
location, or feature limits; those require separate entitlement rules.

## Customer contacts and appointments

The app's **Clientes** area stores business-scoped customer contacts only
after a vendor records the customer's explicit choice of service-related
message channels. Marketing permission is separate and unchecked by default.
The vendor can revoke a channel, service-message consent, marketing consent,
or optional private-AI consent.
Direct Firestore client access to customer and appointment records is denied;
the authenticated backend checks business membership and the paid-access
launch switch.

Business owners configure their timezone, weekly hours, appointment services,
durations, and whether a booking needs vendor approval or may be confirmed
automatically. Appointments reserve 15-minute slots in a Firestore transaction
so simultaneous requests cannot double-book the same business. Auto-confirm
uses only vendor-configured hours and enabled services. To publish a customer
booking page, enable online bookings, set a unique 3-50 character lowercase
slug, and enable the public booking page in **Clientes**. Configure
`PUBLIC_APP_URL` to the Flutter web deployment and `WEB_APP_ORIGINS` to its
HTTPS origin. The public page is `/book/<slug>`; hosting must serve the Flutter
single-page app for that path. Public endpoints are:

- `GET /api/public/businesses/:slug` — public business name and enabled services
- `GET /api/public/businesses/:slug/availability?serviceId=...&date=YYYY-MM-DD`
- `POST /api/public/businesses/:slug/book` — validates opt-in, rechecks business
  settings and uses a Firestore transaction to reserve the selected slots

The public API rate-limits requests per client IP and includes a booking
honeypot. The limiter is in-memory; use a shared rate-limit store before
running multiple backend instances or exposing the endpoint to high traffic.
When the paid-access launch switch is on, public availability and booking are
also restricted to businesses with an active or trialing POS subscription.

### Twilio and SendGrid setup

Store Twilio and SendGrid credentials only in the backend environment, never
in Flutter or Firestore client-readable documents. Each vendor must enter its
unique Twilio SMS sender number and WhatsApp Business sender number in
**Clientes → Preferencias**. These must be E.164 numbers provisioned in the
configured Twilio account. Set the Twilio inbound messaging webhook to
`https://<DOMAIN>/webhook/twilio/inbound` using POST; the backend validates
`X-Twilio-Signature`, maps the receiving number to exactly one business, and
accepts inbound text only from a customer with active channel consent. A
customer's STOP/UNSUBSCRIBE keyword revokes that channel.
For WhatsApp business-initiated messages, create and approve a Twilio Content
template with one body variable and set its Content SID in
`TWILIO_WHATSAPP_CONTENT_SID`; messages use the template variable `1`. Without
it, Twilio can reject free-form messages outside an active customer-initiated
conversation window.

Verify the SendGrid sender domain and configure Inbound Parse for
`SENDGRID_INBOUND_DOMAIN`, including its required MX record. Set the parser's
POST URL to
`https://<DOMAIN>/webhook/sendgrid/inbound/<SENDGRID_INBOUND_WEBHOOK_SECRET>`.
Use a unique random secret of at least 32 characters. Replies use opaque
per-conversation `reply+<token>@<domain>` addresses and are accepted only from
the opted-in customer's email. Messages are stored in the business-scoped
inbox. Outbound messages are sent only to channels the customer opted into for
service-related contact; marketing consent is separate and is not used for
bulk campaigns. Failed provider sends are surfaced in the API and inbox.

The Flutter inbox supports business replies, inbound customer messages, and
reviewable AI drafts. Provider delivery is unavailable until the provider
accounts, sender numbers, verified domains, and webhook URLs above are
configured. Twilio/SendGrid credentials are shared service credentials; do
not promise message delivery until their account approval and webhook tests
are complete.

### Private AI safeguards

Keep `PRIVATE_AI_ENABLED` unset or `false` until the private model's HTTPS API
is ready. The connector sends only the recent conversation text, channel, and
business name to `PRIVATE_AI_URL`; it excludes customer phone and email. The
customer must separately opt in to AI-assisted drafting, and the business
owner must enable drafts in **Clientes → Preferencias**. Replies are saved as
drafts for a vendor to review and send; the model cannot send messages or take
actions. The endpoint must accept a JSON request with `task`,
`businessName`, `channel`, and `messages`, and return JSON with a `reply`
string. Do not point this setting at a third-party model. Inventory and live
stock/pricing lookups are not part of this initial AI connector.

### Appointment reminders

Vendors may save private in-app reminders in **Agenda**. These stay attached to
the business and appear in the calendar when a vendor opens the app; the app
does not yet deliver operating-system push notifications while closed.

Optional customer appointment reminders can be enabled in
**Clientes → Preferencias** (30 minutes, 2 hours, or 24 hours before the
appointment). They are queued only for confirmed appointments, and delivery
rechecks the appointment status, the business preference, the customer's
current service-message consent, and their selected channels. Failed provider
deliveries retry up to three times. Configure a Render Cron Job using the same
source repository as the backend web service, command `npm run reminders`, and
a five-minute schedule. For the combined app repository, set the cron job's
root directory to `backend`; for the standalone backend repository, use the
repository root. Set its `REMINDER_JOB_URL` to
`https://<DOMAIN>/api/internal/appointment-reminders` and set
`REMINDER_JOB_SECRET` to the same secret used by the backend web service. The
worker exits unsuccessfully if the endpoint rejects the request. Scheduled
provider delivery is unavailable until both services are deployed and the
Twilio/SendGrid configuration above is complete.
