# Node.js / TypeScript SDK

> **v0.X breaking change — `appUuid: string` replaces the `app` slug.**
> Methods that used to take an app identifier (`app: "workahub"`, `appId: 2`,
> `appName: "..."`) now take an `appUuid: string` (UUID-formatted). Affected
> calls: `register`, `login`, `sendOtp`, `verifyOtp`,
> and the new `lookupOrganization`. The backend no longer
> accepts slug aliases — see [CHANGELOG.md](./CHANGELOG.md).
>
> **`sendMagicLink` signature change** — it is now `sendMagicLink(email, appUuid, opts?)`
> with `redirectTo` passed inside `opts`; the send/verify
> response shapes are now strongly typed (`access_token`, not `accessToken`).
> See the [Magic-link](#magic-link-passwordless-sign-in) section.

## Overview

The official Node.js SDK for ButtrBase. Fully typed, `fetch`-based client covering every API surface — auth, organizations, billing, RBAC, teams, credentials, search, AI gateway, webhooks, zero-trust, and more.

## Installation

```bash
npm install @buttrbase/sdk
```

## Quick Start

```typescript
import { ButtrbaseClient } from '@buttrbase/sdk';

// App-server auth uses OAuth2 client-credentials (the client_id / client_secret
// pair you create with `client.createCredential(...)`).
const client = new ButtrbaseClient({
  clientId: process.env.BUTTRBASE_CLIENT_ID!,
  clientSecret: process.env.BUTTRBASE_CLIENT_SECRET!,
});

// For public/frontend contexts, instantiate a secret-less client:
// const publicClient = ButtrbaseClient.newPublic(process.env.BUTTRBASE_CLIENT_ID!);

const APP_UUID = '018f1234-5678-7000-8000-000000000001';

// Login (app_uuid is required). The returned access_token becomes the bearer
// for subsequent authenticated calls.
const resp = await client.login('user@example.com', 'password', APP_UUID);
console.log(resp.access_token);

// Get profile
const profile = await client.getProfile();
```

> **App-server bearer tokens.** Construct the client with your
> `clientId` / `clientSecret` and authenticated calls just work — the SDK
> exchanges them for a bearer via the OAuth2 client-credentials grant
> (`POST /api/v1/auth/token`) on the first authenticated request, caches it,
> and refreshes it shortly before it expires. Call `authenticate()` explicitly
> to force a fresh token, or pass `accessToken` to the constructor to supply a
> bearer out-of-band (e.g. one obtained via `login` / `authStepUp`).

## Authentication

> **Guides**
> - [Multi-org onboarding](https://buttrbase.com/en/docs/multi-org-onboarding) — email → verify → (create org | sign in), with fast HS256 login + async RS256 upgrade.

### Register

```typescript
const APP_UUID = '018f1234-5678-7000-8000-000000000001';

const resp = await client.register('user@example.com', 'password', APP_UUID, {
  firstName: 'Jane', lastName: 'Doe'
});
```

### Login Options

```typescript
const options = await client.getLoginOptions('018f1234-5678-7000-8000-0000000000aa');
```

### Magic-link (passwordless sign-in)

Magic-link is the **only** browser sign-in flow that yields a JWKS-verifiable
**RS256** access token. The generic email-OTP endpoints issue **HS256** tokens
signed with Buttrbase's server secret, which the public JWKS cannot verify —
so any third-party app that needs to verify Buttrbase tokens itself (e.g. in
its own backend, against the published JWKS) must use magic-link.

It is a two-step flow:

1. **Send** — `sendMagicLink(email, appUuid, opts?)` posts to
   `POST /api/auth/magic-link/send` and emails the user a one-time link.
   Returns `{ sent, dev_token, expires_in_seconds }`. `dev_token` is the raw
   one-time token, returned only in non-prod dev-echo mode (handy for tests);
   it is `null` in production.
2. **Verify** — `verifyMagicLink(token)` posts to
   `POST /api/auth/magic-link/verify`, exchanging the one-time token (from the
   emailed link, or `dev_token`) for an RS256 `access_token`. Returns
   `{ access_token, token_type, user: { user_uuid, email }, redirect_to }`.

#### Cross-app federation & the redirect allowlist

Pass a `redirectTo` whose **origin** is registered on
the Buttrbase application — i.e. it appears in the application's WebAuthn
`rp_origins` or its configured redirect URL. When the origin is allowlisted,
the emailed link points at the app's **own** callback
(`{redirect_to}?token=...`), so the app verifies the RS256 token itself.

Non-allowlisted or non-absolute `redirectTo` targets are ignored and the link
falls back to the Buttrbase-hosted sign-in page. For the first-party flow,
omit `redirectTo` entirely.

```typescript
const APP_UUID = '018f1234-5678-7000-8000-000000000001';

// 1. Send the link. For cross-app federation, pass an allowlisted
//    redirectTo (its origin must be registered on the application).
const { sent, expires_in_seconds } = await client.sendMagicLink(
  'user@example.com',
  APP_UUID,
  { redirectTo: 'https://app.example.com/auth/callback' },
);

// 2. Verify the one-time token (from the emailed link's `?token=...`, or the
//    dev_token in non-prod) to get an RS256 access token.
const { access_token, token_type, user, redirect_to } =
  await client.verifyMagicLink('token-from-email');

console.log(access_token); // RS256 JWT — verifiable against the public JWKS
console.log(user.user_uuid, user.email);
```

### Token claims enrichment — roles and email (v0.5.0)

After obtaining a buttrbase RS256 access token you have two options: use the
built-in `Verifier` (recommended — cryptographic RS256 verification included),
or decode-only helpers if you already have a verified token from another library.

#### Option A — built-in `Verifier` (RS256 + JWKS, recommended)

`Verifier` fetches the org's JWKS, validates the RS256 signature, issuer, and
expiry, and returns a typed `AuthContext`. Construct once at startup and share
across requests (JWKS responses are cached internally by `jose`).

```typescript
import { Verifier } from '@buttrbase/client';

const verifier = new Verifier({
  jwksUrl: 'https://api.buttrbase.com/jwks.json',
  issuer: 'https://api.buttrbase.com',
  // audience: 'my-app', // optional — omit to skip aud validation (matches Rust SDK default)
});

// In an HTTP handler — strip "Bearer " and verify in one call:
const ctx = await verifier.verifyBearer(req.headers.authorization ?? '');

console.log(ctx.userId);  // sub claim (string UUID)
console.log(ctx.orgId);   // org claim (string UUID)
console.log(ctx.scopes);  // string[] — e.g. ["read:messages"]
console.log(ctx.roles);   // string[] split from data.roles — e.g. ["owner"]
console.log(ctx.email);   // string | undefined — from data.email

if (ctx.roles.includes('owner')) {
  // ...
}

// Or verify a raw token string and get the full Claims payload:
const claims = await verifier.verifyToken(accessToken);
console.log(claims.sub, claims.org, claims.data?.roles);
```

`audience` is optional (and defaults to `undefined` = not enforced). buttrbase
access tokens do not carry a stable per-application `aud` claim, so most
consumers should omit it — identity is established by the issuer + signature +
`org`/`sub` claims. Set `audience` only when you mint tokens with a known
audience. This matches the Rust SDK's `VerifierConfig { audience: None }`
default.

`Verifier` mirrors `Verifier` / `VerifierConfig` / `verify` / `verify_bearer`
from the Rust SDK (`src/verify/verifier.rs`).

> **Note:** `Verifier` now supports hybrid verification! By default, it performs local RS256 verification using the JWKS endpoint. However, if the token is an `HS256` token, it will automatically fallback to a network introspection request against the Buttrbase API to verify the token. You MUST set the `INTROSPECTION_API_KEY` environment variable to authenticate the introspection request.


#### Option B — decode-only helpers (no signature check)

Use these helpers when you have already verified the token signature with
another JWKS library and only need to parse the payload:

```typescript
import { decodeButtrbaseClaims, claimsToAuthContext, decodeJwtPayload } from '@buttrbase/client';

// One-shot: decode JWT payload (no signature check) and return AuthContext.
const ctx = decodeButtrbaseClaims(accessToken);

// Or: bring your own already-verified Claims object.
const rawClaims = yourJwksVerifier.verify(accessToken);
const ctx2 = claimsToAuthContext(rawClaims);
```

The `data.roles` field is a comma/space-delimited string on the wire
(`"owner"`, `"org_admin,leadership"`, `"admin member"`); all three helpers
split it into a `string[]`, matching the Rust SDK's `AuthContext::from(Claims)`
(added in Rust SDK 0.6.0).

**No signature verification is performed by the decode-only helpers.** Use
`Verifier` above, or `client.orgJwks(orgUuid)` to fetch the public JWKS for
use with another library.

### OTP (Passwordless Phone)

```typescript
const APP_UUID = '018f1234-5678-7000-8000-000000000001';

await client.sendOtp('+15551234567', APP_UUID);
const resp = await client.verifyOtp('+15551234567', '123456', APP_UUID);
```

### Passkey support (WebAuthn)

The SDK exposes the four WebAuthn ceremony endpoints as thin HTTP wrappers.
The challenge / credential blobs are pass-through `unknown` JSON — the
browser's `navigator.credentials.create` / `.get` APIs produce and consume
them directly, so no WebAuthn helper library is required.

```typescript
// Registration (requires an authenticated user — add a passkey to an existing
// account):
const { challenge, registration_state } = await client.passkeyRegisterBegin();
const credential = await navigator.credentials.create({ publicKey: (challenge as any).publicKey });
const result = await client.passkeyRegisterComplete({ registration_state, credential });
console.log(result.credential_id);

// Authentication (anonymous):
const { challenge: ac, auth_state } = await client.passkeyAuthenticateBegin();
const assertion = await navigator.credentials.get({ publicKey: (ac as any).publicKey });
const session = await client.passkeyAuthenticateComplete({ auth_state, credential: assertion });

// List the signed-in user's enrolled passkeys (descending by created_at):
const passkeys = await client.listMyPasskeys();
for (const p of passkeys) {
  console.log(p.nickname ?? p.credential_id_prefix, p.credential_uuid);
}

// Revoke one by its credential_uuid (owner check enforced server-side):
await client.deleteMyPasskey(passkeys[0].credential_uuid);
```

### Organization Lookup

```typescript
const APP_UUID = '018f1234-5678-7000-8000-000000000001';

const org = await client.lookupOrganization(APP_UUID, { domain: 'acme.com' });
// or by slug
const org2 = await client.lookupOrganization(APP_UUID, { slug: 'acme' });
```

### SSO (OIDC / SAML)

```typescript
const oidcUrl = await client.oidcAuthorizeUrl('connection-uuid');
const samlUrl = await client.samlAuthorizeUrl('connection-uuid');
```

### OAuth (Google / Microsoft / GitHub / Apple)

```typescript
const APP_UUID = '018f1234-5678-7000-8000-000000000001';

const url = client.oauthStartUrl('google', APP_UUID, 'https://app.example.com/auth/callback');
// Redirect the browser to `url`; the backend will 302 to Google.
```

## MFA / TOTP

```typescript
const status = await client.mfaStatus();
const enrollment = await client.mfaEnroll();
await client.mfaActivate('123456');
await client.mfaVerify('123456');
await client.mfaChallenge();
const codes = await client.mfaGenerateRecoveryCodes();
await client.mfaRedeemRecoveryCode('recovery-code');
await client.mfaDisable();
```

## Step-Up Auth

```typescript
const resp = await client.authStepUp('totp-code');
// the SDK's bearer access token is auto-replaced with the elevated token
```

## Organization Security

```typescript
const settings = await client.getSecuritySettings('org-uuid');
await client.updateSecuritySettings('org-uuid', { mfa_required: true });

const connections = await client.listSsoConnections('org-uuid');
await client.createSsoConnection('org-uuid', { provider: 'okta', name: 'Okta SSO' });

const events = await client.listAuditEvents('org-uuid');
```

## Sessions & Devices

```typescript
const sessions = await client.orgSessionInventory('org-uuid');
await client.orgRevokeAllSessions('org-uuid');

const accounts = await client.listDeviceAccounts('device-uuid');
await client.addDeviceAccount('device-uuid', { email: 'user@example.com' });
await client.switchDeviceActiveAccount('device-uuid', 'account-uuid');
```

### End-user device keys (self-service)

```typescript
// Authenticated end user; lists the caller's own active device keys.
const devices = await client.listDevices();
await client.revokeDevice(devices[0].device_uuid);
```

### Windowed scope re-mint (JIT)

```typescript
// Re-mint an access token windowed to a least-privilege scope subset.
const { token, scopes } = await client.scopeContext({
  requested_scopes: ['billing:read'],
});
```

## Tenant Home (discovery)

```typescript
// Public — no auth required. 404 if no active tenant home for this org/app.
const home = await client.getTenantHome('org-uuid', 42);
// { tenancy_mode, home_region, home_base_url }
```

## Client Credentials (app-server auth)

The single app-server credential is an OAuth2 `client_id` / `client_secret`
pair.

```typescript
// List existing credentials (no secrets returned)
const { data } = await client.listCredentials();

// Create — `client_secret` is shown ONCE. Save it now or rotate later.
const created = await client.createCredential('CI runner', 'GitHub Actions');
console.log('save these:', created.client_id, created.client_secret);

// Rotate the secret (invalidates the previous one)
const rotated = await client.rotateCredentialSecret(created.credentials_id);

// Delete
await client.deleteCredential(created.credentials_id);

// Construct a client with the pair — authenticated calls just work. The SDK
// runs the client-credentials grant lazily on the first authed request,
// caches the bearer, and refreshes it before it expires.
const appClient = new ButtrbaseClient({
  clientId: created.client_id,
  clientSecret: created.client_secret,
});
await appClient.getProfile(); // bearer fetched + attached automatically

// Or force a token exchange up front (e.g. to fail fast on bad credentials):
const { access_token, expires_in } = await appClient.authenticate();
```

## OAuth Provider Admin

```typescript
const APP_UUID = '018f1234-5678-7000-8000-000000000001';

// Register a provider
const config = await client.createOAuthConfig(APP_UUID, {
  provider: 'google',
  client_id: 'GOOGLE_CLIENT_ID',
  client_secret: 'GOOGLE_CLIENT_SECRET',
  redirect_uris: ['https://app.example.com/auth/callback'],
  scopes: ['openid', 'email', 'profile'],
  enabled: true,
});

// List (secrets are never returned)
const configs = await client.listOAuthConfigs(APP_UUID);

// Update — partial; client_secret only rotates when present
await client.updateOAuthConfig(APP_UUID, 'google', {
  scopes: ['openid', 'email', 'profile', 'offline_access'],
});

// Delete
await client.deleteOAuthConfig(APP_UUID, 'google');
```

## App-level Audit Log

```typescript
const APP_UUID = '018f1234-5678-7000-8000-000000000001';

const rows = await client.readAuditLog(APP_UUID, {
  limit: 100,
  action_prefix: 'oauth.',
});
```

## Entitlements

```typescript
const check = await client.entitlementsCheck('advanced-analytics', 'org-uuid');
const batch = await client.entitlementsCheckBatch([{ feature: 'sso' }]);
const effective = await client.entitlementsEffective();
```

## Pricing

```typescript
const preview = await client.pricingPreview({ plan: 'pro' });
const quote = await client.pricingQuote({ plan: 'pro', seats: 10 });
const session = await client.pricingCheckoutSession({ plan: 'pro' });
```

## Coupons & Gift Cards

```typescript
// Admin
const coupons = await client.adminListProductCoupons('product-id');
await client.adminCreateProductCoupon('product-id', { code: 'SAVE20', discount_type: 'percent' });

// Public
const result = await client.validateCoupon('SAVE20');
const gc = await client.validateGiftCard('GC-123');
```

## Organization Invitations

Generate and consume secure `gv_tkn_` prefixed invitation tokens to securely onboard users with strict role bindings.

```typescript
// 1. Generate an invitation (Admin only)
const invite = await client.createInvitation('org-uuid', {
  email: 'new.hire@example.com',
  role: 'member',
  teams: ['engineering']
});
console.log(invite.token); // e.g. "gv_tkn_8a9b2c3d..."

// 2. Preview the invitation (Unauthenticated, safe for public UI)
const preview = await client.getInvitationPreview('gv_tkn_8a9b2c3d...');
console.log(preview.org_name, preview.role);

// 3. Accept the invitation (Requires authenticated user)
await client.acceptInvitation('gv_tkn_8a9b2c3d...');
```

## Teams

```typescript
const team = await client.createTeam({ name: 'Engineering', org_uuid: '...' });
const teams = await client.listOrgTeams('org-uuid');
const members = await client.listTeamMembers('team-uuid');
await client.addTeamMember('team-uuid', 'user-uuid');
await client.removeTeamMember('team-uuid', 'user-uuid');

const observers = await client.listTeamObservers('team-uuid');
await client.addTeamObserver('team-uuid', 'user-uuid');
```

## Admin: Signing Keys

```typescript
const keys = await client.listSigningKeys('org-uuid');
await client.rotateSigningKeys('org-uuid');
const audit = await client.listSigningAudit('org-uuid');
```

## Admin: mTLS CA

```typescript
const ca = await client.getCa('org-uuid');
await client.initCa('org-uuid', { common_name: 'My CA' });
const certs = await client.listCertificates('org-uuid');
const cert = await client.issueCertificate('org-uuid', '...');
await client.revokeCertificate('org-uuid', 'serial');
```

## Admin: Secrets Vault

```typescript
const secrets = await client.listSecrets('org-uuid');
await client.putSecret('org-uuid', 'DB_URL', 'postgres://...');
const secret = await client.getSecret('org-uuid', 'DB_URL');
await client.deleteSecret('org-uuid', 'DB_URL');
```

## Admin: Domains & Webhooks

```typescript
const domains = await client.listDomains('org-uuid');
const domain = await client.createDomain('org-uuid', 'example.com');
await client.verifyDomain('org-uuid', '1');

const endpoints = await client.listWebhookEndpoints('org-uuid');
await client.createWebhookEndpoint('org-uuid', 'https://hook.example.com', ['user.created']);
```

## Payments

```typescript
const session = await client.createPaymentCheckout(5000, 'usd', 'US');
const invoice = await client.sendInvoice(5000, 'usd', '018f1234-5678-7000-8000-000000000001');
```

## AI Gateway

```typescript
const resp = await client.aiChatCompletions('org-uuid', 'openai', {
  model: 'gpt-4',
  messages: [{ role: 'user', content: 'Hello!' }]
});
```

## SMS & Email

```typescript
await client.sendSms('+15551234567', 'Hello from ButtrBase!');
await client.verifyEmailIdentity('user@example.com', 'AKIA...', 'secret', 'us-east-1');
```

## Errors

Non-2xx responses throw `ButtrbaseError` with `statusCode`, `detail`, and the parsed `payload`.

## Docs

See https://buttrbase.com/docs for the full API reference.

## Tutorials

The [ButtrBase tutorial series](https://buttrbase.com/docs/tutorials) walks through a complete app integration in six parts: provisioning, OAuth, issuing API keys from a backend, browser→desktop session handoff, passwordless sign-in, and passkeys.

### Deployment & Federation

A Node/Express service verifies ButtrBase RS256 tokens via the SDK's `verify` path the same way regardless of where the backend is deployed — these targets are where your token issuer runs.

- [Deploy with Helm](https://buttrbase.com/docs/deployment/deploy-with-helm) — the runnable substrate every other deploy path wraps
- [GCP Marketplace](https://buttrbase.com/docs/deployment/gcp-marketplace)
- [AWS Marketplace](https://buttrbase.com/docs/deployment/aws-marketplace)
- [Azure Marketplace](https://buttrbase.com/docs/deployment/azure-marketplace)
- [OpenShift](https://buttrbase.com/docs/deployment/openshift-operator)
- [DigitalOcean](https://buttrbase.com/docs/deployment/digitalocean-1click)
- [Terraform Module](https://buttrbase.com/docs/deployment/terraform-module)
- [Self-Host On-Prem](https://buttrbase.com/docs/deployment/self-host-on-prem)
- [Set Up Federation](https://buttrbase.com/docs/deployment/set-up-federation) — register in the directory, exchange trust, open cross-org shared channels

## Recipes

### Complete Onboarding

```typescript
import { ButtrbaseClient } from '@buttrbase/sdk';

const client = new ButtrbaseClient({
  clientId: process.env.BUTTRBASE_CLIENT_ID!,
  clientSecret: process.env.BUTTRBASE_CLIENT_SECRET!,
});
const APP_UUID = '018f1234-5678-7000-8000-000000000001';

// 1. Register and login
await client.register('admin@acme.com', 's3cur3!', APP_UUID, { firstName: 'Alice' });
const login = await client.login('admin@acme.com', 's3cur3!', APP_UUID);

// 2. Get profile
const profile = await client.getProfile();

// 3. Create a team and add a member
const orgUuid = (profile.org as { uuid: string }).uuid;
const team = await client.createTeam({ name: 'Engineering', org_uuid: orgUuid });
await client.addTeamMember((team as { uuid: string }).uuid, 'colleague-user-uuid');
```

### OAuth Start URL

```typescript
const APP_UUID = '018f1234-5678-7000-8000-000000000001';

// Build the URL; do NOT fetch it from this SDK — the backend 302s to the
// upstream IdP and your client must follow that in a browser context.
const url = client.oauthStartUrl(
  'google',
  APP_UUID,
  'https://app.example.com/auth/callback',
);
// Redirect the user's browser to `url`.
```

### Create a Client Credential (client_secret shown once)

```typescript
const created = await client.createCredential('GitHub Actions');

// WARNING: created.client_secret is shown ONCE. Save it to your secret store now.
process.env.BUTTRBASE_CLIENT_ID = created.client_id;
process.env.BUTTRBASE_CLIENT_SECRET = created.client_secret;
```

### Register an OAuth Provider

```typescript
const APP_UUID = '018f1234-5678-7000-8000-000000000001';

await client.createOAuthConfig(APP_UUID, {
  provider: 'google',
  client_id: process.env.GOOGLE_CLIENT_ID!,
  client_secret: process.env.GOOGLE_CLIENT_SECRET!,
  redirect_uris: ['https://app.example.com/auth/callback'],
  scopes: ['openid', 'email', 'profile'],
  enabled: true,
});
```

### Read the Audit Log

```typescript
const APP_UUID = '018f1234-5678-7000-8000-000000000001';

const rows = await client.readAuditLog(APP_UUID, {
  limit: 50,
  action_prefix: 'oauth.', // e.g. oauth.config.created, oauth.config.updated
});
for (const row of rows) {
  console.log(`${row.created_at} ${row.action} by ${row.actor_user_uuid ?? '<system>'}`);
}
```

### MFA Enrollment

```typescript
// 1. Check MFA status
const status = await client.mfaStatus();

// 2. Enroll in TOTP — returns secret + QR URL
const enrollment = await client.mfaEnroll();
console.log(`Scan this QR: ${enrollment.qr_code}`);

// 3. Activate with code from authenticator app
await client.mfaActivate('123456');

// 4. Generate recovery codes
const codes = await client.mfaGenerateRecoveryCodes();
console.log('Save these recovery codes:', codes);
```

### Checkout Flow

```typescript
// 1. Preview pricing
const preview = await client.pricingPreview({ plan: 'pro', seats: 10 });

// 2. Check entitlement
const check = await client.entitlementsCheck('advanced-analytics', 'org-uuid');

// 3. Create checkout session
const session = await client.pricingCheckoutSession({ plan: 'pro', seats: 10 });
console.log(`Redirect to: ${session.url}`);
```

### SSO Setup

```typescript
// 1. Create an OIDC connection
const conn = await client.createSsoConnection('org-uuid', 'okta', 'Okta SSO', {
  domain: 'myorg.okta.com',
  client_id: '...',
  client_secret: '...',
});

// 2. Get the authorize URL
const url = await client.oidcAuthorizeUrl((conn as { connection_uuid: string }).connection_uuid);
```

### Secrets & Key Management

```typescript
// 1. Store a secret
await client.putSecret('org-uuid', 'DATABASE_URL', 'postgres://...');

// 2. List and retrieve secrets
const secrets = await client.listSecrets('org-uuid');
const secret = await client.getSecret('org-uuid', 'DATABASE_URL');

// 3. Rotate signing keys
await client.rotateSigningKeys('org-uuid');
const audit = await client.listSigningAudit('org-uuid');
```

## Rust SDK parity methods (0.6.0)

The following methods were added to bring the Node SDK to feature parity with
`buttrbase-sdk-rust`. All are strictly additive — no existing method was changed.

### Auth — email OTP (v1 uuid-based)

```typescript
const APP_UUID = '018f1234-5678-7000-8000-000000000001';

// Step 1 — send OTP email
await client.sendOtpV1('alice@example.com', APP_UUID);

// Step 2 — verify OTP; returns TokenPair with signup_token
const { token: signupToken } = await client.verifyOtpV1('alice@example.com', '123456', APP_UUID);

// Step 3 — finalize registration (existing method, unchanged)
const result = await client.finalizeRegistration({
  email: 'alice@example.com',
  password: 's3cur3!',
  app_uuid: APP_UUID,
  signup_token: signupToken,
  org_choice: { type: 'create', name: 'Acme Inc' },
});
```

> These are the canonical v1 email-OTP methods. The pre-existing `sendOtp` /
> `verifyOtp` (phone-based) and `sendOtpEmail` / `verifyOtpEmail` (also email,
> same endpoint) are retained unchanged.

### Auth — token refresh

```typescript
// Refresh a short-lived access token using the refresh token
const { token: newAccessToken } = await client.refreshToken(tokenPair.refresh_token!);
```

### Entitlements (canonical shapes)

```typescript
// Single check — body uses feature_key (canonical)
const { granted } = await client.checkEntitlement('advanced_analytics');

// Batch check — body uses feature_keys: string[]
const results = await client.checkEntitlements(['advanced_analytics', 'export_data']);
// results: { advanced_analytics: { granted: true }, export_data: { granted: false, reason: 'plan_limit' } }

// Effective entitlements (typed)
const all = await client.effectiveEntitlements();
// all: EffectiveEntitlement[] — [{ feature_key, granted, reason }]
```

> The pre-existing `entitlementsCheck(feature, orgUuid?)` and
> `entitlementsCheckBatch(checks)` use different body field names; they are
> retained unchanged alongside the canonical variants.

### Pricing (typed)

```typescript
// Preview — accepts typed PricingPreviewRequest
const preview = await client.pricingPreviewTyped({ price_id: 42, country: 'US' });
// preview: { amount_cents, currency, discount_cents, tax_cents, final_cents, region_resolved }

// Lock a quote (10-min TTL)
const quote = await client.pricingQuoteTyped({ price_id: 42 });

// Create checkout session
const session = await client.checkoutSessionTyped({ price_id: 42, quote_id: 'q-abc' });
// session: { payment_url, session_id, provider }
```

### Wallet

```typescript
// Balance summary (typed WalletSummary)
const wallet = await client.walletSummary();
// { balance_cents, budget_limit_cents, budget_period }

// Paginated transactions
const txs = await client.walletTransactions(20, 0);
// txs: WalletTransaction[] — [{ id, kind, amount_cents, description, created_at }]
```

### Subscriptions

```typescript
// List subscriptions
const subs = await client.listSubscriptions();
// subs: SubscriptionItem[]

// Create a subscription
const sub = await client.createSubscription({ price_id: 20 });

// Cancel
await client.cancelSubscription(sub.id);
```

### Billing history (typed)

```typescript
const invoices = await client.billingHistory();
// invoices: Invoice[]
```

### Usage reporting (typed)

```typescript
await client.reportUsage({
  metric: 'api_calls',
  quantity: 1,
  org_uuid: 'org-uuid',
});
```

### Analytics (canonical names + period param)

```typescript
// Ingest event (typed AnalyticsEvent)
await client.ingestEvent({ event_type: 'page_view', properties: { page: '/home' } });

// App overview — now with required period param
const appOverview = await client.appAnalyticsOverview('app-uuid', '30d');

// Org overview — now with required period param
const orgOverview = await client.orgAnalyticsOverview('org-uuid', '7d');
```

### Teams (typed)

```typescript
const teams = await client.orgTeams('org-uuid');  // TeamItem[]
const myTeams = await client.userTeams('user-uuid');  // TeamItem[]
```

### App management

```typescript
// Apps the caller belongs to
const apps = await client.myApps();  // AppEntry[]

// Orgs within an app
const orgs = await client.appOrgs('app-uuid');  // OrgEntry[]

// Credentials (admin only)
const creds = await client.appCredentials('app-uuid');  // AppCredentialsResponse

// Enable sandbox
await client.enableSandbox('app-uuid');

// Rotate credentials
const newCreds = await client.rotateCredentials('app-uuid', 'live');
```

## Releasing (maintainers)

Tagged pushes (`v*`) trigger `.github/workflows/release.yml`, which runs `npm publish --access public`.
