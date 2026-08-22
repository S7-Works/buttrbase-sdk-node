# Changelog

## Unreleased — Rust SDK parity (0.6.0)

### Added (strictly additive, no breaking changes)

All methods below mirror the identically-named method in the Rust SDK (`buttrbase-sdk-rust`).
Every new method has a unit test asserting the correct URL, HTTP verb, request body, and
parsed response shape.

#### Verifier — Hybrid Verification

- **`verifyToken` / `verifyBearer`** now support a hybrid verification fallback. If an `HS256` token is encountered, the SDK decodes the header and makes a network introspection call to `/api/auth/introspect`. Set the `INTROSPECTION_API_KEY` environment variable to authenticate the introspection request. RS256 tokens proceed with existing local verification.

#### Auth — email OTP (v1, uuid-based)


- **`sendOtpV1(email, appUuid)`** — `POST /api/v1/auth/otp/send` (no auth).
  Canonical form of the v1 email-OTP send endpoint, mirroring Rust `send_otp(email, app_uuid)`.
  The pre-existing `sendOtpEmail` (which calls the same endpoint) is retained unchanged.
- **`verifyOtpV1(email, otp, appUuid) → TokenPair`** — `POST /api/v1/auth/otp/verify` (no auth).
  Canonical form mirroring Rust `verify_otp(email, otp, app_uuid)`.
  The pre-existing `verifyOtpEmail` is retained unchanged.

  > **Divergence note:** `sendOtp` / `verifyOtp` (existing methods, phone-based,
  > `/api/auth/otp`) are NOT repointed. The v1 email-OTP endpoint is exposed as the
  > new `*V1` variants alongside the existing phone variants to preserve backward
  > compatibility.

#### Auth — token refresh

- **`refreshToken(refreshToken) → AccessToken`** — `POST /api/app/auth/refresh` (no auth).
  Request body: `{ refresh: refreshToken }`. Mirrors Rust `refresh_token(refresh_token)`.

#### Entitlements — canonical shapes

- **`checkEntitlement(featureKey) → EntitlementResult`** — `POST /api/entitlements/check`.
  Body: `{ feature_key }` (not `feature`). Returns typed `{ granted, reason }`.
  Mirrors Rust `check_entitlement(bearer, feature_key)`.
  > Pre-existing `entitlementsCheck(feature, orgUuid?)` retained; it uses `feature` in the body
  > (not `feature_key`) — this divergence is preserved, not silently fixed.
- **`checkEntitlements(featureKeys) → Record<string, EntitlementResult>`** —
  `POST /api/entitlements/check/batch`. Body: `{ feature_keys: string[] }`.
  Mirrors Rust `check_entitlements(bearer, feature_keys)`.
  > Pre-existing `entitlementsCheckBatch(checks)` retained; body shape differs (`checks`).
- **`effectiveEntitlements() → EffectiveEntitlement[]`** — `GET /api/entitlements/effective`.
  Typed result. Mirrors Rust `effective_entitlements(bearer)`.

#### Pricing — typed request/response shapes

- **`pricingPreviewTyped(req: PricingPreviewRequest) → PricingPreview`** — `POST /api/pricing/preview`.
  Mirrors Rust `pricing_preview(bearer, req)`. Pre-existing `pricingPreview(payload: Record)` retained.
- **`pricingQuoteTyped(req: PricingPreviewRequest) → unknown`** — `POST /api/pricing/quote`.
  Mirrors Rust `pricing_quote(bearer, req)`. Pre-existing `pricingQuote(payload)` retained.
- **`checkoutSessionTyped(req: CheckoutSessionRequest) → CheckoutSession`** — `POST /api/pricing/checkout-session`.
  Mirrors Rust `checkout_session(bearer, req)`. Pre-existing `pricingCheckoutSession(payload)` retained.

#### Wallet

- **`walletSummary() → WalletSummary`** — `GET /api/wallet`.
  Typed variant; pre-existing `getWallet()` (untyped) retained.
- **`walletTransactions(limit?, offset?) → WalletTransaction[]`** — `GET /api/wallet/transactions?limit=&offset=`.
  Mirrors Rust `wallet_transactions(bearer, limit, offset)`. Defaults: `limit=20, offset=0`.

#### Subscriptions

- **`listSubscriptions() → SubscriptionItem[]`** — `GET /api/subscriptions`.
  Mirrors Rust `subscriptions(bearer)`.
- **`createSubscription(body) → SubscriptionItem`** — `POST /api/subscriptions`.
  Mirrors Rust `create_subscription(bearer, body)`.
- **`cancelSubscription(subscriptionId: number)`** — `DELETE /api/subscriptions/{id}`.
  Mirrors Rust `cancel_subscription(bearer, subscription_id)`.

#### Billing

- **`billingHistory() → Invoice[]`** — `GET /api/billing/history`.
  Typed variant; pre-existing `getBillingHistory()` (untyped) retained.

#### Usage

- **`reportUsage(event: UsageEvent)`** — `POST /api/usage/report`.
  Accepts typed `UsageEvent`. Mirrors Rust `report_usage(event)`.
  Pre-existing `usageReport(payload: Record)` retained.

#### Analytics

- **`ingestEvent(event: AnalyticsEvent)`** — `POST /api/analytics/events`.
  Typed variant. Mirrors Rust `ingest_event(bearer, event)`.
- **`appAnalyticsOverview(appUuid, period)`** — `GET /api/analytics/apps/{appUuid}/overview?period=`.
  Adds required `period` param missing from `analyticsAppOverview`. Mirrors Rust `app_analytics_overview`.
- **`orgAnalyticsOverview(orgUuid, period)`** — `GET /api/analytics/organizations/{orgUuid}/overview?period=`.
  Adds required `period` param. Mirrors Rust `org_analytics_overview`.

#### Teams (typed)

- **`orgTeams(orgUuid) → TeamItem[]`** — `GET /api/organizations/{orgUuid}/teams`.
  Typed variant. Pre-existing `listOrgTeams` (returns `unknown[]`) retained.
- **`userTeams(userUuid) → TeamItem[]`** — `GET /api/users/{userUuid}/teams`.
  Typed variant. Pre-existing `getUserTeams` (returns `unknown[]`) retained.

#### App management

- **`myApps() → AppEntry[]`** — `GET /api/me/apps`. Mirrors Rust `my_apps(bearer)`.
- **`appOrgs(appUuid) → OrgEntry[]`** — `GET /api/apps/{appUuid}/organizations`.
  Mirrors Rust `app_orgs(bearer, app_uuid)`.
- **`appCredentials(appUuid) → AppCredentialsResponse`** — `GET /api/apps/{appUuid}/credentials`.
  Mirrors Rust `app_credentials(bearer, app_uuid)`.
- **`enableSandbox(appUuid)`** — `PATCH /api/apps/{appUuid}` body `{ sandbox_enabled: true }`.
  Mirrors Rust `enable_sandbox(bearer, app_uuid)`.
- **`rotateCredentials(appUuid, environment) → unknown`** — `POST /api/apps/{appUuid}/credentials/{env}/rotate`.
  Mirrors Rust `rotate_credentials(bearer, app_uuid, environment)`.

### New types (all exported from `@buttrbase/client`)

`AccessToken`, `EntitlementResult`, `EffectiveEntitlement`, `WalletSummary`,
`WalletTransaction`, `SubscriptionItem`, `PricingPreviewRequest`, `PricingPreview`,
`CheckoutSessionRequest`, `CheckoutSession`, `UsageEvent`, `AnalyticsEvent`,
`AppEntry`, `OrgEntry`, `AppCredentialsResponse`, `AppCredentialInfo`,
`Invoice`, `TeamItem`.

### Tests

23 new `describe` blocks (one per new method) in `tests/unit.test.ts`, each asserting
the correct URL, HTTP verb, request body, and parsed response shape against a mocked
fetch. All 165 tests pass.

---

## Unreleased — cryptographic RS256 verifier (`Verifier`)

### Added (strictly additive, no breaking changes)

- **`Verifier` class** (`src/verify.ts`) — cryptographic JWT verifier with
  JWKS fetch and caching (backed by `jose`). Mirrors `Verifier` /
  `VerifierConfig` / `verify` / `verify_bearer` from the Rust SDK
  (buttrbase-sdk-rust `src/verify/verifier.rs`).
  - **`new Verifier(config: VerifierConfig)`** — construct once at startup;
    reuse across requests. `config` has `jwksUrl`, `issuer`, and optional
    `audience`.
  - **`verifyToken(token): Promise<Claims>`** — validates RS256 signature
    against the remote JWKS, enforces `iss` and expiry. Enforces `aud` only
    when `audience` is configured (mirrors Rust `validate_aud = false` when
    `audience: None`). Returns the typed `Claims` on success.
  - **`verifyBearer(authHeader): Promise<AuthContext>`** — strips `Bearer `
    from an `Authorization` header value, calls `verifyToken`, and returns
    `AuthContext` via the existing `claimsToAuthContext` helper.
  - **`issuer`** / **`audience`** — read-only accessors (useful for
    diagnostics).
- **`VerifierConfig` interface** — exported from `@buttrbase/client`.
- `jose` added as a production dependency (JWKS fetch/cache + RS256
  verification).

### Dependency added

- `jose` (ESM-first JOSE library by panva; widely used, zero transitive
  dependencies). Added as a `dependency` (not `devDependency`) since the
  `Verifier` class is part of the public runtime API.

---

## 0.5.0 — data envelope: roles / email (mirrors Rust SDK 0.6.0)

### Added (strictly additive)

- **`ClaimsData` interface** — typed shape of the buttrbase `data` JWT claim
  envelope (`roles?`, `email?`, `org_uuid?`, `user_uuid?`, plus an index
  signature for forward-compatible fields).
- **`Claims` interface** — full decoded JWT payload (`sub`, `org`, `exp`,
  `iat`, `scope?`, `data?`).
- **`AuthContext` interface** — the principal callers actually want:
  `userId`, `orgId`, `scopes`, `roles` (split from `data.roles` on
  commas/spaces → `string[]`), and `email` (from `data.email`).
- **`decodeJwtPayload(token)`** — decodes the base64url payload of a JWT
  string and returns the raw `Claims` object. **No signature verification.**
- **`decodeButtrbaseClaims(token)`** — convenience wrapper: decodes the JWT
  payload and converts it to an `AuthContext` via `claimsToAuthContext`.
  **No signature verification** — always verify against the JWKS first.
- **`claimsToAuthContext(claims)`** — converts a `Claims` object (e.g. from
  your own JWKS verification library) to a typed `AuthContext`.
- All three functions are exported from the package root (`@buttrbase/client`).

> **Why no signature verification here?** The SDK already exposes
> `orgJwks(orgUuid)` to fetch the public JWKS. Integrating a full RS256
> verifier would require adding a crypto dependency and entangle Node vs.
> browser APIs. The split — verify externally, decode here — keeps the SDK
> zero-dependency. This mirrors the approach taken in the Rust SDK, where
> `Claims` / `ClaimsData` / `AuthContext` are also separate from the
> `Verifier`.

## Unreleased — magic-link contract aligned with backend

### Breaking
- **`sendMagicLink` signature.** Now `sendMagicLink(email, opts?)` where `opts`
  is `{ appUuid?, redirectTo?, orgUuid? }` (matching the backend's optional
  `app_uuid` / `redirect_to` / `org_uuid` body fields). The previously
  documented positional `sendMagicLink(email, appUuid, opts)` form is removed;
  `appUuid` now lives in `opts`. The endpoint stays `POST /api/auth/magic-link/send`.
- **Magic-link response types.** `MagicLinkSend` is now
  `{ sent: boolean; dev_token: string | null; expires_in_seconds: number }` and
  `MagicLinkVerify` is `{ access_token: string; token_type: string; user: { user_uuid; email }; redirect_to: string | null }`.
  The verify response field is `access_token` (was incorrectly documented as
  `accessToken`).

### Added
- `MagicLinkSendOptions` and `MagicLinkUser` types.
- Cross-app federation support: passing `appUuid` + an allowlisted-origin
  `redirectTo` makes the emailed link target the app's own callback
  (`{redirect_to}?token=...`) so the app verifies the RS256 token itself.
- Expanded README "Magic-link (passwordless sign-in)" section and method
  TSDoc covering RS256-vs-HS256, the send→verify flow, and the redirect
  allowlist.

## Unreleased — static API keys removed; OAuth2 client-credentials only

### Breaking
- **Static API-key auth removed.** The `wb_live_*` / `wb_test_*` keys, the
  `X-API-Key` header, and the api-key→token exchange are no longer supported.
  OAuth2 client-credentials (`client_id` + `client_secret`) is now the single
  app-server credential.
- `ButtrbaseClient` constructor no longer accepts `apiKey`. It now requires
  `clientId` and `clientSecret`, and accepts an optional `accessToken` (a
  pre-obtained bearer). Token-issuing flows (`login`, `authStepUp`, ...)
  replace the bearer on success.
- Removed `exchangeApiKey(apiKey)` and `exchangeRefreshToken(refreshToken)`
  (wrapped `POST /api/v1/auth/api-key/exchange`).
- Removed app-level API-key admin: `listAppApiKeys`, `createAppApiKey`,
  `revokeAppApiKey`, `rotateAppApiKey`.
- Removed org-level API-key admin: `listApiKeysV2`, `createApiKeyV2`,
  `deleteApiKeyV2`.
- Removed types: `ExchangeResponse`, `ApiKeySummary`, `CreatedKeyResponse`,
  `CreateApiKeyInput`, `ApiKeyType`, `ApiKeyEnv`, `ExpiryInput`.

### Added
- **Client-credentials token grant.** New `authenticate()` method wraps
  `POST /api/v1/auth/token` (`grant_type=client_credentials`), exchanging the
  configured `clientId` / `clientSecret` for an app-server bearer and storing
  it for subsequent requests. Authenticated calls now work end-to-end with just
  `clientId` / `clientSecret`: the SDK fetches a bearer lazily before the first
  authed request, caches it, and refreshes it ~30s before `expires_in` lapses.
  A constructor-supplied `accessToken` (or a `login` / `authStepUp` bearer) is
  used as-is and is never auto-refreshed by the grant.

## Unreleased — app_uuid migration

### Breaking
- Methods taking an `app` slug now take `appUuid: string` (UUID):
  `register`, `login`, `sendOtp`, `verifyOtp`, `sendMagicLink`. The backend
  no longer accepts slug aliases (`app`, `appId`, `appName`); requests
  without a valid `app_uuid` are rejected.
- `sendMagicLink` is now `sendMagicLink(email, appUuid, opts)` and posts to
  `/api/auth/magic-link/send` (the `orgUuid` option was removed; supply
  `appUuid` instead).
- `sendOtp(phone, appUuid)` is the canonical name and posts to
  `/api/auth/otp` (previously `/api/auth/otp/send`). `otpSend` is kept as a
  deprecated alias for one release; it will be removed in v1.0.
- `verifyOtp(phone, code, appUuid)` is the canonical name. `otpVerify` is
  kept as a deprecated alias for one release; removed in v1.0.
- `register` is now `register(email, password, appUuid, opts)`; the previous
  `orgName` slug parameter was removed.
- `login` is now `login(email, password, appUuid)`; the previous `orgName`
  slug parameter was removed. The access token is still cached on success.

### Added
- `lookupOrganization(appUuid, { domain?, slug? })` — wraps
  `POST /api/auth/organizations/lookup`.
- `oauthStartUrl(provider, appUuid, returnTo)` — pure URL builder for
  `GET /api/v1/auth/oauth/{provider}/start`. The caller must navigate the
  browser to the returned URL (the backend issues a 302).
- OAuth config admin: `listOAuthConfigs`, `createOAuthConfig`,
  `updateOAuthConfig`, `deleteOAuthConfig`
  (`/api/v1/apps/{app_uuid}/oauth-configs[/...]`).
- `readAuditLog(appUuid, { limit?, action_prefix? })` — wraps
  `GET /api/v1/apps/{app_uuid}/audit-log`.
- Types: `OAuthConfigSummary`, `CreateOAuthConfigInput`,
  `UpdateOAuthConfigInput`, `AuditLogQuery`, `AuditRow`, `OAuthProvider`.

### Passkey support
- `passkeyRegisterBegin()` / `passkeyRegisterComplete(body)` /
  `passkeyAuthenticateBegin()` / `passkeyAuthenticateComplete(body)` — thin
  wrappers over `POST /api/passkeys/{register,authenticate}/{begin,complete}`.
  The WebAuthn challenge / credential blobs are typed as `unknown` and passed
  through unchanged so the browser's `navigator.credentials.create/get` APIs
  can consume / produce them directly. Begin endpoints unwrap the backend's
  `{data: ...}` envelope for ergonomics.
- `listMyPasskeys()` — `GET /api/v1/me/passkeys`. Returns
  `PasskeyListItem[]` in descending `created_at` order.
- `deleteMyPasskey(credentialUuid)` — `DELETE /api/v1/me/passkeys/{uuid}`.
  Owner check is enforced on the backend.
- Types: `PasskeyRegistrationChallenge`, `PasskeyRegistrationComplete`,
  `PasskeyRegistrationResult`, `PasskeyAuthChallenge`, `PasskeyAuthComplete`,
  `PasskeyListItem`.
