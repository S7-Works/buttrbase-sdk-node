import type { CouponValidation, GiftCardValidation, GiftCardRedemption, MagicLinkSend, MagicLinkSendOptions, MagicLinkVerify, MfaStatus, MfaEnrollment, OrgSignResponse, Jwk, SecretGet, SecretSummary, StepUpResponse, ElevationGrant, SpiffeSvidResponse, AuthEvent, ReencryptResponse, RevokeSessionResponse, OrgMetrics, Credential, CredentialListResponse, CreateCredentialResponse, RotateSecretResponse, SandboxResetResponse, InviteAcceptRequest, InviteAcceptResponse, OrgCheckResponse, SuperuserResponse, CheckOrgNameResponse, ClientCredentialsTokenResponse, TokenPair, FinalizeRegistrationRequest, RegistrationResult, CreateInvitationRequest, InvitationResponse, InvitationPreview, AcceptInvitationResponse, InvitationListItem, ContactRequest, ContactUsRequest, ContactSubmitResponse, GeoResponse, OAuthProvider, OAuthConfigSummary, CreateOAuthConfigInput, UpdateOAuthConfigInput, AppRpConfig, UpdateAppRpConfigInput, AuditLogQuery, AuditRow, PasskeyRegistrationChallenge, PasskeyRegistrationComplete, PasskeyRegistrationResult, PasskeyAuthChallenge, PasskeyAuthComplete, PasskeyListItem, ScopeContextRequest, ScopeContextResponse, DeviceItem, RevokeDeviceResponse, TenantHome, WebhookEndpoint, WebhookDelivery, AccessToken, EntitlementResult, EffectiveEntitlement, WalletSummary, WalletTransaction, SubscriptionItem, PricingPreviewRequest, PricingPreview, CheckoutSessionRequest, CheckoutSession, UsageEvent, AnalyticsEvent, AppEntry, OrgEntry, AppCredentialsResponse, Invoice, TeamItem } from './types.js';
export interface ButtrbaseClientOptions {
    /**
     * OAuth2 client-credentials issued to your app server (the `client_id` /
     * `client_secret` pair returned by {@link ButtrbaseClient.createCredential}).
     * This is the single app-server credential.
     */
    clientId: string;
    clientSecret?: string;
    /**
     * Optional pre-obtained bearer access token. When supplied it is used as the
     * `Authorization: Bearer` value immediately. Token-issuing flows
     * (`login`, `authStepUp`, ...) replace it on success.
     *
     * When omitted, the SDK lazily exchanges the configured `clientId` /
     * `clientSecret` for a bearer via the OAuth2 client-credentials grant
     * (`POST /api/v1/auth/token`) before the first authenticated request, caches
     * it, and refreshes it shortly before it expires.
     */
    accessToken?: string;
    baseUrl?: string;
    fetch?: typeof fetch;
    /**
     * Maximum number of automatic retries for transient failures (HTTP 502/503/504,
     * 429, and network/connection errors). The backend can scale to zero, so the
     * first request after an idle period may return a 502 cold-start. Defaults to 3.
     * Set to 0 to disable retries entirely.
     */
    maxRetries?: number;
    /**
     * Base delay (in milliseconds) for exponential backoff between retries.
     * Defaults to 500. Delays grow ~base, base*2, base*4 (with jitter) and are
     * capped at base*8. A `Retry-After` response header, when present, overrides this.
     */
    retryBaseDelayMs?: number;
}
export declare class ButtrbaseClient {
    private clientId;
    private clientSecret;
    /** Current bearer token used for authenticated requests, if any. */
    private accessToken;
    /**
     * Epoch ms at which the client-credentials token should be considered stale
     * and re-fetched (already adjusted for the refresh skew). `undefined` when
     * the current token did not come from the client-credentials grant (e.g. a
     * constructor-supplied `accessToken` or a `login` bearer), so it is never
     * auto-refreshed.
     */
    private accessTokenExpiresAt;
    /** De-dupes concurrent client-credentials grants into a single request. */
    private tokenRequest;
    private baseUrl;
    private fetchImpl;
    private maxRetries;
    private retryBaseDelayMs;
    constructor(opts: ButtrbaseClientOptions);
    /**
     * POST /api/v1/auth/token — exchange the configured `clientId` /
     * `clientSecret` for an app-server bearer via the OAuth2 client-credentials
     * grant. On success the returned `access_token` becomes the bearer for
     * subsequent authenticated requests and is cached until shortly before it
     * expires (per `expires_in`).
     *
     * Calling this directly forces a fresh token; otherwise the SDK fetches one
     * lazily before the first authenticated request and refreshes it on expiry.
     * Bad credentials surface as a `ButtrbaseError` (HTTP 401).
     */
    authenticate(): Promise<ClientCredentialsTokenResponse>;
    /**
     * Ensure a usable bearer is present, fetching one via the client-credentials
     * grant when none is set or the cached one has reached its refresh deadline.
     * Concurrent callers share a single in-flight grant. Returns the bearer.
     */
    private ensureAccessToken;
    /** Sleep for `ms`, rejecting early if the (optional) signal aborts. */
    private static sleep;
    /** True when a thrown fetch error represents an abort rather than a network failure. */
    private static isAbortError;
    /**
     * Compute the delay before the next retry. Honors a `Retry-After` header
     * (delta-seconds or HTTP-date) when present; otherwise uses exponential
     * backoff with full jitter, capped at base*8.
     */
    private retryDelayMs;
    private request;
    validateCoupon(code: string, opts?: {
        cartLabels?: string[];
        productId?: number;
    }): Promise<CouponValidation>;
    validateGiftCard(code: string): Promise<GiftCardValidation>;
    redeemGiftCard(code: string, amountCents: number, userId?: number): Promise<GiftCardRedemption>;
    /**
     * Send a passwordless magic-link email (`POST /api/auth/magic-link/send`).
     *
     * Magic-link is the only browser flow that yields a JWKS-verifiable **RS256**
     * access token. (The generic email-OTP endpoints issue HS256 tokens signed
     * with Buttrbase's server secret, which the public JWKS cannot verify.) So
     * third-party apps that need to verify tokens themselves must use this flow.
     *
     * Cross-app federation: pass `appUuid` together with a `redirectTo` whose
     * origin is registered on the Buttrbase application (its WebAuthn
     * `rp_origins` or configured redirect URL). The emailed link then points at
     * the app's own callback (`{redirect_to}?token=...`) so the app verifies the
     * RS256 token itself. Non-allowlisted or non-absolute targets fall back to
     * the Buttrbase-hosted sign-in page. Omit `redirectTo` for the first-party
     * flow.
     *
     * @param email   Recipient email address (required).
     * @param opts    Optional `appUuid`, `redirectTo`, and `orgUuid`.
     * @returns       `{ sent, dev_token, expires_in_seconds }`. `dev_token` is
     *                the raw one-time token in non-prod dev-echo mode; `null` in
     *                production.
     *
     * @example
     * ```ts
     * const { sent, expires_in_seconds } = await client.sendMagicLink(
     *   "user@example.com",
     *   { appUuid: "076bf23c-...", redirectTo: "https://app.example.com/auth/callback" },
     * );
     * ```
     */
    sendMagicLink(email: string, opts?: MagicLinkSendOptions): Promise<MagicLinkSend>;
    /**
     * Verify a magic-link token (`POST /api/auth/magic-link/verify`).
     *
     * Exchanges the raw one-time token (delivered via the emailed link, or
     * `dev_token` in dev-echo mode) for a JWKS-verifiable RS256 `access_token`.
     *
     * @param token  The one-time magic-link token.
     * @returns      `{ access_token, token_type, user, redirect_to }`.
     *
     * @example
     * ```ts
     * const { access_token, user } = await client.verifyMagicLink(token);
     * ```
     */
    verifyMagicLink(token: string): Promise<MagicLinkVerify>;
    mfaStatus(): Promise<MfaStatus>;
    mfaEnroll(label?: string): Promise<MfaEnrollment>;
    mfaActivate(code: string): Promise<{
        status: string;
    }>;
    orgSign(orgUuid: string, claims: Record<string, unknown>, opts?: {
        ttlSeconds?: number;
    }): Promise<OrgSignResponse>;
    orgJwks(orgUuid: string): Promise<{
        keys: Jwk[];
    }>;
    getSecret(orgUuid: string, name: string): Promise<SecretGet>;
    putSecret(orgUuid: string, name: string, value: string, description?: string): Promise<SecretSummary>;
    /**
     * POST /api/auth/step-up — exchange MFA code for a short-lived elevated
     * access token (~5 min). On success, the SDK's bearer is REPLACED with
     * the returned `access_token` so subsequent admin/JIT calls are elevated.
     */
    authStepUp(code: string, recovery?: boolean): Promise<StepUpResponse>;
    /** POST /api/admin/orgs/{org}/elevation/request */
    elevationRequest(orgUuid: string, scope: string, opts?: {
        reason?: string;
        ttlSeconds?: number;
    }): Promise<ElevationGrant>;
    /**
     * POST /api/admin/orgs/{org}/elevation/{grant}/approve.
     * Server returns 403 if the approver is the same admin as the requester.
     */
    elevationApprove(orgUuid: string, grantUuid: string): Promise<ElevationGrant>;
    /** GET /api/admin/orgs/{org}/elevation */
    elevationList(orgUuid: string, status?: string): Promise<ElevationGrant[]>;
    /** POST /api/admin/orgs/{org}/spiffe/svid — issue an X.509 SVID. */
    spiffeIssueSvid(orgUuid: string, workloadPath: string, opts?: {
        ttlSeconds?: number;
    }): Promise<SpiffeSvidResponse>;
    /** GET /api/admin/orgs/{org}/auth-events — context-aware audit events. */
    listAuthEvents(orgUuid: string, opts?: {
        userUuid?: string;
        limit?: number;
    }): Promise<AuthEvent[]>;
    /** POST /api/admin/orgs/{org}/reencrypt/secrets */
    reencryptSecrets(orgUuid: string): Promise<ReencryptResponse>;
    /** POST /api/admin/orgs/{org}/reencrypt/signing-keys */
    reencryptSigningKeys(orgUuid: string): Promise<ReencryptResponse>;
    /** POST /api/admin/orgs/{org}/reencrypt/mtls-ca */
    reencryptMtlsCa(orgUuid: string): Promise<ReencryptResponse>;
    /** POST /api/admin/sessions/revoke — add `jti` to the revocation list. */
    revokeSession(jti: string, ttlSeconds?: number): Promise<RevokeSessionResponse>;
    /** GET /api/admin/orgs/{org}/metrics */
    getOrgMetrics(orgUuid: string): Promise<OrgMetrics>;
    /** GET /credentials — list all client credentials for the authenticated account. */
    listCredentials(): Promise<CredentialListResponse>;
    /**
     * POST /credentials — create a new OAuth2 client credential.
     * Returns 201 with the full credential including `client_secret` (shown only once).
     */
    createCredential(name: string, description?: string): Promise<CreateCredentialResponse>;
    /** GET /credentials/:id — fetch a credential by ID (no `client_secret`). */
    getCredential(id: string): Promise<Credential>;
    /** DELETE /credentials/:id — permanently delete a credential (returns void on 204). */
    deleteCredential(id: string): Promise<void>;
    /**
     * POST /credentials/:id/rotate-secret — rotate the client secret for a credential.
     * Returns new `client_id` and `client_secret`.
     */
    rotateCredentialSecret(id: string): Promise<RotateSecretResponse>;
    /**
     * POST /api/sandbox/reset — reset the sandbox environment.
     * Optionally scoped to a specific org via `orgUuid`.
     */
    resetSandbox(orgUuid?: string): Promise<SandboxResetResponse>;
    /**
     * POST /api/auth/register — register a new user for an app.
     *
     * BREAKING: previously this accepted an `orgName` slug; now `appUuid` (a UUID
     * string) is required. The backend rejects requests without a valid `app_uuid`.
     *
     * @deprecated Use sendOtpEmail → verifyOtpEmail → finalizeRegistration instead.
     */
    register(email: string, password: string, appUuid: string, opts?: {
        firstName?: string;
        lastName?: string;
    }): Promise<Record<string, unknown>>;
    /**
     * POST /api/auth/login — stores access_token on success.
     *
     * BREAKING: previously this accepted an `orgName` slug; now `appUuid` (a UUID
     * string) is required. The backend rejects requests without a valid `app_uuid`.
     */
    login(email: string, password: string, appUuid: string): Promise<Record<string, unknown>>;
    /**
     * POST /api/auth/organizations/lookup — look up an organization by domain or slug.
     *
     * BREAKING: now requires `appUuid` (a UUID string). The backend rejects requests
     * without a valid `app_uuid`.
     */
    lookupOrganization(appUuid: string, opts?: {
        domain?: string;
        slug?: string;
    }): Promise<Record<string, unknown>>;
    /** GET /api/auth/organizations/{org_uuid}/login-options */
    getLoginOptions(orgUuid: string): Promise<Record<string, unknown>>;
    /** GET /api/auth/status */
    getStatus(): Promise<Record<string, unknown>>;
    /** GET /api/profile */
    getProfile(): Promise<Record<string, unknown>>;
    /** PUT /api/profile */
    updateProfile(data: Record<string, unknown>): Promise<Record<string, unknown>>;
    /** GET /api/auth/orgs-by-domain/{domain} */
    getOrgByDomain(domain: string): Promise<Record<string, unknown>>;
    /**
     * POST /api/auth/otp — send an OTP code to a phone number.
     *
     * BREAKING: now requires `appUuid` (a UUID string). The backend rejects requests
     * without a valid `app_uuid`.
     */
    sendOtp(phone: string, appUuid: string): Promise<Record<string, unknown>>;
    /**
     * @deprecated Use {@link sendOtp} instead. This alias exists for back-compat
     * during the cross-SDK naming normalisation and will be removed in v1.0.
     */
    otpSend(phone: string, appUuid: string): Promise<Record<string, unknown>>;
    /**
     * POST /api/auth/otp/verify — verify an OTP code.
     *
     * BREAKING: now requires `appUuid` (a UUID string). The backend rejects requests
     * without a valid `app_uuid`.
     */
    verifyOtp(phone: string, code: string, appUuid: string): Promise<Record<string, unknown>>;
    /**
     * @deprecated Use {@link verifyOtp} instead. Removed in v1.0.
     */
    otpVerify(phone: string, code: string, appUuid: string): Promise<Record<string, unknown>>;
    /** POST /api/auth/mfa/totp/verify */
    mfaVerify(code: string): Promise<Record<string, unknown>>;
    /** POST /api/auth/mfa/totp/challenge */
    mfaChallenge(): Promise<Record<string, unknown>>;
    /** DELETE /api/auth/mfa/totp */
    mfaDisable(): Promise<Record<string, unknown>>;
    /** POST /api/auth/mfa/recovery-codes */
    mfaGenerateRecoveryCodes(): Promise<Record<string, unknown>>;
    /** POST /api/auth/mfa/recovery-codes/redeem */
    mfaRedeemRecoveryCode(code: string): Promise<Record<string, unknown>>;
    /**
     * POST /api/passkeys/register/begin — start passkey registration.
     * Requires an authenticated caller (you add a passkey to an existing account).
     * Pass the returned `challenge` to `navigator.credentials.create({publicKey: challenge.publicKey})`
     * and the `registration_state` back to {@link passkeyRegisterComplete}.
     */
    passkeyRegisterBegin(): Promise<PasskeyRegistrationChallenge>;
    /**
     * POST /api/passkeys/register/complete — finish passkey registration.
     * `credential` is the WebAuthn `RegisterPublicKeyCredential` produced by the
     * browser; `registration_state` is the opaque blob returned by
     * {@link passkeyRegisterBegin}.
     */
    passkeyRegisterComplete(body: PasskeyRegistrationComplete): Promise<PasskeyRegistrationResult>;
    /**
     * POST /api/passkeys/authenticate/begin — start passkey authentication.
     * Anonymous; no Authorization header required. Pass the returned `challenge`
     * to `navigator.credentials.get({publicKey: challenge.publicKey})`.
     */
    passkeyAuthenticateBegin(): Promise<PasskeyAuthChallenge>;
    /**
     * POST /api/passkeys/authenticate/complete — finish passkey authentication.
     * Returns the session payload (shape currently unstable on the backend —
     * `unknown` here, callers should narrow at the call site).
     */
    passkeyAuthenticateComplete(body: PasskeyAuthComplete): Promise<unknown>;
    /**
     * GET /api/v1/me/passkeys — list the signed-in user's enrolled passkeys.
     * Returns the rows in descending `created_at` order. Each row carries a
     * `credential_uuid` (for revocation) and a 12-char `credential_id_prefix`
     * for display.
     */
    listMyPasskeys(): Promise<PasskeyListItem[]>;
    /**
     * DELETE /api/v1/me/passkeys/{credentialUuid} — revoke one of the
     * signed-in user's passkeys. The backend enforces the owner check; passing
     * a UUID owned by another user returns 404.
     */
    deleteMyPasskey(credentialUuid: string): Promise<{
        status: string;
    }>;
    /** GET /api/auth/oidc/{connection_uuid}/authorize */
    oidcAuthorizeUrl(connectionUuid: string): Promise<Record<string, unknown>>;
    /** GET /api/auth/saml/{connection_uuid}/authorize */
    samlAuthorizeUrl(connectionUuid: string): Promise<Record<string, unknown>>;
    /** GET /api/users */
    listUsers(filters?: Record<string, unknown>): Promise<Record<string, unknown>>;
    /** GET /api/users/{user_uuid}/level */
    getUserLevel(userUuid: string): Promise<Record<string, unknown>>;
    /** POST /api/users/{user_uuid}/level */
    setUserLevel(userUuid: string, userType: string): Promise<Record<string, unknown>>;
    /** PUT /api/users/{user_uuid}/status */
    updateUserStatus(userUuid: string, active: boolean): Promise<Record<string, unknown>>;
    /** PUT /api/users/{user_uuid}/role */
    updateUserRole(userUuid: string, role: string): Promise<Record<string, unknown>>;
    /** GET /api/organizations/{org_uuid}/security-settings */
    getSecuritySettings(orgUuid: string): Promise<Record<string, unknown>>;
    /** PUT /api/organizations/{org_uuid}/security-settings */
    updateSecuritySettings(orgUuid: string, settings: Record<string, unknown>): Promise<Record<string, unknown>>;
    /** GET /api/organizations/{org_uuid}/sso-connections */
    listSsoConnections(orgUuid: string): Promise<unknown[]>;
    /** POST /api/organizations/{org_uuid}/sso-connections */
    createSsoConnection(orgUuid: string, provider: string, name: string, config: Record<string, unknown>): Promise<Record<string, unknown>>;
    /** PUT /api/organizations/{org_uuid}/sso-connections/{connection_uuid} */
    updateSsoConnection(orgUuid: string, connectionUuid: string, data: Record<string, unknown>): Promise<Record<string, unknown>>;
    /** DELETE /api/organizations/{org_uuid}/sso-connections/{connection_uuid} */
    deleteSsoConnection(orgUuid: string, connectionUuid: string): Promise<void>;
    /** GET /api/organizations/{org_uuid}/audit-events */
    listAuditEvents(orgUuid: string): Promise<unknown[]>;
    /** GET /api/organizations/{org_uuid}/audit-events/export */
    exportAuditEvents(orgUuid: string): Promise<Record<string, unknown>>;
    /** GET /api/organizations/{org_uuid}/branding */
    getBranding(orgUuid: string): Promise<Record<string, unknown>>;
    /** PUT /api/organizations/{org_uuid}/branding */
    updateBranding(orgUuid: string, branding: Record<string, unknown>): Promise<Record<string, unknown>>;
    /** GET /api/organizations/{org_uuid}/session-inventory */
    orgSessionInventory(orgUuid: string): Promise<Record<string, unknown>>;
    /** POST /api/organizations/{org_uuid}/revoke-all-sessions */
    orgRevokeAllSessions(orgUuid: string): Promise<Record<string, unknown>>;
    /** GET /api/devices/{device_uuid}/accounts */
    listDeviceAccounts(deviceUuid: string): Promise<unknown[]>;
    /** POST /api/devices/{device_uuid}/accounts */
    addDeviceAccount(deviceUuid: string, data: Record<string, unknown>): Promise<Record<string, unknown>>;
    /** DELETE /api/devices/{device_uuid}/accounts */
    deleteDeviceAccounts(deviceUuid: string): Promise<void>;
    /** DELETE /api/devices/{device_uuid}/accounts/{account_uuid} */
    deleteDeviceAccount(deviceUuid: string, accountUuid: string): Promise<void>;
    /** POST /api/devices/{device_uuid}/active-account */
    switchDeviceActiveAccount(deviceUuid: string, accountUuid: string): Promise<Record<string, unknown>>;
    /** GET /api/devices/{device_uuid}/session-inventory */
    deviceSessionInventory(deviceUuid: string): Promise<Record<string, unknown>>;
    /** POST /api/devices/{device_uuid}/revoke-all */
    revokeAllDeviceSessions(deviceUuid: string): Promise<Record<string, unknown>>;
    /** GET /api/organizations/{org_uuid}/service-identities */
    listServiceIdentities(orgUuid: string): Promise<unknown[]>;
    /** POST /api/organizations/{org_uuid}/service-identities */
    createServiceIdentity(orgUuid: string, payload: Record<string, unknown>): Promise<Record<string, unknown>>;
    /** DELETE /api/organizations/{org_uuid}/service-identities/{key_uuid} */
    deleteServiceIdentity(orgUuid: string, keyUuid: string): Promise<void>;
    /** POST /api/organizations/{org_uuid}/service-identities/automation-token */
    createServiceIdentityAutomationToken(orgUuid: string, payload: Record<string, unknown>): Promise<Record<string, unknown>>;
    /** POST /api/entitlements/check */
    entitlementsCheck(feature: string, orgUuid?: string): Promise<Record<string, unknown>>;
    /** POST /api/entitlements/check/batch */
    entitlementsCheckBatch(checks: unknown[]): Promise<Record<string, unknown>>;
    /** GET /api/entitlements/effective */
    entitlementsEffective(): Promise<Record<string, unknown>>;
    /** POST /api/admin/entitlements/explain */
    adminEntitlementsExplain(payload: Record<string, unknown>): Promise<Record<string, unknown>>;
    /** POST /api/pricing/preview */
    pricingPreview(payload: Record<string, unknown>): Promise<Record<string, unknown>>;
    /** POST /api/pricing/quote */
    pricingQuote(payload: Record<string, unknown>): Promise<Record<string, unknown>>;
    /** POST /api/pricing/checkout-session */
    pricingCheckoutSession(payload: Record<string, unknown>): Promise<Record<string, unknown>>;
    /** POST /api/admin/pricing/explain */
    adminPricingExplain(payload: Record<string, unknown>): Promise<Record<string, unknown>>;
    /** POST /api/catalog/pricing/preview */
    catalogPricingPreview(payload: Record<string, unknown>): Promise<Record<string, unknown>>;
    /** GET /api/admin/products/{product_id}/coupons */
    adminListProductCoupons(productId: string): Promise<unknown[]>;
    /** POST /api/admin/products/{product_id}/coupons */
    adminCreateProductCoupon(productId: string, coupon: Record<string, unknown>): Promise<Record<string, unknown>>;
    /** PUT /api/admin/products/{product_id}/coupons/{coupon_id} */
    adminUpdateProductCoupon(productId: string, couponId: string, coupon: Record<string, unknown>): Promise<Record<string, unknown>>;
    /** DELETE /api/admin/products/{product_id}/coupons/{coupon_id} */
    adminDeleteProductCoupon(productId: string, couponId: string): Promise<void>;
    /** PUT /api/admin/coupons/{id}/labels */
    setCouponLabels(couponId: string, labels: string[]): Promise<Record<string, unknown>>;
    /** POST /api/admin/coupons/{id}/labels */
    addCouponLabel(couponId: string, label: string): Promise<Record<string, unknown>>;
    /** DELETE /api/admin/coupons/{id}/labels/{label} */
    removeCouponLabel(couponId: string, label: string): Promise<void>;
    /** PUT /api/admin/products/{id}/tags */
    setProductTags(productId: string, tags: string[]): Promise<Record<string, unknown>>;
    /** POST /api/admin/products/{id}/tags */
    addProductTag(productId: string, tag: string): Promise<Record<string, unknown>>;
    /** DELETE /api/admin/products/{id}/tags/{tag} */
    removeProductTag(productId: string, tag: string): Promise<void>;
    /** POST /api/analytics/events */
    ingestAnalyticsEvent(event: Record<string, unknown>): Promise<Record<string, unknown>>;
    /** GET /api/analytics/apps/{app_uuid}/overview */
    analyticsAppOverview(appUuid: string): Promise<Record<string, unknown>>;
    /** GET /api/analytics/organizations/{org_uuid}/overview */
    analyticsOrgOverview(orgUuid: string): Promise<Record<string, unknown>>;
    /** POST /api/teams */
    createTeam(payload: Record<string, unknown>): Promise<Record<string, unknown>>;
    /** GET /api/organizations/{org_uuid}/teams */
    listOrgTeams(orgUuid: string): Promise<unknown[]>;
    /** GET /api/teams/org/{org_uuid}/inactive */
    listInactiveTeams(orgUuid: string): Promise<unknown[]>;
    /** POST /api/teams/lifecycle/{team_uuid}/reactivate */
    reactivateTeam(teamUuid: string): Promise<Record<string, unknown>>;
    /** DELETE /api/teams/lifecycle/{team_uuid} */
    archiveTeam(teamUuid: string): Promise<void>;
    /** GET /api/teams/{team_uuid}/members */
    listTeamMembers(teamUuid: string): Promise<unknown[]>;
    /** POST /api/teams/{team_uuid}/members */
    addTeamMember(teamUuid: string, userUuid: string): Promise<Record<string, unknown>>;
    /** DELETE /api/teams/{team_uuid}/members/{user_uuid} */
    removeTeamMember(teamUuid: string, userUuid: string): Promise<void>;
    /** GET /api/teams/{team_uuid}/observers */
    listTeamObservers(teamUuid: string): Promise<unknown[]>;
    /** POST /api/teams/{team_uuid}/observers */
    addTeamObserver(teamUuid: string, userUuid: string): Promise<Record<string, unknown>>;
    /** DELETE /api/teams/{team_uuid}/observers/{user_uuid} */
    removeTeamObserver(teamUuid: string, userUuid: string): Promise<void>;
    /** GET /api/users/{user_uuid}/teams */
    getUserTeams(userUuid: string): Promise<unknown[]>;
    /** GET /api/users/{user_uuid}/observed-teams */
    getUserObservedTeams(userUuid: string): Promise<unknown[]>;
    /** GET /api/organizations/{org_uuid}/features */
    listOrgFeatures(orgUuid: string): Promise<unknown[]>;
    /** POST /api/organizations/{org_uuid}/features */
    setOrgFeature(orgUuid: string, feature: Record<string, unknown>): Promise<Record<string, unknown>>;
    /** DELETE /api/organizations/{org_uuid}/features/{feature_id} */
    removeOrgFeature(orgUuid: string, featureId: string): Promise<void>;
    /** GET /api/roles */
    listRoles(): Promise<unknown[]>;
    /** GET /api/roles/permissions */
    listAllPermissions(): Promise<unknown[]>;
    /** GET /api/roles/{role_id}/permissions */
    getRolePermissions(roleId: string): Promise<unknown[]>;
    /** PUT /api/roles/{role_id}/permissions */
    updateRolePermissions(roleId: string, permissions: unknown[]): Promise<Record<string, unknown>>;
    /** GET /api/v2/products/{product_id}/permissions */
    getProductPermissions(productId: string): Promise<unknown[]>;
    /** POST /api/v2/products/{product_id}/roles */
    createProductRole(productId: string, roleData: Record<string, unknown>): Promise<Record<string, unknown>>;
    /** GET /api/v2/organizations/{org_uuid}/products/{product_id}/roles */
    getAssignableRoles(orgUuid: string, productId: string): Promise<unknown[]>;
    /** PUT /api/v2/organizations/{org_uuid}/users/{user_uuid}/role */
    assignRoleToUser(orgUuid: string, userUuid: string, roleId: string): Promise<Record<string, unknown>>;
    /** POST /api/billing/checkout */
    checkout(priceId: string, couponCode?: string, addOns?: unknown[]): Promise<Record<string, unknown>>;
    /** GET /api/billing/history */
    getBillingHistory(): Promise<Record<string, unknown>>;
    /** GET /api/billing/invoices */
    listInvoices(): Promise<unknown[]>;
    /** GET /api/billing/config/{provider} */
    getProviderConfig(provider: string): Promise<Record<string, unknown>>;
    /** POST /api/billing/subscriptions/add-on */
    addAddOn(addOn: Record<string, unknown>): Promise<Record<string, unknown>>;
    /** GET /api/wallet */
    getWallet(): Promise<Record<string, unknown>>;
    /** GET /api/environments */
    listEnvironments(): Promise<unknown[]>;
    /** POST /api/plaid/create-link-token */
    plaidCreateLinkToken(payload: Record<string, unknown>): Promise<Record<string, unknown>>;
    /** POST /api/plaid/exchange-public-token */
    plaidExchangePublicToken(publicToken: string): Promise<Record<string, unknown>>;
    /** GET /api/plaid/accounts */
    plaidAccounts(): Promise<unknown[]>;
    /** POST /api/usage/report */
    usageReport(payload: Record<string, unknown>): Promise<Record<string, unknown>>;
    /** GET /api/help */
    helpRoot(): Promise<Record<string, unknown>>;
    /** GET /api/help/search?q={query} */
    helpSearch(query: string): Promise<Record<string, unknown>>;
    /** GET /api/help/categories/{slug} */
    helpCategory(slug: string): Promise<Record<string, unknown>>;
    /** GET /api/help/articles/{slug} */
    helpArticle(slug: string): Promise<Record<string, unknown>>;
    /** POST /api/v2/search/index */
    searchIndex(payload: Record<string, unknown>): Promise<Record<string, unknown>>;
    /** POST /api/v2/search/query */
    searchQuery(q: string, filters?: Record<string, unknown>): Promise<Record<string, unknown>>;
    /** POST /api/v2/search/chat */
    searchChat(q: string, options?: Record<string, unknown>): Promise<Record<string, unknown>>;
    /** POST to gateway.buttrbase.com — AI chat completions via org gateway. */
    aiChatCompletions(orgUuid: string, provider: string, payload: Record<string, unknown>): Promise<Record<string, unknown>>;
    /** GET /api/admin/organizations/{org_uuid}/signing-keys */
    listSigningKeys(orgUuid: string): Promise<unknown[]>;
    /** POST /api/admin/organizations/{org_uuid}/signing-keys/rotate */
    rotateSigningKeys(orgUuid: string): Promise<Record<string, unknown>>;
    /** GET /api/admin/organizations/{org_uuid}/signing-audit */
    listSigningAudit(orgUuid: string): Promise<unknown[]>;
    /** POST /api/orgs/{org_uuid}/sign-document */
    signDocument(orgUuid: string, document: Record<string, unknown>): Promise<Record<string, unknown>>;
    /** GET /api/admin/organizations/{org_uuid}/certificate-authority */
    getCa(orgUuid: string): Promise<Record<string, unknown>>;
    /** POST /api/admin/organizations/{org_uuid}/certificate-authority/init */
    initCa(orgUuid: string, config: Record<string, unknown>): Promise<Record<string, unknown>>;
    /** GET /api/admin/organizations/{org_uuid}/certificates */
    listCertificates(orgUuid: string): Promise<unknown[]>;
    /** POST /api/admin/organizations/{org_uuid}/certificates */
    issueCertificate(orgUuid: string, csr: string): Promise<Record<string, unknown>>;
    /** POST /api/admin/organizations/{org_uuid}/certificates/{serial}/revoke */
    revokeCertificate(orgUuid: string, serial: string): Promise<Record<string, unknown>>;
    /** POST /api/admin/organizations/{org_uuid}/auth-events/purge */
    purgeAuthEvents(orgUuid: string): Promise<Record<string, unknown>>;
    /** GET /api/admin/organizations/{org_uuid}/kms-status */
    kmsStatus(orgUuid: string): Promise<Record<string, unknown>>;
    /** PATCH /api/admin/organizations/{org_uuid}/sso/{connection_uuid}/saml-cert */
    samlCertRollover(orgUuid: string, connectionUuid: string, payload: Record<string, unknown>): Promise<Record<string, unknown>>;
    /** PATCH /api/admin/organizations/{org_uuid}/payment-settings */
    updatePaymentSettings(orgUuid: string, settings: Record<string, unknown>): Promise<Record<string, unknown>>;
    /** GET /api/admin/organizations/{org_uuid}/secrets */
    listSecrets(orgUuid: string): Promise<unknown[]>;
    /** DELETE /api/admin/organizations/{org_uuid}/secrets/{name} */
    deleteSecret(orgUuid: string, name: string): Promise<void>;
    /** POST /api/admin/organizations/{org_uuid}/admin-portal/issue */
    adminPortalIssue(orgUuid: string): Promise<Record<string, unknown>>;
    /** POST /api/admin-portal/exchange */
    adminPortalExchange(token: string): Promise<Record<string, unknown>>;
    /** GET /api/admin/organizations/{org_uuid}/domains */
    listDomains(orgUuid: string): Promise<unknown[]>;
    /** POST /api/admin/organizations/{org_uuid}/domains */
    createDomain(orgUuid: string, domain: string): Promise<Record<string, unknown>>;
    /** POST /api/admin/organizations/{org_uuid}/domains/{id}/verify */
    verifyDomain(orgUuid: string, domainId: string): Promise<Record<string, unknown>>;
    /** DELETE /api/admin/organizations/{org_uuid}/domains/{id} */
    deleteDomain(orgUuid: string, domainId: string): Promise<void>;
    /** GET /api/admin/organizations/{org_uuid}/webhook-endpoints */
    listWebhookEndpoints(orgUuid: string): Promise<unknown[]>;
    /** POST /api/admin/organizations/{org_uuid}/webhook-endpoints */
    createWebhookEndpoint(orgUuid: string, url: string, events: string[]): Promise<Record<string, unknown>>;
    /** DELETE /api/admin/organizations/{org_uuid}/webhook-endpoints/{id} */
    deleteWebhookEndpoint(orgUuid: string, endpointId: string): Promise<void>;
    /** GET /api/admin/organizations/{org_uuid}/webhook-deliveries */
    listOrgWebhookDeliveries(orgUuid: string): Promise<unknown[]>;
    /** POST /api/admin/organizations/{org_uuid}/scim-tokens */
    issueScimToken(orgUuid: string): Promise<Record<string, unknown>>;
    /** POST /api/payments/checkout */
    createPaymentCheckout(amount: number, currency: string, country: string, orgUuid?: string): Promise<Record<string, unknown>>;
    /** POST /api/payments/invoices/send */
    sendInvoice(amount: number, currency: string, appUuid: string, opts?: {
        memo?: string;
        dueDate?: string;
    }): Promise<Record<string, unknown>>;
    /** POST /api/sms/send_sms */
    sendSms(phone: string, message: string, opts?: {
        from?: string;
        orgUuid?: string;
    }): Promise<Record<string, unknown>>;
    /** POST /api/email/verify-identity */
    verifyEmailIdentity(email: string, awsAccessKeyId: string, awsSecretAccessKey: string, awsRegion?: string): Promise<Record<string, unknown>>;
    /** POST /api/v2/jobs/enqueue */
    enqueueJob(name: string, payload: Record<string, unknown>): Promise<Record<string, unknown>>;
    /** POST /api/v2/notifications/send */
    sendNotification(payload: Record<string, unknown>): Promise<Record<string, unknown>>;
    /** GET /api/v2/notifications */
    listNotifications(): Promise<unknown[]>;
    /** GET /api/v2/custom-variables/{key} */
    getCustomVariable(key: string): Promise<Record<string, unknown>>;
    /** POST /api/v2/custom-variables */
    setCustomVariable(key: string, value: string, scope?: string): Promise<Record<string, unknown>>;
    /** POST /api/v2/webhooks */
    registerWebhook(url: string, events: string[], orgUuid?: string): Promise<Record<string, unknown>>;
    /** POST /api/auth/invite/accept */
    inviteAccept(req: InviteAcceptRequest): Promise<InviteAcceptResponse>;
    /** GET /api/auth/orgs/check?name={name} */
    checkOrgName(name: string): Promise<OrgCheckResponse>;
    /**
     * Send an email OTP for the 0.3.0 registration flow.
     * POST /api/v1/auth/otp/send
     * Flow: sendOtpEmail → verifyOtpEmail → finalizeRegistration
     */
    sendOtpEmail(email: string, appUuid: string): Promise<void>;
    /**
     * Verify an email OTP. Returns a TokenPair whose `token` is the
     * signup_token for finalizeRegistration.
     * POST /api/v1/auth/otp/verify
     */
    verifyOtpEmail(email: string, otp: string, appUuid: string): Promise<TokenPair>;
    /**
     * Check whether an org name is available before registration.
     * POST /api/v1/auth/check-org-name
     */
    checkOrgNameV2(name: string): Promise<CheckOrgNameResponse>;
    /**
     * Complete user registration after OTP verification.
     * POST /api/v1/auth/finalize-registration
     * req.signup_token must be the token from verifyOtpEmail.
     */
    finalizeRegistration(req: FinalizeRegistrationRequest): Promise<RegistrationResult>;
    /**
     * Create an org invitation.
     * POST /api/organizations/{orgUuid}/invitations
     * The token in the response is shown once.
     */
    createInvitation(orgUuid: string, req: CreateInvitationRequest): Promise<InvitationResponse>;
    /**
     * Preview an invitation by token (public, no auth).
     * GET /api/auth/invitations/{token}
     */
    previewInvitation(token: string): Promise<InvitationPreview>;
    /**
     * Accept an invitation for an already-authenticated user joining an
     * additional org. New users should use finalizeRegistration with
     * OrgChoice { type: 'accept_invite', invitation_token }.
     * POST /api/auth/invitations/{token}/accept
     */
    acceptInvitation(token: string): Promise<AcceptInvitationResponse>;
    /**
     * List all invitations for an org.
     * GET /api/organizations/{orgUuid}/invitations
     */
    listInvitations(orgUuid: string): Promise<InvitationListItem[]>;
    /**
     * Revoke a pending invitation by its integer ID.
     * DELETE /api/organizations/{orgUuid}/invitations/{invitationId}
     */
    revokeInvitation(orgUuid: string, invitationId: number): Promise<void>;
    /** GET /api/auth/superuser?email={email} */
    getSuperuserFlag(email: string): Promise<SuperuserResponse>;
    /** POST /api/contact */
    postContact(req: ContactRequest): Promise<ContactSubmitResponse>;
    /** POST /api/contact-us */
    postContactUs(req: ContactUsRequest): Promise<ContactSubmitResponse>;
    /** GET /api/geo/ip */
    getClientIp(): Promise<GeoResponse>;
    /**
     * Build the OAuth start URL for `GET /api/v1/auth/oauth/{provider}/start`.
     *
     * This is a pure URL builder — the caller is responsible for navigating the
     * browser to the returned URL (the backend responds with a 302 redirect to
     * the upstream identity provider, which `fetch` cannot follow safely).
     */
    oauthStartUrl(provider: OAuthProvider, appUuid: string, returnTo: string): string;
    /** GET /api/v1/apps/{app_uuid}/oauth-configs — list configured OAuth providers (no secrets). */
    listOAuthConfigs(appUuid: string): Promise<OAuthConfigSummary[]>;
    /** POST /api/v1/apps/{app_uuid}/oauth-configs — register a new OAuth provider. */
    createOAuthConfig(appUuid: string, input: CreateOAuthConfigInput): Promise<OAuthConfigSummary>;
    /**
     * PATCH /api/v1/apps/{app_uuid}/oauth-configs/{provider} — partially update
     * an OAuth provider config. `client_secret` is only rotated when present.
     */
    updateOAuthConfig(appUuid: string, provider: OAuthProvider, patch: UpdateOAuthConfigInput): Promise<OAuthConfigSummary>;
    /** DELETE /api/v1/apps/{app_uuid}/oauth-configs/{provider} — remove an OAuth provider. */
    deleteOAuthConfig(appUuid: string, provider: OAuthProvider): Promise<void>;
    /**
     * GET /api/v1/apps/{app_uuid}/rp-config — fetch the per-app WebAuthn
     * relying-party config (RP id + allowed origins).
     * `rp_id` is `null` when the app inherits the deployment-wide env-var RP id.
     */
    getAppRpConfig(appUuid: string): Promise<AppRpConfig>;
    /**
     * PATCH /api/v1/apps/{app_uuid}/rp-config — partially update the per-app
     * WebAuthn relying-party config. Omitted fields stay unchanged; `rp_id` set
     * to `null` would fall back to the env var, but this typed input cannot
     * express an explicit-null patch (known limitation — use raw JSON to clear).
     */
    updateAppRpConfig(appUuid: string, patch: UpdateAppRpConfigInput): Promise<AppRpConfig>;
    /** GET /api/v1/apps/{app_uuid}/audit-log — read recent audit rows for an app. */
    readAuditLog(appUuid: string, opts?: AuditLogQuery): Promise<AuditRow[]>;
    /**
     * POST /api/app/auth/scope-context — re-mint an access token windowed to an
     * explicit, gate-checked scope subset (least-privilege "windowed" strategy).
     *
     * Authenticated end-user call: the caller must already hold a valid access
     * token. The granted set is always a subset of the caller's effective scopes
     * and each requested scope is run through the scope-gate (step-up) machinery.
     * Fails CLOSED — a 403 (`forbidden`) is returned for a scope the caller lacks
     * and a 401 (`step_up_required`) when a gate demands a fresher factor; in
     * neither case is a token minted. On success returns the new `token` plus the
     * granted (sorted, de-duplicated) `scopes`. The refresh token is unchanged.
     */
    scopeContext(req: ScopeContextRequest): Promise<ScopeContextResponse>;
    /**
     * GET /api/app/devices — list the caller's ACTIVE (non-revoked) device keys.
     * Authenticated end-user call, scoped to the verified token's user. Returns
     * only public-safe fields (no private key material).
     */
    listDevices(): Promise<DeviceItem[]>;
    /**
     * POST /api/app/devices/{device_uuid}/revoke — soft-revoke a device the caller
     * owns. Authenticated end-user call; ownership is enforced server-side, so a
     * device that does not exist, is already revoked, or belongs to another user
     * yields 404 (`ButtrbaseError`).
     */
    revokeDevice(deviceUuid: string): Promise<RevokeDeviceResponse>;
    /**
     * GET /api/tenant/home — resolve an ACTIVE tenant's home so a client can
     * target it directly. Public (no auth): the client is still figuring out
     * *where* to talk. Returns only public routing info; unknown or non-active
     * tenants yield 404 (`ButtrbaseError`). `appId` is optional.
     */
    getTenantHome(orgUuid: string, appId?: number): Promise<TenantHome>;
    /**
     * POST /api/auth/request-password-reset — send a password-reset email.
     * No API key required.
     */
    requestPasswordReset(email: string): Promise<{
        message: string;
    }>;
    /**
     * POST /api/auth/reset-password — complete a password reset using the token
     * from the reset email. No API key required.
     */
    resetPassword(token: string, password: string): Promise<{
        message: string;
    }>;
    /** GET /api/v1/webhooks — list all webhook endpoints. */
    listWebhooks(): Promise<{
        data: WebhookEndpoint[];
    }>;
    /** POST /api/v1/webhooks — register a new webhook endpoint. */
    createWebhook(url: string, opts?: {
        eventTypes?: string[];
        signingSecret?: string;
        description?: string;
    }): Promise<{
        data: WebhookEndpoint;
    }>;
    /** DELETE /api/v1/webhooks/{id} — permanently remove a webhook endpoint. */
    deleteWebhook(id: number): Promise<void>;
    /** GET /api/v1/webhooks/{id}/deliveries — list deliveries for a webhook endpoint. */
    listWebhookDeliveries(webhookId: number): Promise<WebhookDelivery[]>;
    /** POST /api/v1/webhooks/{id}/deliveries/{deliveryId}/retry — retry a failed delivery. */
    retryWebhookDelivery(webhookId: number, deliveryId: number): Promise<{
        status: string;
    }>;
    /**
     * POST /v1/oauth/connections/{provider}/refresh — refresh an OAuth connection's
     * access token for the given provider.
     */
    refreshOAuthConnection(provider: string): Promise<{
        provider: string;
        refreshed: boolean;
        expires_at?: string;
    }>;
    /**
     * POST /api/email/send — send a transactional email via the configured
     * provider. At least one of `htmlBody` or `textBody` should be supplied.
     */
    sendEmail(opts: {
        to: string;
        subject: string;
        htmlBody?: string;
        textBody?: string;
        fromAddress?: string;
        replyTo?: string;
    }): Promise<{
        status: string;
        provider: string;
        message?: string;
        messageId?: string;
    }>;
    /**
     * Send a one-time-password email for the v1 registration / sign-in flow.
     *
     * POST /api/v1/auth/otp/send  (app-level Basic auth)
     *
     * This is the canonical email-OTP endpoint that accepts `email` + `app_uuid`
     * (UUID string). It mirrors `send_otp(email, app_uuid)` in the Rust SDK.
     *
     * **Not** the same as {@link sendOtp} (phone-OTP) or {@link sendOtpEmail}
     * (existing alias that also calls this endpoint). Prefer `sendOtpEmail` if
     * you are already using it; `sendOtpV1` is the name-aligned canonical form.
     *
     * Flow: `sendOtpV1` → `verifyOtpV1` → `finalizeRegistration`
     */
    sendOtpV1(email: string, appUuid: string): Promise<void>;
    /**
     * Verify an email OTP and obtain a `TokenPair` whose `token` is the
     * `signup_token` for `finalizeRegistration`.
     *
     * POST /api/v1/auth/otp/verify  (app-level Basic auth)
     *
     * Mirrors `verify_otp(email, otp, app_uuid)` in the Rust SDK.
     * `verifyOtpV1` is the name-aligned canonical form; `verifyOtpEmail` is the
     * existing method that does the same thing.
     */
    verifyOtpV1(email: string, otp: string, appUuid: string): Promise<TokenPair>;
    /**
     * Refresh an access token using the refresh token from a prior
     * `verifyOtpV1` / `verifyOtpEmail` / `finalizeRegistration` call.
     *
     * POST /api/app/auth/refresh
     *
     * Mirrors `refresh_token(refresh_token)` in the Rust SDK.
     * Returns a new `AccessToken` (with a possibly rotated refresh token).
     *
     * @param refreshToken The refresh token string from a prior `TokenPair`.
     */
    refreshToken(refreshToken: string): Promise<AccessToken>;
    /**
     * Check whether the authenticated user (identified by the SDK's bearer) has
     * access to `featureKey`.
     *
     * POST /api/entitlements/check  →  `{ data: EntitlementResult }`
     *
     * Mirrors `check_entitlement(bearer, feature_key)` in the Rust SDK.
     * The request body uses `feature_key` (not `feature` — see divergence note
     * in parity-audit.md).
     *
     * The pre-existing `entitlementsCheck(feature, orgUuid?)` method remains
     * unchanged; this is the canonical name-aligned variant.
     */
    checkEntitlement(featureKey: string): Promise<EntitlementResult>;
    /**
     * Batch-check multiple feature keys in one call.
     *
     * POST /api/entitlements/check/batch  →  `{ data: Record<string, EntitlementResult> }`
     *
     * Mirrors `check_entitlements(bearer, feature_keys)` in the Rust SDK.
     * The request body uses `feature_keys: string[]` (not `checks: [...]` — see
     * divergence note in parity-audit.md).
     *
     * The pre-existing `entitlementsCheckBatch(checks)` method remains
     * unchanged; this is the canonical name-aligned variant.
     */
    checkEntitlements(featureKeys: string[]): Promise<Record<string, EntitlementResult>>;
    /**
     * Return all effective entitlements for the authenticated user.
     *
     * GET /api/entitlements/effective  →  `{ data: EffectiveEntitlement[] }`
     *
     * Mirrors `effective_entitlements(bearer)` in the Rust SDK.
     * The pre-existing `entitlementsEffective()` returns `Record<string, unknown>`;
     * this canonical variant returns a typed `EffectiveEntitlement[]`.
     */
    effectiveEntitlements(): Promise<EffectiveEntitlement[]>;
    /**
     * Preview the price (with tax / discount / region) for a given `price_id`.
     *
     * POST /api/pricing/preview  →  `{ data: PricingPreview }`
     *
     * Mirrors `pricing_preview(bearer, req)` in the Rust SDK.
     * The pre-existing `pricingPreview(payload: Record<string,unknown>)` remains
     * unchanged; this canonical variant accepts the typed `PricingPreviewRequest`
     * and returns a typed `PricingPreview`.
     */
    pricingPreviewTyped(req: PricingPreviewRequest): Promise<PricingPreview>;
    /**
     * Lock a signed price quote (10-minute TTL). Pass `quote_id` to
     * `checkoutSessionTyped` to guarantee the price the user saw.
     *
     * POST /api/pricing/quote  →  `{ data: unknown }`
     *
     * Mirrors `pricing_quote(bearer, req)` in the Rust SDK.
     */
    pricingQuoteTyped(req: PricingPreviewRequest): Promise<unknown>;
    /**
     * Create a checkout session. Blocked for sandbox credentials on the backend.
     *
     * POST /api/pricing/checkout-session  →  `{ data: CheckoutSession }`
     *
     * Mirrors `checkout_session(bearer, req)` in the Rust SDK.
     */
    checkoutSessionTyped(req: CheckoutSessionRequest): Promise<CheckoutSession>;
    /**
     * Get the authenticated user's wallet balance and budget.
     *
     * GET /api/wallet  →  `{ data: WalletSummary }`
     *
     * Mirrors `wallet(bearer)` in the Rust SDK.
     * The pre-existing `getWallet()` returns `Record<string,unknown>` (untyped);
     * this canonical variant returns a typed `WalletSummary`.
     */
    walletSummary(): Promise<WalletSummary>;
    /**
     * List wallet transactions (deposits + withdrawals) with pagination.
     *
     * GET /api/wallet/transactions?limit={limit}&offset={offset}
     *    →  `{ data: WalletTransaction[] }`
     *
     * Mirrors `wallet_transactions(bearer, limit, offset)` in the Rust SDK.
     *
     * @param limit   Max rows to return (default 20).
     * @param offset  Zero-based offset for pagination (default 0).
     */
    walletTransactions(limit?: number, offset?: number): Promise<WalletTransaction[]>;
    /**
     * List the authenticated user's subscriptions.
     *
     * GET /api/subscriptions  →  `{ data: SubscriptionItem[] }`
     *
     * Mirrors `subscriptions(bearer)` in the Rust SDK.
     */
    listSubscriptions(): Promise<SubscriptionItem[]>;
    /**
     * Create a subscription for a price.
     *
     * POST /api/subscriptions  →  `{ data: SubscriptionItem }`
     *
     * Mirrors `create_subscription(bearer, body)` in the Rust SDK.
     *
     * @param body  Subscription creation payload (at minimum `{ price_id: number }`).
     */
    createSubscription(body: Record<string, unknown>): Promise<SubscriptionItem>;
    /**
     * Cancel a subscription by its integer ID.
     *
     * DELETE /api/subscriptions/{subscriptionId}
     *
     * Mirrors `cancel_subscription(bearer, subscription_id)` in the Rust SDK.
     */
    cancelSubscription(subscriptionId: number): Promise<void>;
    /**
     * Get the authenticated user's billing history (invoices).
     *
     * GET /api/billing/history  →  `{ data: Invoice[] }`
     *
     * Mirrors `billing_history(bearer)` in the Rust SDK.
     * The pre-existing `getBillingHistory()` returns `Record<string,unknown>`;
     * this canonical variant returns `Invoice[]`.
     */
    billingHistory(): Promise<Invoice[]>;
    /**
     * Report a metered usage event for billing reconciliation.
     *
     * POST /api/usage/report  (uses the SDK's bearer — app-server token obtained
     * via the client-credentials grant; mirrors the Rust SDK's HTTP Basic auth
     * model at the application level).
     *
     * Mirrors `report_usage(event)` in the Rust SDK.
     * The pre-existing `usageReport(payload)` accepts `Record<string,unknown>`;
     * this canonical variant accepts the typed `UsageEvent`.
     */
    reportUsage(event: UsageEvent): Promise<void>;
    /**
     * Ingest an analytics event on behalf of the authenticated user.
     *
     * POST /api/analytics/events
     *
     * Mirrors `ingest_event(bearer, event)` in the Rust SDK.
     * The pre-existing `ingestAnalyticsEvent(event)` accepts
     * `Record<string,unknown>`; this canonical variant accepts the typed
     * `AnalyticsEvent` and returns `void`.
     */
    ingestEvent(event: AnalyticsEvent): Promise<void>;
    /**
     * Get analytics overview for an app (uses the SDK's app-server bearer).
     *
     * GET /api/analytics/apps/{appUuid}/overview?period={period}
     *
     * Mirrors `app_analytics_overview(app_uuid, period)` in the Rust SDK.
     * The pre-existing `analyticsAppOverview(appUuid)` does not accept a period;
     * this canonical variant adds the required `period` parameter.
     */
    appAnalyticsOverview(appUuid: string, period: string): Promise<Record<string, unknown>>;
    /**
     * Get analytics overview for an org.
     *
     * GET /api/analytics/organizations/{orgUuid}/overview?period={period}
     *
     * Mirrors `org_analytics_overview(bearer, org_uuid, period)` in the Rust SDK.
     * The pre-existing `analyticsOrgOverview(orgUuid)` does not accept a period;
     * this canonical variant adds the required `period` parameter.
     */
    orgAnalyticsOverview(orgUuid: string, period: string): Promise<Record<string, unknown>>;
    /**
     * List active teams in an org (typed).
     *
     * GET /api/organizations/{orgUuid}/teams  →  `{ data: TeamItem[] }`
     *
     * Mirrors `org_teams(bearer, org_uuid)` in the Rust SDK.
     * The pre-existing `listOrgTeams(orgUuid)` returns `unknown[]`; this
     * canonical variant returns the typed `TeamItem[]`.
     */
    orgTeams(orgUuid: string): Promise<TeamItem[]>;
    /**
     * List teams a user is a member of (typed).
     *
     * GET /api/users/{userUuid}/teams  →  `{ data: TeamItem[] }`
     *
     * Mirrors `user_teams(bearer, user_uuid)` in the Rust SDK.
     * The pre-existing `getUserTeams(userUuid)` returns `unknown[]`; this
     * canonical variant returns the typed `TeamItem[]`.
     */
    userTeams(userUuid: string): Promise<TeamItem[]>;
    /**
     * List apps the authenticated user belongs to.
     *
     * GET /api/me/apps  →  `{ data: AppEntry[] }`
     *
     * Mirrors `my_apps(bearer)` in the Rust SDK.
     */
    myApps(): Promise<AppEntry[]>;
    /**
     * List orgs within an app that the user belongs to.
     *
     * GET /api/apps/{appUuid}/organizations  →  `{ data: OrgEntry[] }`
     *
     * Mirrors `app_orgs(bearer, app_uuid)` in the Rust SDK.
     */
    appOrgs(appUuid: string): Promise<OrgEntry[]>;
    /**
     * Get live/sandbox credential info for an app (admin only).
     *
     * GET /api/apps/{appUuid}/credentials  →  `{ data: AppCredentialsResponse }`
     *
     * Mirrors `app_credentials(bearer, app_uuid)` in the Rust SDK.
     */
    appCredentials(appUuid: string): Promise<AppCredentialsResponse>;
    /**
     * Enable sandbox mode for an app.
     *
     * PATCH /api/apps/{appUuid}  body: `{ sandbox_enabled: true }`
     *
     * Mirrors `enable_sandbox(bearer, app_uuid)` in the Rust SDK.
     */
    enableSandbox(appUuid: string): Promise<void>;
    /**
     * Rotate credentials for a given environment (`"live"` or `"sandbox"`).
     *
     * POST /api/apps/{appUuid}/credentials/{environment}/rotate
     *    →  `{ data: unknown }`
     *
     * Mirrors `rotate_credentials(bearer, app_uuid, environment)` in the Rust SDK.
     */
    rotateCredentials(appUuid: string, environment: string): Promise<unknown>;
}
