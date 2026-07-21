import { ButtrbaseError } from './errors.js';
import type {
  CouponValidation,
  GiftCardValidation,
  GiftCardRedemption,
  MagicLinkSend,
  MagicLinkSendOptions,
  MagicLinkVerify,
  MfaStatus,
  MfaEnrollment,
  OrgSignResponse,
  Jwk,
  SecretGet,
  SecretSummary,
  StepUpResponse,
  ElevationGrant,
  SpiffeSvidResponse,
  AuthEvent,
  ReencryptResponse,
  RevokeSessionResponse,
  OrgMetrics,
  Credential,
  CredentialListResponse,
  CreateCredentialResponse,
  RotateSecretResponse,
  SandboxResetResponse,
  InviteAcceptRequest,
  InviteAcceptResponse,
  OrgCheckResponse,
  SuperuserResponse,
  CheckOrgNameResponse,
  ClientCredentialsTokenResponse,
  TokenPair,
  FinalizeRegistrationRequest,
  RegistrationResult,
  CreateInvitationRequest,
  InvitationResponse,
  InvitationPreview,
  AcceptInvitationResponse,
  InvitationListItem,
  ContactRequest,
  ContactUsRequest,
  ContactSubmitResponse,
  GeoResponse,
  OAuthProvider,
  OAuthConfigSummary,
  CreateOAuthConfigInput,
  UpdateOAuthConfigInput,
  AppRpConfig,
  UpdateAppRpConfigInput,
  AuditLogQuery,
  AuditRow,
  PasskeyRegistrationChallenge,
  PasskeyRegistrationComplete,
  PasskeyRegistrationResult,
  PasskeyAuthChallenge,
  PasskeyAuthComplete,
  PasskeyListItem,
  ScopeContextRequest,
  ScopeContextResponse,
  DeviceItem,
  RevokeDeviceResponse,
  TenantHome,
  WebhookEndpoint,
  WebhookDelivery,
  // Parity additions (0.6.0)
  AccessToken,
  EntitlementResult,
  EffectiveEntitlement,
  WalletSummary,
  WalletTransaction,
  SubscriptionItem,
  PricingPreviewRequest,
  PricingPreview,
  CheckoutSessionRequest,
  CheckoutSession,
  UsageEvent,
  AnalyticsEvent,
  AppEntry,
  OrgEntry,
  AppCredentialsResponse,
  Invoice,
  TeamItem,
} from './types.js';

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

const DEFAULT_BASE_URL = 'https://stagingapi.buttrbase.com';
const DEFAULT_MAX_RETRIES = 3;
const DEFAULT_RETRY_BASE_DELAY_MS = 500;
// Refresh a client-credentials token this many seconds before it actually
// expires, so an in-flight request never races the expiry boundary.
const TOKEN_REFRESH_SKEW_SECONDS = 30;
// HTTP statuses safe to retry: gateway/cold-start (the app never processed the
// request, so even non-idempotent methods are safe) plus rate-limiting.
const RETRYABLE_STATUSES = new Set([429, 502, 503, 504]);

export class ButtrbaseClient {
  private clientId: string;
  private clientSecret: string;
  /** Current bearer token used for authenticated requests, if any. */
  private accessToken: string | undefined;
  /**
   * Epoch ms at which the client-credentials token should be considered stale
   * and re-fetched (already adjusted for the refresh skew). `undefined` when
   * the current token did not come from the client-credentials grant (e.g. a
   * constructor-supplied `accessToken` or a `login` bearer), so it is never
   * auto-refreshed.
   */
  private accessTokenExpiresAt: number | undefined;
  /** De-dupes concurrent client-credentials grants into a single request. */
  private tokenRequest: Promise<string> | undefined;
  private baseUrl: string;
  private fetchImpl: typeof fetch;
  private maxRetries: number;
  private retryBaseDelayMs: number;

  constructor(opts: ButtrbaseClientOptions) {
    if (!opts.clientId) throw new Error('clientId is required');
    
    this.clientId = opts.clientId;
    this.clientSecret = opts.clientSecret ?? '';
    this.accessToken = opts.accessToken;
    this.baseUrl = (opts.baseUrl ?? DEFAULT_BASE_URL).replace(/\/+$/, '');
    const f = opts.fetch ?? globalThis.fetch;
    if (!f) throw new Error('No fetch implementation available');
    this.fetchImpl = f.bind(globalThis);
    this.maxRetries = Math.max(0, opts.maxRetries ?? DEFAULT_MAX_RETRIES);
    this.retryBaseDelayMs = Math.max(0, opts.retryBaseDelayMs ?? DEFAULT_RETRY_BASE_DELAY_MS);
  }

  // ===== Client-credentials token grant =====

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
  async authenticate(): Promise<ClientCredentialsTokenResponse> {
    const res = await this.request<ClientCredentialsTokenResponse>(
      'POST',
      '/api/v1/auth/token',
      {
        auth: false,
        body: {
          grant_type: 'client_credentials',
          client_id: this.clientId,
          client_secret: this.clientSecret,
        },
      },
    );
    this.accessToken = res.access_token;
    // Only auto-refresh tokens we minted ourselves; a finite `expires_in`
    // schedules the refresh, otherwise leave the token non-expiring.
    if (typeof res.expires_in === 'number' && Number.isFinite(res.expires_in)) {
      const ttlMs = Math.max(0, res.expires_in - TOKEN_REFRESH_SKEW_SECONDS) * 1000;
      this.accessTokenExpiresAt = Date.now() + ttlMs;
    } else {
      this.accessTokenExpiresAt = undefined;
    }
    return res;
  }

  /**
   * Ensure a usable bearer is present, fetching one via the client-credentials
   * grant when none is set or the cached one has reached its refresh deadline.
   * Concurrent callers share a single in-flight grant. Returns the bearer.
   */
  private async ensureAccessToken(signal?: AbortSignal): Promise<string> {
    const fresh =
      this.accessToken !== undefined &&
      (this.accessTokenExpiresAt === undefined || Date.now() < this.accessTokenExpiresAt);
    if (fresh) return this.accessToken as string;

    if (!this.tokenRequest) {
      this.tokenRequest = this.authenticate()
        .then((res) => res.access_token)
        .finally(() => {
          this.tokenRequest = undefined;
        });
    }
    // Surface an abort promptly without disturbing the shared grant.
    if (signal) {
      return Promise.race([
        this.tokenRequest,
        new Promise<string>((_, reject) => {
          if (signal.aborted) {
            reject(signal.reason ?? new DOMException('Aborted', 'AbortError'));
            return;
          }
          signal.addEventListener(
            'abort',
            () => reject(signal.reason ?? new DOMException('Aborted', 'AbortError')),
            { once: true },
          );
        }),
      ]);
    }
    return this.tokenRequest;
  }

  /** Sleep for `ms`, rejecting early if the (optional) signal aborts. */
  private static sleep(ms: number, signal?: AbortSignal): Promise<void> {
    return new Promise((resolve, reject) => {
      if (signal?.aborted) {
        reject(signal.reason ?? new DOMException('Aborted', 'AbortError'));
        return;
      }
      const timer = setTimeout(() => {
        signal?.removeEventListener('abort', onAbort);
        resolve();
      }, ms);
      const onAbort = () => {
        clearTimeout(timer);
        reject(signal?.reason ?? new DOMException('Aborted', 'AbortError'));
      };
      signal?.addEventListener('abort', onAbort, { once: true });
    });
  }

  /** True when a thrown fetch error represents an abort rather than a network failure. */
  private static isAbortError(err: unknown): boolean {
    return (
      err instanceof DOMException ? err.name === 'AbortError' : (err as { name?: string })?.name === 'AbortError'
    );
  }

  /**
   * Compute the delay before the next retry. Honors a `Retry-After` header
   * (delta-seconds or HTTP-date) when present; otherwise uses exponential
   * backoff with full jitter, capped at base*8.
   */
  private retryDelayMs(attempt: number, retryAfter: string | null): number {
    if (retryAfter) {
      const trimmed = retryAfter.trim();
      const asSeconds = Number(trimmed);
      if (Number.isFinite(asSeconds)) return Math.max(0, asSeconds * 1000);
      const asDate = Date.parse(trimmed);
      if (!Number.isNaN(asDate)) return Math.max(0, asDate - Date.now());
    }
    const ceiling = this.retryBaseDelayMs * Math.min(2 ** attempt, 8);
    // Full jitter: a random value in [0, ceiling].
    return Math.round(Math.random() * ceiling);
  }

  private async request<T>(
    method: string,
    path: string,
    opts: { body?: unknown; auth?: boolean; query?: Record<string, unknown>; signal?: AbortSignal; headers?: Record<string, string> } = {},
  ): Promise<T> {
    const auth = opts.auth ?? true;
    let url = `${this.baseUrl}${path}`;
    if (opts.query) {
      const qs = new URLSearchParams();
      for (const [k, v] of Object.entries(opts.query)) {
        if (v === undefined || v === null) continue;
        if (Array.isArray(v)) for (const item of v) qs.append(k, String(item));
        else qs.append(k, String(v));
      }
      const s = qs.toString();
      if (s) url += `?${s}`;
    }
    const headers: Record<string, string> = { Accept: 'application/json' };
    if (auth) {
      // Lazily obtain (or refresh) a bearer via the client-credentials grant
      // when none is set or the cached one is due for refresh.
      const token = await this.ensureAccessToken(opts.signal);
      headers.Authorization = `Bearer ${token}`;
    }
    let body: BodyInit | undefined;
    if (opts.body !== undefined) {
      headers['Content-Type'] = 'application/json';
      body = JSON.stringify(opts.body);
    }
    const signal = opts.signal;

    // Attempts: 1 initial + up to `maxRetries` retries.
    for (let attempt = 0; ; attempt++) {
      const isLastAttempt = attempt >= this.maxRetries;
      let res: Response;
      try {
        res = await this.fetchImpl(url, { method, headers, body, signal });
      } catch (err) {
        // Never retry an explicit abort; surface it immediately.
        if (ButtrbaseClient.isAbortError(err) || signal?.aborted) throw err;
        // Network/connection error (fetch threw): retry if attempts remain.
        if (isLastAttempt) throw err;
        await ButtrbaseClient.sleep(this.retryDelayMs(attempt, null), signal);
        continue;
      }

      if (!res.ok && RETRYABLE_STATUSES.has(res.status) && !isLastAttempt) {
        const retryAfter = res.headers?.get?.('retry-after') ?? null;
        // Drain the body so the connection can be reused before retrying.
        try {
          await res.text();
        } catch {
          /* ignore */
        }
        await ButtrbaseClient.sleep(this.retryDelayMs(attempt, retryAfter), signal);
        continue;
      }

      const text = await res.text();
      let parsed: unknown = undefined;
      if (text) {
        try {
          parsed = JSON.parse(text);
        } catch {
          parsed = text;
        }
      }
      if (!res.ok) {
        let detail = res.statusText || 'request failed';
        if (parsed && typeof parsed === 'object' && 'detail' in (parsed as Record<string, unknown>)) {
          const d = (parsed as Record<string, unknown>).detail;
          if (typeof d === 'string') detail = d;
          else detail = JSON.stringify(d);
        } else if (typeof parsed === 'string' && parsed) {
          detail = parsed;
        }
        throw new ButtrbaseError(res.status, detail, parsed);
      }
      return parsed as T;
    }
  }

  validateCoupon(
    code: string,
    opts: { cartLabels?: string[]; productId?: number } = {},
  ): Promise<CouponValidation> {
    const body: Record<string, unknown> = { code };
    if (opts.cartLabels !== undefined) body.cart_labels = opts.cartLabels;
    if (opts.productId !== undefined) body.product_id = opts.productId;
    return this.request<CouponValidation>('POST', '/v1/coupons/validate', { body });
  }

  validateGiftCard(code: string): Promise<GiftCardValidation> {
    return this.request<GiftCardValidation>('POST', '/v1/gift-cards/validate', { body: { code } });
  }

  redeemGiftCard(
    code: string,
    amountCents: number,
    userId?: number,
  ): Promise<GiftCardRedemption> {
    const body: Record<string, unknown> = { code, amount_cents: amountCents };
    if (userId !== undefined) body.user_id = userId;
    return this.request<GiftCardRedemption>('POST', '/v1/gift-cards/redeem', { body });
  }

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
  sendMagicLink(
    email: string,
    opts: MagicLinkSendOptions = {},
  ): Promise<MagicLinkSend> {
    const body: Record<string, unknown> = { email };
    if (opts.appUuid !== undefined) body.app_uuid = opts.appUuid;
    if (opts.redirectTo !== undefined) body.redirect_to = opts.redirectTo;
    if (opts.orgUuid !== undefined) body.org_uuid = opts.orgUuid;
    return this.request<MagicLinkSend>('POST', '/api/auth/magic-link/send', { body, auth: false });
  }

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
  verifyMagicLink(token: string): Promise<MagicLinkVerify> {
    return this.request<MagicLinkVerify>('POST', '/api/auth/magic-link/verify', { body: { token }, auth: false });
  }

  mfaStatus(): Promise<MfaStatus> {
    return this.request<MfaStatus>('GET', '/v1/auth/mfa/status');
  }

  mfaEnroll(label?: string): Promise<MfaEnrollment> {
    const body: Record<string, unknown> = {};
    if (label !== undefined) body.label = label;
    return this.request<MfaEnrollment>('POST', '/v1/auth/mfa/enroll', { body });
  }

  mfaActivate(code: string): Promise<{ status: string }> {
    return this.request<{ status: string }>('POST', '/v1/auth/mfa/activate', { body: { code } });
  }

  orgSign(
    orgUuid: string,
    claims: Record<string, unknown>,
    opts: { ttlSeconds?: number } = {},
  ): Promise<OrgSignResponse> {
    const body: Record<string, unknown> = { claims };
    if (opts.ttlSeconds !== undefined) body.ttl_seconds = opts.ttlSeconds;
    return this.request<OrgSignResponse>('POST', `/v1/orgs/${encodeURIComponent(orgUuid)}/sign`, {
      body,
    });
  }

  orgJwks(orgUuid: string): Promise<{ keys: Jwk[] }> {
    return this.request<{ keys: Jwk[] }>(
      'GET',
      `/v1/orgs/${encodeURIComponent(orgUuid)}/.well-known/jwks.json`,
      { auth: false },
    );
  }

  getSecret(orgUuid: string, name: string): Promise<SecretGet> {
    return this.request<SecretGet>(
      'GET',
      `/v1/orgs/${encodeURIComponent(orgUuid)}/secrets/${encodeURIComponent(name)}`,
    );
  }

  putSecret(
    orgUuid: string,
    name: string,
    value: string,
    description?: string,
  ): Promise<SecretSummary> {
    const body: Record<string, unknown> = { value };
    if (description !== undefined) body.description = description;
    return this.request<SecretSummary>(
      'PUT',
      `/v1/orgs/${encodeURIComponent(orgUuid)}/secrets/${encodeURIComponent(name)}`,
      { body },
    );
  }

  // ===== Zero-trust endpoints =====

  /**
   * POST /api/auth/step-up — exchange MFA code for a short-lived elevated
   * access token (~5 min). On success, the SDK's bearer is REPLACED with
   * the returned `access_token` so subsequent admin/JIT calls are elevated.
   */
  async authStepUp(code: string, recovery = false): Promise<StepUpResponse> {
    const body: Record<string, unknown> = { code, recovery };
    const res = await this.request<StepUpResponse>('POST', '/api/auth/step-up', { body });
    if (res && res.access_token) {
      this.accessToken = res.access_token;
      // This bearer carries elevated/user context — don't let the
      // client-credentials refresh logic silently replace it.
      this.accessTokenExpiresAt = undefined;
    }
    return res;
  }

  // ----- JIT elevation (admin) — all require an active step-up session -----

  /** POST /api/admin/orgs/{org}/elevation/request */
  elevationRequest(
    orgUuid: string,
    scope: string,
    opts: { reason?: string; ttlSeconds?: number } = {},
  ): Promise<ElevationGrant> {
    const body: Record<string, unknown> = { scope };
    if (opts.reason !== undefined) body.reason = opts.reason;
    if (opts.ttlSeconds !== undefined) body.ttl_seconds = opts.ttlSeconds;
    return this.request<ElevationGrant>(
      'POST',
      `/api/admin/orgs/${encodeURIComponent(orgUuid)}/elevation/request`,
      { body },
    );
  }

  /**
   * POST /api/admin/orgs/{org}/elevation/{grant}/approve.
   * Server returns 403 if the approver is the same admin as the requester.
   */
  elevationApprove(orgUuid: string, grantUuid: string): Promise<ElevationGrant> {
    return this.request<ElevationGrant>(
      'POST',
      `/api/admin/orgs/${encodeURIComponent(orgUuid)}/elevation/${encodeURIComponent(grantUuid)}/approve`,
    );
  }

  /** GET /api/admin/orgs/{org}/elevation */
  elevationList(orgUuid: string, status?: string): Promise<ElevationGrant[]> {
    const query: Record<string, unknown> = {};
    if (status !== undefined) query.status = status;
    return this.request<ElevationGrant[]>(
      'GET',
      `/api/admin/orgs/${encodeURIComponent(orgUuid)}/elevation`,
      { query },
    );
  }

  /** POST /api/admin/orgs/{org}/spiffe/svid — issue an X.509 SVID. */
  spiffeIssueSvid(
    orgUuid: string,
    workloadPath: string,
    opts: { ttlSeconds?: number } = {},
  ): Promise<SpiffeSvidResponse> {
    const body: Record<string, unknown> = { workload_path: workloadPath };
    if (opts.ttlSeconds !== undefined) body.ttl_seconds = opts.ttlSeconds;
    return this.request<SpiffeSvidResponse>(
      'POST',
      `/api/admin/orgs/${encodeURIComponent(orgUuid)}/spiffe/svid`,
      { body },
    );
  }

  /** GET /api/admin/orgs/{org}/auth-events — context-aware audit events. */
  listAuthEvents(
    orgUuid: string,
    opts: { userUuid?: string; limit?: number } = {},
  ): Promise<AuthEvent[]> {
    const query: Record<string, unknown> = { limit: opts.limit ?? 50 };
    if (opts.userUuid !== undefined) query.user_uuid = opts.userUuid;
    return this.request<AuthEvent[]>(
      'GET',
      `/api/admin/orgs/${encodeURIComponent(orgUuid)}/auth-events`,
      { query },
    );
  }

  /** POST /api/admin/orgs/{org}/reencrypt/secrets */
  reencryptSecrets(orgUuid: string): Promise<ReencryptResponse> {
    return this.request<ReencryptResponse>(
      'POST',
      `/api/admin/orgs/${encodeURIComponent(orgUuid)}/reencrypt/secrets`,
    );
  }

  /** POST /api/admin/orgs/{org}/reencrypt/signing-keys */
  reencryptSigningKeys(orgUuid: string): Promise<ReencryptResponse> {
    return this.request<ReencryptResponse>(
      'POST',
      `/api/admin/orgs/${encodeURIComponent(orgUuid)}/reencrypt/signing-keys`,
    );
  }

  /** POST /api/admin/orgs/{org}/reencrypt/mtls-ca */
  reencryptMtlsCa(orgUuid: string): Promise<ReencryptResponse> {
    return this.request<ReencryptResponse>(
      'POST',
      `/api/admin/orgs/${encodeURIComponent(orgUuid)}/reencrypt/mtls-ca`,
    );
  }

  /** POST /api/admin/sessions/revoke — add `jti` to the revocation list. */
  revokeSession(jti: string, ttlSeconds?: number): Promise<RevokeSessionResponse> {
    const body: Record<string, unknown> = { jti };
    if (ttlSeconds !== undefined) body.ttl_seconds = ttlSeconds;
    return this.request<RevokeSessionResponse>(
      'POST',
      '/api/admin/sessions/revoke',
      { body },
    );
  }

  /** GET /api/admin/orgs/{org}/metrics */
  getOrgMetrics(orgUuid: string): Promise<OrgMetrics> {
    return this.request<OrgMetrics>(
      'GET',
      `/api/admin/orgs/${encodeURIComponent(orgUuid)}/metrics`,
    );
  }

  // ===== Credentials (OAuth2 client-credentials) =====
  //
  // These manage the `client_id` / `client_secret` pairs that are the single
  // app-server credential for the platform. Pass the resulting pair to the
  // `ButtrbaseClient` constructor as `clientId` / `clientSecret`.

  /** GET /credentials — list all client credentials for the authenticated account. */
  listCredentials(): Promise<CredentialListResponse> {
    return this.request<CredentialListResponse>('GET', '/credentials');
  }

  /**
   * POST /credentials — create a new OAuth2 client credential.
   * Returns 201 with the full credential including `client_secret` (shown only once).
   */
  createCredential(name: string, description?: string): Promise<CreateCredentialResponse> {
    const body: Record<string, unknown> = { name };
    if (description !== undefined) body.description = description;
    return this.request<CreateCredentialResponse>('POST', '/credentials', { body });
  }

  /** GET /credentials/:id — fetch a credential by ID (no `client_secret`). */
  getCredential(id: string): Promise<Credential> {
    return this.request<Credential>('GET', `/credentials/${encodeURIComponent(id)}`);
  }

  /** DELETE /credentials/:id — permanently delete a credential (returns void on 204). */
  async deleteCredential(id: string): Promise<void> {
    await this.request<unknown>('DELETE', `/credentials/${encodeURIComponent(id)}`);
  }

  /**
   * POST /credentials/:id/rotate-secret — rotate the client secret for a credential.
   * Returns new `client_id` and `client_secret`.
   */
  rotateCredentialSecret(id: string): Promise<RotateSecretResponse> {
    return this.request<RotateSecretResponse>(
      'POST',
      `/credentials/${encodeURIComponent(id)}/rotate-secret`,
    );
  }

  // ===== Sandbox =====

  /**
   * POST /api/sandbox/reset — reset the sandbox environment.
   * Optionally scoped to a specific org via `orgUuid`.
   */
  resetSandbox(orgUuid?: string): Promise<SandboxResetResponse> {
    const body: Record<string, unknown> = {};
    if (orgUuid !== undefined) body.org_uuid = orgUuid;
    return this.request<SandboxResetResponse>('POST', '/api/sandbox/reset', { body });
  }

  // ===== Auth =====

  /**
   * POST /api/auth/register — register a new user for an app.
   *
   * BREAKING: previously this accepted an `orgName` slug; now `appUuid` (a UUID
   * string) is required. The backend rejects requests without a valid `app_uuid`.
   *
   * @deprecated Use sendOtpEmail → verifyOtpEmail → finalizeRegistration instead.
   */
  register(
    email: string,
    password: string,
    appUuid: string,
    opts: { firstName?: string; lastName?: string } = {},
  ): Promise<Record<string, unknown>> {
    const body: Record<string, unknown> = { email, password, app_uuid: appUuid };
    if (opts.firstName !== undefined) body.first_name = opts.firstName;
    if (opts.lastName !== undefined) body.last_name = opts.lastName;
    return this.request<Record<string, unknown>>('POST', '/api/auth/register', { body, auth: false });
  }

  /**
   * POST /api/auth/login — stores access_token on success.
   *
   * BREAKING: previously this accepted an `orgName` slug; now `appUuid` (a UUID
   * string) is required. The backend rejects requests without a valid `app_uuid`.
   */
  async login(email: string, password: string, appUuid: string): Promise<Record<string, unknown>> {
    const body: Record<string, unknown> = { email, password, app_uuid: appUuid };
    const res = await this.request<Record<string, unknown>>('POST', '/api/auth/login', { body, auth: false });
    if (res && typeof res.access_token === 'string') {
      this.accessToken = res.access_token;
      // A user bearer — not subject to client-credentials auto-refresh.
      this.accessTokenExpiresAt = undefined;
    }
    return res;
  }

  /**
   * POST /api/auth/organizations/lookup — look up an organization by domain or slug.
   *
   * BREAKING: now requires `appUuid` (a UUID string). The backend rejects requests
   * without a valid `app_uuid`.
   */
  lookupOrganization(
    appUuid: string,
    opts: { domain?: string; slug?: string } = {},
  ): Promise<Record<string, unknown>> {
    const body: Record<string, unknown> = { app_uuid: appUuid };
    if (opts.domain !== undefined) body.domain = opts.domain;
    if (opts.slug !== undefined) body.slug = opts.slug;
    return this.request<Record<string, unknown>>(
      'POST',
      '/api/auth/organizations/lookup',
      { body, auth: false },
    );
  }

  /** GET /api/auth/organizations/{org_uuid}/login-options */
  getLoginOptions(orgUuid: string): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>(
      'GET',
      `/api/auth/organizations/${encodeURIComponent(orgUuid)}/login-options`,
      { auth: false },
    );
  }

  /** GET /api/auth/status */
  getStatus(): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>('GET', '/api/auth/status');
  }

  /** GET /api/profile */
  getProfile(): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>('GET', '/api/profile');
  }

  /** PUT /api/profile */
  updateProfile(data: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>('PUT', '/api/profile', { body: data });
  }

  /** GET /api/auth/orgs-by-domain/{domain} */
  getOrgByDomain(domain: string): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>(
      'GET',
      `/api/auth/orgs-by-domain/${encodeURIComponent(domain)}`,
      { auth: false },
    );
  }

  // ===== OTP =====

  /**
   * POST /api/auth/otp — send an OTP code to a phone number.
   *
   * BREAKING: now requires `appUuid` (a UUID string). The backend rejects requests
   * without a valid `app_uuid`.
   */
  sendOtp(phone: string, appUuid: string): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>(
      'POST',
      '/api/auth/otp',
      { body: { phone, app_uuid: appUuid }, auth: false },
    );
  }

  /**
   * @deprecated Use {@link sendOtp} instead. This alias exists for back-compat
   * during the cross-SDK naming normalisation and will be removed in v1.0.
   */
  otpSend(phone: string, appUuid: string): Promise<Record<string, unknown>> {
    return this.sendOtp(phone, appUuid);
  }

  /**
   * POST /api/auth/otp/verify — verify an OTP code.
   *
   * BREAKING: now requires `appUuid` (a UUID string). The backend rejects requests
   * without a valid `app_uuid`.
   */
  verifyOtp(phone: string, code: string, appUuid: string): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>(
      'POST',
      '/api/auth/otp/verify',
      { body: { phone, code, app_uuid: appUuid }, auth: false },
    );
  }

  /**
   * @deprecated Use {@link verifyOtp} instead. Removed in v1.0.
   */
  otpVerify(phone: string, code: string, appUuid: string): Promise<Record<string, unknown>> {
    return this.verifyOtp(phone, code, appUuid);
  }

  // ===== MFA (extended) =====

  /** POST /api/auth/mfa/totp/verify */
  mfaVerify(code: string): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>('POST', '/api/auth/mfa/totp/verify', { body: { code } });
  }

  /** POST /api/auth/mfa/totp/challenge */
  mfaChallenge(): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>('POST', '/api/auth/mfa/totp/challenge');
  }

  /** DELETE /api/auth/mfa/totp */
  mfaDisable(): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>('DELETE', '/api/auth/mfa/totp');
  }

  /** POST /api/auth/mfa/recovery-codes */
  mfaGenerateRecoveryCodes(): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>('POST', '/api/auth/mfa/recovery-codes');
  }

  /** POST /api/auth/mfa/recovery-codes/redeem */
  mfaRedeemRecoveryCode(code: string): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>('POST', '/api/auth/mfa/recovery-codes/redeem', { body: { code } });
  }

  // ===== Passkeys (WebAuthn) =====
  //
  // The backend exposes the WebAuthn ceremonies in two halves: a `begin`
  // endpoint that returns a challenge plus an opaque server-signed state blob,
  // and a `complete` endpoint that the caller hits with the browser's response
  // plus the same state blob (stateless flow — server-side state is not
  // tracked between requests).
  //
  // These SDK methods are thin HTTP wrappers; the actual WebAuthn JSON is
  // passed through unchanged so the browser's `navigator.credentials.create`
  // / `navigator.credentials.get` APIs can consume / produce it directly.

  /**
   * POST /api/passkeys/register/begin — start passkey registration.
   * Requires an authenticated caller (you add a passkey to an existing account).
   * Pass the returned `challenge` to `navigator.credentials.create({publicKey: challenge.publicKey})`
   * and the `registration_state` back to {@link passkeyRegisterComplete}.
   */
  async passkeyRegisterBegin(): Promise<PasskeyRegistrationChallenge> {
    const res = await this.request<{ data: PasskeyRegistrationChallenge }>(
      'POST',
      '/api/passkeys/register/begin',
    );
    return res.data;
  }

  /**
   * POST /api/passkeys/register/complete — finish passkey registration.
   * `credential` is the WebAuthn `RegisterPublicKeyCredential` produced by the
   * browser; `registration_state` is the opaque blob returned by
   * {@link passkeyRegisterBegin}.
   */
  async passkeyRegisterComplete(
    body: PasskeyRegistrationComplete,
  ): Promise<PasskeyRegistrationResult> {
    const res = await this.request<{ data: PasskeyRegistrationResult }>(
      'POST',
      '/api/passkeys/register/complete',
      { body },
    );
    return res.data;
  }

  /**
   * POST /api/passkeys/authenticate/begin — start passkey authentication.
   * Anonymous; no Authorization header required. Pass the returned `challenge`
   * to `navigator.credentials.get({publicKey: challenge.publicKey})`.
   */
  async passkeyAuthenticateBegin(): Promise<PasskeyAuthChallenge> {
    const res = await this.request<{ data: PasskeyAuthChallenge }>(
      'POST',
      '/api/passkeys/authenticate/begin',
      { auth: false },
    );
    return res.data;
  }

  /**
   * POST /api/passkeys/authenticate/complete — finish passkey authentication.
   * Returns the session payload (shape currently unstable on the backend —
   * `unknown` here, callers should narrow at the call site).
   */
  passkeyAuthenticateComplete(body: PasskeyAuthComplete): Promise<unknown> {
    return this.request<unknown>(
      'POST',
      '/api/passkeys/authenticate/complete',
      { body, auth: false },
    );
  }

  /**
   * GET /api/v1/me/passkeys — list the signed-in user's enrolled passkeys.
   * Returns the rows in descending `created_at` order. Each row carries a
   * `credential_uuid` (for revocation) and a 12-char `credential_id_prefix`
   * for display.
   */
  listMyPasskeys(): Promise<PasskeyListItem[]> {
    return this.request<PasskeyListItem[]>('GET', '/api/v1/me/passkeys');
  }

  /**
   * DELETE /api/v1/me/passkeys/{credentialUuid} — revoke one of the
   * signed-in user's passkeys. The backend enforces the owner check; passing
   * a UUID owned by another user returns 404.
   */
  deleteMyPasskey(credentialUuid: string): Promise<{ status: string }> {
    return this.request<{ status: string }>(
      'DELETE',
      `/api/v1/me/passkeys/${encodeURIComponent(credentialUuid)}`,
    );
  }

  // ===== SSO =====

  /** GET /api/auth/oidc/{connection_uuid}/authorize */
  oidcAuthorizeUrl(connectionUuid: string): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>(
      'GET',
      `/api/auth/oidc/${encodeURIComponent(connectionUuid)}/authorize`,
      { auth: false },
    );
  }

  /** GET /api/auth/saml/{connection_uuid}/authorize */
  samlAuthorizeUrl(connectionUuid: string): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>(
      'GET',
      `/api/auth/saml/${encodeURIComponent(connectionUuid)}/authorize`,
      { auth: false },
    );
  }

  // ===== Users =====

  /** GET /api/users */
  listUsers(filters?: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>('GET', '/api/users', { query: filters });
  }

  /** GET /api/users/{user_uuid}/level */
  getUserLevel(userUuid: string): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>(
      'GET',
      `/api/users/${encodeURIComponent(userUuid)}/level`,
    );
  }

  /** POST /api/users/{user_uuid}/level */
  setUserLevel(userUuid: string, userType: string): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>(
      'POST',
      `/api/users/${encodeURIComponent(userUuid)}/level`,
      { body: { user_type: userType } },
    );
  }

  /** PUT /api/users/{user_uuid}/status */
  updateUserStatus(userUuid: string, active: boolean): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>(
      'PUT',
      `/api/users/${encodeURIComponent(userUuid)}/status`,
      { body: { active } },
    );
  }

  /** PUT /api/users/{user_uuid}/role */
  updateUserRole(userUuid: string, role: string): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>(
      'PUT',
      `/api/users/${encodeURIComponent(userUuid)}/role`,
      { body: { role } },
    );
  }

  // ===== Org Security =====

  /** GET /api/organizations/{org_uuid}/security-settings */
  getSecuritySettings(orgUuid: string): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>(
      'GET',
      `/api/organizations/${encodeURIComponent(orgUuid)}/security-settings`,
    );
  }

  /** PUT /api/organizations/{org_uuid}/security-settings */
  updateSecuritySettings(orgUuid: string, settings: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>(
      'PUT',
      `/api/organizations/${encodeURIComponent(orgUuid)}/security-settings`,
      { body: settings },
    );
  }

  /** GET /api/organizations/{org_uuid}/sso-connections */
  listSsoConnections(orgUuid: string): Promise<unknown[]> {
    return this.request<unknown[]>(
      'GET',
      `/api/organizations/${encodeURIComponent(orgUuid)}/sso-connections`,
    );
  }

  /** POST /api/organizations/{org_uuid}/sso-connections */
  createSsoConnection(
    orgUuid: string,
    provider: string,
    name: string,
    config: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>(
      'POST',
      `/api/organizations/${encodeURIComponent(orgUuid)}/sso-connections`,
      { body: { provider, name, config } },
    );
  }

  /** PUT /api/organizations/{org_uuid}/sso-connections/{connection_uuid} */
  updateSsoConnection(
    orgUuid: string,
    connectionUuid: string,
    data: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>(
      'PUT',
      `/api/organizations/${encodeURIComponent(orgUuid)}/sso-connections/${encodeURIComponent(connectionUuid)}`,
      { body: data },
    );
  }

  /** DELETE /api/organizations/{org_uuid}/sso-connections/{connection_uuid} */
  async deleteSsoConnection(orgUuid: string, connectionUuid: string): Promise<void> {
    await this.request<unknown>(
      'DELETE',
      `/api/organizations/${encodeURIComponent(orgUuid)}/sso-connections/${encodeURIComponent(connectionUuid)}`,
    );
  }

  /** GET /api/organizations/{org_uuid}/audit-events */
  listAuditEvents(orgUuid: string): Promise<unknown[]> {
    return this.request<unknown[]>(
      'GET',
      `/api/organizations/${encodeURIComponent(orgUuid)}/audit-events`,
    );
  }

  /** GET /api/organizations/{org_uuid}/audit-events/export */
  exportAuditEvents(orgUuid: string): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>(
      'GET',
      `/api/organizations/${encodeURIComponent(orgUuid)}/audit-events/export`,
    );
  }

  // ===== Branding =====

  /** GET /api/organizations/{org_uuid}/branding */
  getBranding(orgUuid: string): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>(
      'GET',
      `/api/organizations/${encodeURIComponent(orgUuid)}/branding`,
    );
  }

  /** PUT /api/organizations/{org_uuid}/branding */
  updateBranding(orgUuid: string, branding: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>(
      'PUT',
      `/api/organizations/${encodeURIComponent(orgUuid)}/branding`,
      { body: branding },
    );
  }

  // ===== Sessions =====

  /** GET /api/organizations/{org_uuid}/session-inventory */
  orgSessionInventory(orgUuid: string): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>(
      'GET',
      `/api/organizations/${encodeURIComponent(orgUuid)}/session-inventory`,
    );
  }

  /** POST /api/organizations/{org_uuid}/revoke-all-sessions */
  orgRevokeAllSessions(orgUuid: string): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>(
      'POST',
      `/api/organizations/${encodeURIComponent(orgUuid)}/revoke-all-sessions`,
    );
  }

  /** GET /api/devices/{device_uuid}/accounts */
  listDeviceAccounts(deviceUuid: string): Promise<unknown[]> {
    return this.request<unknown[]>(
      'GET',
      `/api/devices/${encodeURIComponent(deviceUuid)}/accounts`,
    );
  }

  /** POST /api/devices/{device_uuid}/accounts */
  addDeviceAccount(deviceUuid: string, data: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>(
      'POST',
      `/api/devices/${encodeURIComponent(deviceUuid)}/accounts`,
      { body: data },
    );
  }

  /** DELETE /api/devices/{device_uuid}/accounts */
  async deleteDeviceAccounts(deviceUuid: string): Promise<void> {
    await this.request<unknown>(
      'DELETE',
      `/api/devices/${encodeURIComponent(deviceUuid)}/accounts`,
    );
  }

  /** DELETE /api/devices/{device_uuid}/accounts/{account_uuid} */
  async deleteDeviceAccount(deviceUuid: string, accountUuid: string): Promise<void> {
    await this.request<unknown>(
      'DELETE',
      `/api/devices/${encodeURIComponent(deviceUuid)}/accounts/${encodeURIComponent(accountUuid)}`,
    );
  }

  /** POST /api/devices/{device_uuid}/active-account */
  switchDeviceActiveAccount(deviceUuid: string, accountUuid: string): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>(
      'POST',
      `/api/devices/${encodeURIComponent(deviceUuid)}/active-account`,
      { body: { account_uuid: accountUuid } },
    );
  }

  /** GET /api/devices/{device_uuid}/session-inventory */
  deviceSessionInventory(deviceUuid: string): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>(
      'GET',
      `/api/devices/${encodeURIComponent(deviceUuid)}/session-inventory`,
    );
  }

  /** POST /api/devices/{device_uuid}/revoke-all */
  revokeAllDeviceSessions(deviceUuid: string): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>(
      'POST',
      `/api/devices/${encodeURIComponent(deviceUuid)}/revoke-all`,
    );
  }

  // ===== Service Identities =====

  /** GET /api/organizations/{org_uuid}/service-identities */
  listServiceIdentities(orgUuid: string): Promise<unknown[]> {
    return this.request<unknown[]>(
      'GET',
      `/api/organizations/${encodeURIComponent(orgUuid)}/service-identities`,
    );
  }

  /** POST /api/organizations/{org_uuid}/service-identities */
  createServiceIdentity(orgUuid: string, payload: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>(
      'POST',
      `/api/organizations/${encodeURIComponent(orgUuid)}/service-identities`,
      { body: payload },
    );
  }

  /** DELETE /api/organizations/{org_uuid}/service-identities/{key_uuid} */
  async deleteServiceIdentity(orgUuid: string, keyUuid: string): Promise<void> {
    await this.request<unknown>(
      'DELETE',
      `/api/organizations/${encodeURIComponent(orgUuid)}/service-identities/${encodeURIComponent(keyUuid)}`,
    );
  }

  /** POST /api/organizations/{org_uuid}/service-identities/automation-token */
  createServiceIdentityAutomationToken(orgUuid: string, payload: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>(
      'POST',
      `/api/organizations/${encodeURIComponent(orgUuid)}/service-identities/automation-token`,
      { body: payload },
    );
  }

  // ===== Entitlements =====

  /** POST /api/entitlements/check */
  entitlementsCheck(feature: string, orgUuid?: string): Promise<Record<string, unknown>> {
    const body: Record<string, unknown> = { feature };
    if (orgUuid !== undefined) body.org_uuid = orgUuid;
    return this.request<Record<string, unknown>>('POST', '/api/entitlements/check', { body });
  }

  /** POST /api/entitlements/check/batch */
  entitlementsCheckBatch(checks: unknown[]): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>('POST', '/api/entitlements/check/batch', { body: { checks } });
  }

  /** GET /api/entitlements/effective */
  entitlementsEffective(): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>('GET', '/api/entitlements/effective');
  }

  /** POST /api/admin/entitlements/explain */
  adminEntitlementsExplain(payload: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>('POST', '/api/admin/entitlements/explain', { body: payload });
  }

  // ===== Pricing =====

  /** POST /api/pricing/preview */
  pricingPreview(payload: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>('POST', '/api/pricing/preview', { body: payload });
  }

  /** POST /api/pricing/quote */
  pricingQuote(payload: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>('POST', '/api/pricing/quote', { body: payload });
  }

  /** POST /api/pricing/checkout-session */
  pricingCheckoutSession(payload: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>('POST', '/api/pricing/checkout-session', { body: payload });
  }

  /** POST /api/admin/pricing/explain */
  adminPricingExplain(payload: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>('POST', '/api/admin/pricing/explain', { body: payload });
  }

  /** POST /api/catalog/pricing/preview */
  catalogPricingPreview(payload: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>('POST', '/api/catalog/pricing/preview', { body: payload });
  }

  // ===== Coupons Admin =====

  /** GET /api/admin/products/{product_id}/coupons */
  adminListProductCoupons(productId: string): Promise<unknown[]> {
    return this.request<unknown[]>(
      'GET',
      `/api/admin/products/${encodeURIComponent(productId)}/coupons`,
    );
  }

  /** POST /api/admin/products/{product_id}/coupons */
  adminCreateProductCoupon(productId: string, coupon: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>(
      'POST',
      `/api/admin/products/${encodeURIComponent(productId)}/coupons`,
      { body: coupon },
    );
  }

  /** PUT /api/admin/products/{product_id}/coupons/{coupon_id} */
  adminUpdateProductCoupon(
    productId: string,
    couponId: string,
    coupon: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>(
      'PUT',
      `/api/admin/products/${encodeURIComponent(productId)}/coupons/${encodeURIComponent(couponId)}`,
      { body: coupon },
    );
  }

  /** DELETE /api/admin/products/{product_id}/coupons/{coupon_id} */
  async adminDeleteProductCoupon(productId: string, couponId: string): Promise<void> {
    await this.request<unknown>(
      'DELETE',
      `/api/admin/products/${encodeURIComponent(productId)}/coupons/${encodeURIComponent(couponId)}`,
    );
  }

  // ===== Labels =====

  /** PUT /api/admin/coupons/{id}/labels */
  setCouponLabels(couponId: string, labels: string[]): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>(
      'PUT',
      `/api/admin/coupons/${encodeURIComponent(couponId)}/labels`,
      { body: { labels } },
    );
  }

  /** POST /api/admin/coupons/{id}/labels */
  addCouponLabel(couponId: string, label: string): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>(
      'POST',
      `/api/admin/coupons/${encodeURIComponent(couponId)}/labels`,
      { body: { label } },
    );
  }

  /** DELETE /api/admin/coupons/{id}/labels/{label} */
  async removeCouponLabel(couponId: string, label: string): Promise<void> {
    await this.request<unknown>(
      'DELETE',
      `/api/admin/coupons/${encodeURIComponent(couponId)}/labels/${encodeURIComponent(label)}`,
    );
  }

  /** PUT /api/admin/products/{id}/tags */
  setProductTags(productId: string, tags: string[]): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>(
      'PUT',
      `/api/admin/products/${encodeURIComponent(productId)}/tags`,
      { body: { tags } },
    );
  }

  /** POST /api/admin/products/{id}/tags */
  addProductTag(productId: string, tag: string): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>(
      'POST',
      `/api/admin/products/${encodeURIComponent(productId)}/tags`,
      { body: { tag } },
    );
  }

  /** DELETE /api/admin/products/{id}/tags/{tag} */
  async removeProductTag(productId: string, tag: string): Promise<void> {
    await this.request<unknown>(
      'DELETE',
      `/api/admin/products/${encodeURIComponent(productId)}/tags/${encodeURIComponent(tag)}`,
    );
  }

  // ===== Analytics =====

  /** POST /api/analytics/events */
  ingestAnalyticsEvent(event: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>('POST', '/api/analytics/events', { body: event });
  }

  /** GET /api/analytics/apps/{app_uuid}/overview */
  analyticsAppOverview(appUuid: string): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>(
      'GET',
      `/api/analytics/apps/${encodeURIComponent(appUuid)}/overview`,
    );
  }

  /** GET /api/analytics/organizations/{org_uuid}/overview */
  analyticsOrgOverview(orgUuid: string): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>(
      'GET',
      `/api/analytics/organizations/${encodeURIComponent(orgUuid)}/overview`,
    );
  }

  // ===== Teams =====

  /** POST /api/teams */
  createTeam(payload: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>('POST', '/api/teams', { body: payload });
  }

  /** GET /api/organizations/{org_uuid}/teams */
  listOrgTeams(orgUuid: string): Promise<unknown[]> {
    return this.request<unknown[]>(
      'GET',
      `/api/organizations/${encodeURIComponent(orgUuid)}/teams`,
    );
  }

  /** GET /api/teams/org/{org_uuid}/inactive */
  listInactiveTeams(orgUuid: string): Promise<unknown[]> {
    return this.request<unknown[]>(
      'GET',
      `/api/teams/org/${encodeURIComponent(orgUuid)}/inactive`,
    );
  }

  /** POST /api/teams/lifecycle/{team_uuid}/reactivate */
  reactivateTeam(teamUuid: string): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>(
      'POST',
      `/api/teams/lifecycle/${encodeURIComponent(teamUuid)}/reactivate`,
    );
  }

  /** DELETE /api/teams/lifecycle/{team_uuid} */
  async archiveTeam(teamUuid: string): Promise<void> {
    await this.request<unknown>(
      'DELETE',
      `/api/teams/lifecycle/${encodeURIComponent(teamUuid)}`,
    );
  }

  /** GET /api/teams/{team_uuid}/members */
  listTeamMembers(teamUuid: string): Promise<unknown[]> {
    return this.request<unknown[]>(
      'GET',
      `/api/teams/${encodeURIComponent(teamUuid)}/members`,
    );
  }

  /** POST /api/teams/{team_uuid}/members */
  addTeamMember(teamUuid: string, userUuid: string): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>(
      'POST',
      `/api/teams/${encodeURIComponent(teamUuid)}/members`,
      { body: { user_uuid: userUuid } },
    );
  }

  /** DELETE /api/teams/{team_uuid}/members/{user_uuid} */
  async removeTeamMember(teamUuid: string, userUuid: string): Promise<void> {
    await this.request<unknown>(
      'DELETE',
      `/api/teams/${encodeURIComponent(teamUuid)}/members/${encodeURIComponent(userUuid)}`,
    );
  }

  /** GET /api/teams/{team_uuid}/observers */
  listTeamObservers(teamUuid: string): Promise<unknown[]> {
    return this.request<unknown[]>(
      'GET',
      `/api/teams/${encodeURIComponent(teamUuid)}/observers`,
    );
  }

  /** POST /api/teams/{team_uuid}/observers */
  addTeamObserver(teamUuid: string, userUuid: string): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>(
      'POST',
      `/api/teams/${encodeURIComponent(teamUuid)}/observers`,
      { body: { user_uuid: userUuid } },
    );
  }

  /** DELETE /api/teams/{team_uuid}/observers/{user_uuid} */
  async removeTeamObserver(teamUuid: string, userUuid: string): Promise<void> {
    await this.request<unknown>(
      'DELETE',
      `/api/teams/${encodeURIComponent(teamUuid)}/observers/${encodeURIComponent(userUuid)}`,
    );
  }

  /** GET /api/users/{user_uuid}/teams */
  getUserTeams(userUuid: string): Promise<unknown[]> {
    return this.request<unknown[]>(
      'GET',
      `/api/users/${encodeURIComponent(userUuid)}/teams`,
    );
  }

  /** GET /api/users/{user_uuid}/observed-teams */
  getUserObservedTeams(userUuid: string): Promise<unknown[]> {
    return this.request<unknown[]>(
      'GET',
      `/api/users/${encodeURIComponent(userUuid)}/observed-teams`,
    );
  }

  // ===== Org Features =====

  /** GET /api/organizations/{org_uuid}/features */
  listOrgFeatures(orgUuid: string): Promise<unknown[]> {
    return this.request<unknown[]>(
      'GET',
      `/api/organizations/${encodeURIComponent(orgUuid)}/features`,
    );
  }

  /** POST /api/organizations/{org_uuid}/features */
  setOrgFeature(orgUuid: string, feature: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>(
      'POST',
      `/api/organizations/${encodeURIComponent(orgUuid)}/features`,
      { body: feature },
    );
  }

  /** DELETE /api/organizations/{org_uuid}/features/{feature_id} */
  async removeOrgFeature(orgUuid: string, featureId: string): Promise<void> {
    await this.request<unknown>(
      'DELETE',
      `/api/organizations/${encodeURIComponent(orgUuid)}/features/${encodeURIComponent(featureId)}`,
    );
  }

  // ===== Roles =====

  /** GET /api/roles */
  listRoles(): Promise<unknown[]> {
    return this.request<unknown[]>('GET', '/api/roles');
  }

  /** GET /api/roles/permissions */
  listAllPermissions(): Promise<unknown[]> {
    return this.request<unknown[]>('GET', '/api/roles/permissions');
  }

  /** GET /api/roles/{role_id}/permissions */
  getRolePermissions(roleId: string): Promise<unknown[]> {
    return this.request<unknown[]>(
      'GET',
      `/api/roles/${encodeURIComponent(roleId)}/permissions`,
    );
  }

  /** PUT /api/roles/{role_id}/permissions */
  updateRolePermissions(roleId: string, permissions: unknown[]): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>(
      'PUT',
      `/api/roles/${encodeURIComponent(roleId)}/permissions`,
      { body: { permissions } },
    );
  }

  // ===== RBAC =====

  /** GET /api/v2/products/{product_id}/permissions */
  getProductPermissions(productId: string): Promise<unknown[]> {
    return this.request<unknown[]>(
      'GET',
      `/api/v2/products/${encodeURIComponent(productId)}/permissions`,
    );
  }

  /** POST /api/v2/products/{product_id}/roles */
  createProductRole(productId: string, roleData: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>(
      'POST',
      `/api/v2/products/${encodeURIComponent(productId)}/roles`,
      { body: roleData },
    );
  }

  /** GET /api/v2/organizations/{org_uuid}/products/{product_id}/roles */
  getAssignableRoles(orgUuid: string, productId: string): Promise<unknown[]> {
    return this.request<unknown[]>(
      'GET',
      `/api/v2/organizations/${encodeURIComponent(orgUuid)}/products/${encodeURIComponent(productId)}/roles`,
    );
  }

  /** PUT /api/v2/organizations/{org_uuid}/users/{user_uuid}/role */
  assignRoleToUser(orgUuid: string, userUuid: string, roleId: string): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>(
      'PUT',
      `/api/v2/organizations/${encodeURIComponent(orgUuid)}/users/${encodeURIComponent(userUuid)}/role`,
      { body: { role_id: roleId } },
    );
  }

  // ===== Billing =====

  /** POST /api/billing/checkout */
  checkout(priceId: string, couponCode?: string, addOns?: unknown[]): Promise<Record<string, unknown>> {
    const body: Record<string, unknown> = { price_id: priceId };
    if (couponCode !== undefined) body.coupon_code = couponCode;
    if (addOns !== undefined) body.add_ons = addOns;
    return this.request<Record<string, unknown>>('POST', '/api/billing/checkout', { body });
  }

  /** GET /api/billing/history */
  getBillingHistory(): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>('GET', '/api/billing/history');
  }

  /** GET /api/billing/invoices */
  listInvoices(): Promise<unknown[]> {
    return this.request<unknown[]>('GET', '/api/billing/invoices');
  }

  /** GET /api/billing/config/{provider} */
  getProviderConfig(provider: string): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>(
      'GET',
      `/api/billing/config/${encodeURIComponent(provider)}`,
    );
  }

  /** POST /api/billing/subscriptions/add-on */
  addAddOn(addOn: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>('POST', '/api/billing/subscriptions/add-on', { body: addOn });
  }

  /** GET /api/wallet */
  getWallet(): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>('GET', '/api/wallet');
  }

  // ===== Environments =====

  /** GET /api/environments */
  listEnvironments(): Promise<unknown[]> {
    return this.request<unknown[]>('GET', '/api/environments');
  }

  // ===== Plaid =====

  /** POST /api/plaid/create-link-token */
  plaidCreateLinkToken(payload: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>('POST', '/api/plaid/create-link-token', { body: payload });
  }

  /** POST /api/plaid/exchange-public-token */
  plaidExchangePublicToken(publicToken: string): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>('POST', '/api/plaid/exchange-public-token', {
      body: { public_token: publicToken },
    });
  }

  /** GET /api/plaid/accounts */
  plaidAccounts(): Promise<unknown[]> {
    return this.request<unknown[]>('GET', '/api/plaid/accounts');
  }

  // ===== Usage =====

  /** POST /api/usage/report */
  usageReport(payload: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>('POST', '/api/usage/report', { body: payload });
  }

  // ===== Help =====

  /** GET /api/help */
  helpRoot(): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>('GET', '/api/help', { auth: false });
  }

  /** GET /api/help/search?q={query} */
  helpSearch(query: string): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>('GET', '/api/help/search', { query: { q: query }, auth: false });
  }

  /** GET /api/help/categories/{slug} */
  helpCategory(slug: string): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>(
      'GET',
      `/api/help/categories/${encodeURIComponent(slug)}`,
      { auth: false },
    );
  }

  /** GET /api/help/articles/{slug} */
  helpArticle(slug: string): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>(
      'GET',
      `/api/help/articles/${encodeURIComponent(slug)}`,
      { auth: false },
    );
  }

  // ===== Search =====

  /** POST /api/v2/search/index */
  searchIndex(payload: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>('POST', '/api/v2/search/index', { body: payload });
  }

  /** POST /api/v2/search/query */
  searchQuery(q: string, filters?: Record<string, unknown>): Promise<Record<string, unknown>> {
    const body: Record<string, unknown> = { q };
    if (filters !== undefined) body.filters = filters;
    return this.request<Record<string, unknown>>('POST', '/api/v2/search/query', { body });
  }

  /** POST /api/v2/search/chat */
  searchChat(q: string, options?: Record<string, unknown>): Promise<Record<string, unknown>> {
    const body: Record<string, unknown> = { q };
    if (options !== undefined) Object.assign(body, options);
    return this.request<Record<string, unknown>>('POST', '/api/v2/search/chat', { body });
  }

  // ===== AI Gateway =====

  /** POST to gateway.buttrbase.com — AI chat completions via org gateway. */
  async aiChatCompletions(
    orgUuid: string,
    provider: string,
    payload: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    const url = `https://gateway.buttrbase.com/api/v1/organizations/${encodeURIComponent(orgUuid)}/providers/${encodeURIComponent(provider)}/chat/completions`;
    if (!this.accessToken) {
      throw new Error(
        'No access token available for the AI gateway. Obtain a bearer via a ' +
          'token-issuing flow (e.g. login) or pass `accessToken` to the constructor first.',
      );
    }
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      Accept: 'application/json',
      Authorization: `Bearer ${this.accessToken}`,
    };
    const res = await this.fetchImpl(url, {
      method: 'POST',
      headers,
      body: JSON.stringify(payload),
    });
    const text = await res.text();
    let parsed: unknown = undefined;
    if (text) {
      try {
        parsed = JSON.parse(text);
      } catch {
        parsed = text;
      }
    }
    if (!res.ok) {
      let detail = res.statusText || 'request failed';
      if (parsed && typeof parsed === 'object' && 'detail' in (parsed as Record<string, unknown>)) {
        const d = (parsed as Record<string, unknown>).detail;
        if (typeof d === 'string') detail = d;
        else detail = JSON.stringify(d);
      } else if (typeof parsed === 'string' && parsed) {
        detail = parsed;
      }
      throw new ButtrbaseError(res.status, detail, parsed);
    }
    return parsed as Record<string, unknown>;
  }

  // ===== Signing Keys (extended) =====

  /** GET /api/admin/organizations/{org_uuid}/signing-keys */
  listSigningKeys(orgUuid: string): Promise<unknown[]> {
    return this.request<unknown[]>(
      'GET',
      `/api/admin/organizations/${encodeURIComponent(orgUuid)}/signing-keys`,
    );
  }

  /** POST /api/admin/organizations/{org_uuid}/signing-keys/rotate */
  rotateSigningKeys(orgUuid: string): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>(
      'POST',
      `/api/admin/organizations/${encodeURIComponent(orgUuid)}/signing-keys/rotate`,
    );
  }

  /** GET /api/admin/organizations/{org_uuid}/signing-audit */
  listSigningAudit(orgUuid: string): Promise<unknown[]> {
    return this.request<unknown[]>(
      'GET',
      `/api/admin/organizations/${encodeURIComponent(orgUuid)}/signing-audit`,
    );
  }

  /** POST /api/orgs/{org_uuid}/sign-document */
  signDocument(orgUuid: string, document: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>(
      'POST',
      `/api/orgs/${encodeURIComponent(orgUuid)}/sign-document`,
      { body: document },
    );
  }

  // ===== mTLS CA =====

  /** GET /api/admin/organizations/{org_uuid}/certificate-authority */
  getCa(orgUuid: string): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>(
      'GET',
      `/api/admin/organizations/${encodeURIComponent(orgUuid)}/certificate-authority`,
    );
  }

  /** POST /api/admin/organizations/{org_uuid}/certificate-authority/init */
  initCa(orgUuid: string, config: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>(
      'POST',
      `/api/admin/organizations/${encodeURIComponent(orgUuid)}/certificate-authority/init`,
      { body: config },
    );
  }

  /** GET /api/admin/organizations/{org_uuid}/certificates */
  listCertificates(orgUuid: string): Promise<unknown[]> {
    return this.request<unknown[]>(
      'GET',
      `/api/admin/organizations/${encodeURIComponent(orgUuid)}/certificates`,
    );
  }

  /** POST /api/admin/organizations/{org_uuid}/certificates */
  issueCertificate(orgUuid: string, csr: string): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>(
      'POST',
      `/api/admin/organizations/${encodeURIComponent(orgUuid)}/certificates`,
      { body: { csr } },
    );
  }

  /** POST /api/admin/organizations/{org_uuid}/certificates/{serial}/revoke */
  revokeCertificate(orgUuid: string, serial: string): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>(
      'POST',
      `/api/admin/organizations/${encodeURIComponent(orgUuid)}/certificates/${encodeURIComponent(serial)}/revoke`,
    );
  }

  // ===== Zero Trust (extended) =====

  /** POST /api/admin/organizations/{org_uuid}/auth-events/purge */
  purgeAuthEvents(orgUuid: string): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>(
      'POST',
      `/api/admin/organizations/${encodeURIComponent(orgUuid)}/auth-events/purge`,
    );
  }

  /** GET /api/admin/organizations/{org_uuid}/kms-status */
  kmsStatus(orgUuid: string): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>(
      'GET',
      `/api/admin/organizations/${encodeURIComponent(orgUuid)}/kms-status`,
    );
  }

  /** PATCH /api/admin/organizations/{org_uuid}/sso/{connection_uuid}/saml-cert */
  samlCertRollover(
    orgUuid: string,
    connectionUuid: string,
    payload: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>(
      'PATCH',
      `/api/admin/organizations/${encodeURIComponent(orgUuid)}/sso/${encodeURIComponent(connectionUuid)}/saml-cert`,
      { body: payload },
    );
  }

  /** PATCH /api/admin/organizations/{org_uuid}/payment-settings */
  updatePaymentSettings(orgUuid: string, settings: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>(
      'PATCH',
      `/api/admin/organizations/${encodeURIComponent(orgUuid)}/payment-settings`,
      { body: settings },
    );
  }

  // ===== Secrets (extended) =====

  /** GET /api/admin/organizations/{org_uuid}/secrets */
  listSecrets(orgUuid: string): Promise<unknown[]> {
    return this.request<unknown[]>(
      'GET',
      `/api/admin/organizations/${encodeURIComponent(orgUuid)}/secrets`,
    );
  }

  /** DELETE /api/admin/organizations/{org_uuid}/secrets/{name} */
  async deleteSecret(orgUuid: string, name: string): Promise<void> {
    await this.request<unknown>(
      'DELETE',
      `/api/admin/organizations/${encodeURIComponent(orgUuid)}/secrets/${encodeURIComponent(name)}`,
    );
  }

  // ===== Admin Portal =====

  /** POST /api/admin/organizations/{org_uuid}/admin-portal/issue */
  adminPortalIssue(orgUuid: string): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>(
      'POST',
      `/api/admin/organizations/${encodeURIComponent(orgUuid)}/admin-portal/issue`,
    );
  }

  /** POST /api/admin-portal/exchange */
  adminPortalExchange(token: string): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>('POST', '/api/admin-portal/exchange', { body: { token } });
  }

  // ===== Domains =====

  /** GET /api/admin/organizations/{org_uuid}/domains */
  listDomains(orgUuid: string): Promise<unknown[]> {
    return this.request<unknown[]>(
      'GET',
      `/api/admin/organizations/${encodeURIComponent(orgUuid)}/domains`,
    );
  }

  /** POST /api/admin/organizations/{org_uuid}/domains */
  createDomain(orgUuid: string, domain: string): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>(
      'POST',
      `/api/admin/organizations/${encodeURIComponent(orgUuid)}/domains`,
      { body: { domain } },
    );
  }

  /** POST /api/admin/organizations/{org_uuid}/domains/{id}/verify */
  verifyDomain(orgUuid: string, domainId: string): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>(
      'POST',
      `/api/admin/organizations/${encodeURIComponent(orgUuid)}/domains/${encodeURIComponent(domainId)}/verify`,
    );
  }

  /** DELETE /api/admin/organizations/{org_uuid}/domains/{id} */
  async deleteDomain(orgUuid: string, domainId: string): Promise<void> {
    await this.request<unknown>(
      'DELETE',
      `/api/admin/organizations/${encodeURIComponent(orgUuid)}/domains/${encodeURIComponent(domainId)}`,
    );
  }

  // ===== Webhooks Admin =====

  /** GET /api/admin/organizations/{org_uuid}/webhook-endpoints */
  listWebhookEndpoints(orgUuid: string): Promise<unknown[]> {
    return this.request<unknown[]>(
      'GET',
      `/api/admin/organizations/${encodeURIComponent(orgUuid)}/webhook-endpoints`,
    );
  }

  /** POST /api/admin/organizations/{org_uuid}/webhook-endpoints */
  createWebhookEndpoint(orgUuid: string, url: string, events: string[]): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>(
      'POST',
      `/api/admin/organizations/${encodeURIComponent(orgUuid)}/webhook-endpoints`,
      { body: { url, events } },
    );
  }

  /** DELETE /api/admin/organizations/{org_uuid}/webhook-endpoints/{id} */
  async deleteWebhookEndpoint(orgUuid: string, endpointId: string): Promise<void> {
    await this.request<unknown>(
      'DELETE',
      `/api/admin/organizations/${encodeURIComponent(orgUuid)}/webhook-endpoints/${encodeURIComponent(endpointId)}`,
    );
  }

  /** GET /api/admin/organizations/{org_uuid}/webhook-deliveries */
  listOrgWebhookDeliveries(orgUuid: string): Promise<unknown[]> {
    return this.request<unknown[]>(
      'GET',
      `/api/admin/organizations/${encodeURIComponent(orgUuid)}/webhook-deliveries`,
    );
  }

  // ===== SCIM =====

  /** POST /api/admin/organizations/{org_uuid}/scim-tokens */
  issueScimToken(orgUuid: string): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>(
      'POST',
      `/api/admin/organizations/${encodeURIComponent(orgUuid)}/scim-tokens`,
    );
  }

  // ===== Payments =====

  /** POST /api/payments/checkout */
  createPaymentCheckout(
    amount: number,
    currency: string,
    country: string,
    orgUuid?: string,
  ): Promise<Record<string, unknown>> {
    const body: Record<string, unknown> = { amount, currency, country };
    if (orgUuid !== undefined) body.org_uuid = orgUuid;
    return this.request<Record<string, unknown>>('POST', '/api/payments/checkout', { body });
  }

  /** POST /api/payments/invoices/send */
  sendInvoice(
    amount: number,
    currency: string,
    appUuid: string,
    opts: { memo?: string; dueDate?: string } = {},
  ): Promise<Record<string, unknown>> {
    const body: Record<string, unknown> = { amount, currency, app_uuid: appUuid };
    if (opts.memo !== undefined) body.memo = opts.memo;
    if (opts.dueDate !== undefined) body.due_date = opts.dueDate;
    return this.request<Record<string, unknown>>('POST', '/api/payments/invoices/send', { body });
  }

  // ===== SMS =====

  /** POST /api/sms/send_sms */
  sendSms(
    phone: string,
    message: string,
    opts: { from?: string; orgUuid?: string } = {},
  ): Promise<Record<string, unknown>> {
    const body: Record<string, unknown> = { phone, message };
    if (opts.from !== undefined) body.from = opts.from;
    if (opts.orgUuid !== undefined) body.org_uuid = opts.orgUuid;
    return this.request<Record<string, unknown>>('POST', '/api/sms/send_sms', { body });
  }

  // ===== Email =====

  /** POST /api/email/verify-identity */
  verifyEmailIdentity(
    email: string,
    awsAccessKeyId: string,
    awsSecretAccessKey: string,
    awsRegion?: string,
  ): Promise<Record<string, unknown>> {
    const body: Record<string, unknown> = {
      email,
      aws_access_key_id: awsAccessKeyId,
      aws_secret_access_key: awsSecretAccessKey,
    };
    if (awsRegion !== undefined) body.aws_region = awsRegion;
    return this.request<Record<string, unknown>>('POST', '/api/email/verify-identity', { body });
  }

  // ===== Jobs & Notifications =====

  /** POST /api/v2/jobs/enqueue */
  enqueueJob(name: string, payload: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>('POST', '/api/v2/jobs/enqueue', { body: { name, payload } });
  }

  /** POST /api/v2/notifications/send */
  sendNotification(payload: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>('POST', '/api/v2/notifications/send', { body: payload });
  }

  /** GET /api/v2/notifications */
  listNotifications(): Promise<unknown[]> {
    return this.request<unknown[]>('GET', '/api/v2/notifications');
  }

  // ===== Custom Variables =====

  /** GET /api/v2/custom-variables/{key} */
  getCustomVariable(key: string): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>(
      'GET',
      `/api/v2/custom-variables/${encodeURIComponent(key)}`,
    );
  }

  /** POST /api/v2/custom-variables */
  setCustomVariable(key: string, value: string, scope?: string): Promise<Record<string, unknown>> {
    const body: Record<string, unknown> = { key, value };
    if (scope !== undefined) body.scope = scope;
    return this.request<Record<string, unknown>>('POST', '/api/v2/custom-variables', { body });
  }

  // ===== Webhooks (legacy) =====

  /** POST /api/v2/webhooks */
  registerWebhook(url: string, events: string[], orgUuid?: string): Promise<Record<string, unknown>> {
    const body: Record<string, unknown> = { url, events };
    if (orgUuid !== undefined) body.org_uuid = orgUuid;
    return this.request<Record<string, unknown>>('POST', '/api/v2/webhooks', { body });
  }

  // ===== Invite-based registration =====

  /** POST /api/auth/invite/accept */
  inviteAccept(req: InviteAcceptRequest): Promise<InviteAcceptResponse> {
    return this.request<InviteAcceptResponse>('POST', '/api/auth/invite/accept', { body: req, auth: false });
  }

  /** GET /api/auth/orgs/check?name={name} */
  checkOrgName(name: string): Promise<OrgCheckResponse> {
    return this.request<OrgCheckResponse>('GET', '/api/auth/orgs/check', { query: { name }, auth: false });
  }

  // ===== Registration 0.3.0+ =====

  /**
   * Send an email OTP for the 0.3.0 registration flow.
   * POST /api/v1/auth/otp/send
   * Flow: sendOtpEmail → verifyOtpEmail → finalizeRegistration
   */
  sendOtpEmail(email: string, appUuid: string): Promise<void> {
    return this.request<void>('POST', '/api/v1/auth/otp/send', {
      body: { email, app_uuid: appUuid },
      auth: false,
      headers: {
        'Authorization': 'Basic ' + Buffer.from(this.clientId + ':' + this.clientSecret).toString('base64'),
      }
    });
  }

  /**
   * Verify an email OTP. Returns a TokenPair whose `token` is the
   * signup_token for finalizeRegistration.
   * POST /api/v1/auth/otp/verify
   */
  verifyOtpEmail(email: string, otp: string, appUuid: string): Promise<TokenPair> {
    return this.request<TokenPair>('POST', '/api/v1/auth/otp/verify', {
      body: { email, otp, app_uuid: appUuid },
      auth: false,
    });
  }

  /**
   * Check whether an org name is available before registration.
   * POST /api/v1/auth/check-org-name
   */
  checkOrgNameV2(name: string): Promise<CheckOrgNameResponse> {
    return this.request<CheckOrgNameResponse>('POST', '/api/v1/auth/check-org-name', {
      body: { name },
      auth: false,
    });
  }

  /**
   * Complete user registration after OTP verification.
   * POST /api/v1/auth/finalize-registration
   * req.signup_token must be the token from verifyOtpEmail.
   */
  finalizeRegistration(req: FinalizeRegistrationRequest): Promise<RegistrationResult> {
    return this.request<RegistrationResult>('POST', '/api/v1/auth/finalize-registration', {
      body: req,
      auth: false,
    });
  }

  // ===== Invitations =====

  /**
   * Create an org invitation.
   * POST /api/organizations/{orgUuid}/invitations
   * The token in the response is shown once.
   */
  createInvitation(orgUuid: string, req: CreateInvitationRequest): Promise<InvitationResponse> {
    return this.request<InvitationResponse>(
      'POST',
      `/api/organizations/${orgUuid}/invitations`,
      { body: req, auth: true },
    );
  }

  /**
   * Preview an invitation by token (public, no auth).
   * GET /api/auth/invitations/{token}
   */
  previewInvitation(token: string): Promise<InvitationPreview> {
    return this.request<InvitationPreview>(
      'GET',
      `/api/auth/invitations/${encodeURIComponent(token)}`,
      { auth: false },
    );
  }

  /**
   * Accept an invitation for an already-authenticated user joining an
   * additional org. New users should use finalizeRegistration with
   * OrgChoice { type: 'accept_invite', invitation_token }.
   * POST /api/auth/invitations/{token}/accept
   */
  acceptInvitation(token: string): Promise<AcceptInvitationResponse> {
    return this.request<AcceptInvitationResponse>(
      'POST',
      `/api/auth/invitations/${encodeURIComponent(token)}/accept`,
      { auth: true },
    );
  }

  /**
   * List all invitations for an org.
   * GET /api/organizations/{orgUuid}/invitations
   */
  listInvitations(orgUuid: string): Promise<InvitationListItem[]> {
    return this.request<InvitationListItem[]>(
      'GET',
      `/api/organizations/${orgUuid}/invitations`,
      { auth: true },
    );
  }

  /**
   * Revoke a pending invitation by its integer ID.
   * DELETE /api/organizations/{orgUuid}/invitations/{invitationId}
   */
  revokeInvitation(orgUuid: string, invitationId: number): Promise<void> {
    return this.request<void>(
      'DELETE',
      `/api/organizations/${orgUuid}/invitations/${invitationId}`,
      { auth: true },
    );
  }

  /** GET /api/auth/superuser?email={email} */
  getSuperuserFlag(email: string): Promise<SuperuserResponse> {
    return this.request<SuperuserResponse>('GET', '/api/auth/superuser', { query: { email } });
  }

  // ===== Contact forms =====

  /** POST /api/contact */
  postContact(req: ContactRequest): Promise<ContactSubmitResponse> {
    return this.request<ContactSubmitResponse>('POST', '/api/contact', { body: req, auth: false });
  }

  /** POST /api/contact-us */
  postContactUs(req: ContactUsRequest): Promise<ContactSubmitResponse> {
    return this.request<ContactSubmitResponse>('POST', '/api/contact-us', { body: req, auth: false });
  }

  // ===== Geo / IP =====

  /** GET /api/geo/ip */
  getClientIp(): Promise<GeoResponse> {
    return this.request<GeoResponse>('GET', '/api/geo/ip', { auth: false });
  }

  // ===== OAuth start URL helper =====

  /**
   * Build the OAuth start URL for `GET /api/v1/auth/oauth/{provider}/start`.
   *
   * This is a pure URL builder — the caller is responsible for navigating the
   * browser to the returned URL (the backend responds with a 302 redirect to
   * the upstream identity provider, which `fetch` cannot follow safely).
   */
  oauthStartUrl(provider: OAuthProvider, appUuid: string, returnTo: string): string {
    const qs = new URLSearchParams({ app_uuid: appUuid, return_to: returnTo });
    return `${this.baseUrl}/api/v1/auth/oauth/${encodeURIComponent(provider)}/start?${qs.toString()}`;
  }

  // ===== OAuth config admin =====

  /** GET /api/v1/apps/{app_uuid}/oauth-configs — list configured OAuth providers (no secrets). */
  listOAuthConfigs(appUuid: string): Promise<OAuthConfigSummary[]> {
    return this.request<OAuthConfigSummary[]>(
      'GET',
      `/api/v1/apps/${encodeURIComponent(appUuid)}/oauth-configs`,
    );
  }

  /** POST /api/v1/apps/{app_uuid}/oauth-configs — register a new OAuth provider. */
  createOAuthConfig(appUuid: string, input: CreateOAuthConfigInput): Promise<OAuthConfigSummary> {
    return this.request<OAuthConfigSummary>(
      'POST',
      `/api/v1/apps/${encodeURIComponent(appUuid)}/oauth-configs`,
      { body: input },
    );
  }

  /**
   * PATCH /api/v1/apps/{app_uuid}/oauth-configs/{provider} — partially update
   * an OAuth provider config. `client_secret` is only rotated when present.
   */
  updateOAuthConfig(
    appUuid: string,
    provider: OAuthProvider,
    patch: UpdateOAuthConfigInput,
  ): Promise<OAuthConfigSummary> {
    return this.request<OAuthConfigSummary>(
      'PATCH',
      `/api/v1/apps/${encodeURIComponent(appUuid)}/oauth-configs/${encodeURIComponent(provider)}`,
      { body: patch },
    );
  }

  /** DELETE /api/v1/apps/{app_uuid}/oauth-configs/{provider} — remove an OAuth provider. */
  async deleteOAuthConfig(appUuid: string, provider: OAuthProvider): Promise<void> {
    await this.request<unknown>(
      'DELETE',
      `/api/v1/apps/${encodeURIComponent(appUuid)}/oauth-configs/${encodeURIComponent(provider)}`,
    );
  }

  // ===== Per-app WebAuthn relying-party config =====

  /**
   * GET /api/v1/apps/{app_uuid}/rp-config — fetch the per-app WebAuthn
   * relying-party config (RP id + allowed origins).
   * `rp_id` is `null` when the app inherits the deployment-wide env-var RP id.
   */
  getAppRpConfig(appUuid: string): Promise<AppRpConfig> {
    return this.request<AppRpConfig>(
      'GET',
      `/api/v1/apps/${encodeURIComponent(appUuid)}/rp-config`,
    );
  }

  /**
   * PATCH /api/v1/apps/{app_uuid}/rp-config — partially update the per-app
   * WebAuthn relying-party config. Omitted fields stay unchanged; `rp_id` set
   * to `null` would fall back to the env var, but this typed input cannot
   * express an explicit-null patch (known limitation — use raw JSON to clear).
   */
  updateAppRpConfig(appUuid: string, patch: UpdateAppRpConfigInput): Promise<AppRpConfig> {
    return this.request<AppRpConfig>(
      'PATCH',
      `/api/v1/apps/${encodeURIComponent(appUuid)}/rp-config`,
      { body: patch },
    );
  }

  // ===== App-level audit log =====

  /** GET /api/v1/apps/{app_uuid}/audit-log — read recent audit rows for an app. */
  readAuditLog(appUuid: string, opts: AuditLogQuery = {}): Promise<AuditRow[]> {
    const query: Record<string, unknown> = {};
    if (opts.limit !== undefined) query.limit = opts.limit;
    if (opts.action_prefix !== undefined) query.action_prefix = opts.action_prefix;
    return this.request<AuditRow[]>(
      'GET',
      `/api/v1/apps/${encodeURIComponent(appUuid)}/audit-log`,
      { query },
    );
  }

  // ===== Windowed scope re-mint (JIT) =====

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
  scopeContext(req: ScopeContextRequest): Promise<ScopeContextResponse> {
    return this.request<ScopeContextResponse>('POST', '/api/app/auth/scope-context', {
      body: { requested_scopes: req.requested_scopes },
    });
  }

  // ===== End-user device-key management (self-service) =====

  /**
   * GET /api/app/devices — list the caller's ACTIVE (non-revoked) device keys.
   * Authenticated end-user call, scoped to the verified token's user. Returns
   * only public-safe fields (no private key material).
   */
  async listDevices(): Promise<DeviceItem[]> {
    const res = await this.request<{ data: DeviceItem[] }>('GET', '/api/app/devices');
    return res.data;
  }

  /**
   * POST /api/app/devices/{device_uuid}/revoke — soft-revoke a device the caller
   * owns. Authenticated end-user call; ownership is enforced server-side, so a
   * device that does not exist, is already revoked, or belongs to another user
   * yields 404 (`ButtrbaseError`).
   */
  async revokeDevice(deviceUuid: string): Promise<RevokeDeviceResponse> {
    const res = await this.request<{ data: RevokeDeviceResponse }>(
      'POST',
      `/api/app/devices/${encodeURIComponent(deviceUuid)}/revoke`,
    );
    return res.data;
  }

  // ===== Tenant-home discovery =====

  /**
   * GET /api/tenant/home — resolve an ACTIVE tenant's home so a client can
   * target it directly. Public (no auth): the client is still figuring out
   * *where* to talk. Returns only public routing info; unknown or non-active
   * tenants yield 404 (`ButtrbaseError`). `appId` is optional.
   */
  async getTenantHome(orgUuid: string, appId?: number): Promise<TenantHome> {
    const query: Record<string, unknown> = { org_uuid: orgUuid };
    if (appId !== undefined) query.app_id = appId;
    const res = await this.request<{ data: TenantHome }>('GET', '/api/tenant/home', {
      query,
      auth: false,
    });
    return res.data;
  }

  // ===== Password reset =====

  /**
   * POST /api/auth/request-password-reset — send a password-reset email.
   * No API key required.
   */
  requestPasswordReset(email: string): Promise<{ message: string }> {
    return this.request<{ message: string }>('POST', '/api/auth/request-password-reset', {
      body: { email },
      auth: false,
    });
  }

  /**
   * POST /api/auth/reset-password — complete a password reset using the token
   * from the reset email. No API key required.
   */
  resetPassword(token: string, password: string): Promise<{ message: string }> {
    return this.request<{ message: string }>('POST', '/api/auth/reset-password', {
      body: { token, password },
      auth: false,
    });
  }

  // ===== Webhooks =====

  /** GET /api/v1/webhooks — list all webhook endpoints. */
  listWebhooks(): Promise<{ data: WebhookEndpoint[] }> {
    return this.request<{ data: WebhookEndpoint[] }>('GET', '/api/v1/webhooks');
  }

  /** POST /api/v1/webhooks — register a new webhook endpoint. */
  createWebhook(
    url: string,
    opts: { eventTypes?: string[]; signingSecret?: string; description?: string } = {},
  ): Promise<{ data: WebhookEndpoint }> {
    const body: Record<string, unknown> = { url };
    if (opts.eventTypes !== undefined) body.event_types = opts.eventTypes;
    if (opts.signingSecret !== undefined) body.signing_secret = opts.signingSecret;
    if (opts.description !== undefined) body.description = opts.description;
    return this.request<{ data: WebhookEndpoint }>('POST', '/api/v1/webhooks', { body });
  }

  /** DELETE /api/v1/webhooks/{id} — permanently remove a webhook endpoint. */
  async deleteWebhook(id: number): Promise<void> {
    await this.request<unknown>('DELETE', `/api/v1/webhooks/${id}`);
  }

  /** GET /api/v1/webhooks/{id}/deliveries — list deliveries for a webhook endpoint. */
  listWebhookDeliveries(webhookId: number): Promise<WebhookDelivery[]> {
    return this.request<WebhookDelivery[]>('GET', `/api/v1/webhooks/${webhookId}/deliveries`);
  }

  /** POST /api/v1/webhooks/{id}/deliveries/{deliveryId}/retry — retry a failed delivery. */
  retryWebhookDelivery(webhookId: number, deliveryId: number): Promise<{ status: string }> {
    return this.request<{ status: string }>(
      'POST',
      `/api/v1/webhooks/${webhookId}/deliveries/${deliveryId}/retry`,
      { body: {} },
    );
  }

  // ===== OAuth connection refresh =====

  /**
   * POST /v1/oauth/connections/{provider}/refresh — refresh an OAuth connection's
   * access token for the given provider.
   */
  refreshOAuthConnection(
    provider: string,
  ): Promise<{ provider: string; refreshed: boolean; expires_at?: string }> {
    return this.request<{ provider: string; refreshed: boolean; expires_at?: string }>(
      'POST',
      `/v1/oauth/connections/${encodeURIComponent(provider)}/refresh`,
    );
  }

  // ===== Email send =====

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
  }): Promise<{ status: string; provider: string; message?: string; messageId?: string }> {
    const body: Record<string, unknown> = { to: opts.to, subject: opts.subject };
    if (opts.htmlBody !== undefined) body.html_body = opts.htmlBody;
    if (opts.textBody !== undefined) body.text_body = opts.textBody;
    if (opts.fromAddress !== undefined) body.from_address = opts.fromAddress;
    if (opts.replyTo !== undefined) body.reply_to = opts.replyTo;
    return this.request<{ status: string; provider: string; message?: string; messageId?: string }>(
      'POST',
      '/api/email/send',
      { body },
    );
  }

  // =========================================================================
  // Canonical parity additions (0.6.0) — mirrors buttrbase-sdk-rust surface
  // =========================================================================

  // ===== Auth — email OTP (v1, uuid-based) =====

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
  sendOtpV1(email: string, appUuid: string): Promise<void> {
    return this.request<void>('POST', '/api/v1/auth/otp/send', {
      body: { email, app_uuid: appUuid },
      auth: false,
      headers: {
        'Authorization': 'Basic ' + Buffer.from(this.clientId + ':' + this.clientSecret).toString('base64'),
      }
    });
  }

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
  verifyOtpV1(email: string, otp: string, appUuid: string): Promise<TokenPair> {
    return this.request<TokenPair>('POST', '/api/v1/auth/otp/verify', {
      body: { email, otp, app_uuid: appUuid },
      auth: false,
    });
  }

  // ===== Auth — token refresh =====

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
  refreshToken(refreshToken: string): Promise<AccessToken> {
    return this.request<AccessToken>('POST', '/api/app/auth/refresh', {
      body: { refresh: refreshToken },
      auth: false,
    });
  }

  // ===== Entitlements — canonical shapes =====

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
  async checkEntitlement(featureKey: string): Promise<EntitlementResult> {
    const resp = await this.request<{ data: EntitlementResult }>(
      'POST',
      '/api/entitlements/check',
      { body: { feature_key: featureKey } },
    );
    return resp.data;
  }

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
  async checkEntitlements(featureKeys: string[]): Promise<Record<string, EntitlementResult>> {
    const resp = await this.request<{ data: Record<string, EntitlementResult> }>(
      'POST',
      '/api/entitlements/check/batch',
      { body: { feature_keys: featureKeys } },
    );
    return resp.data;
  }

  /**
   * Return all effective entitlements for the authenticated user.
   *
   * GET /api/entitlements/effective  →  `{ data: EffectiveEntitlement[] }`
   *
   * Mirrors `effective_entitlements(bearer)` in the Rust SDK.
   * The pre-existing `entitlementsEffective()` returns `Record<string, unknown>`;
   * this canonical variant returns a typed `EffectiveEntitlement[]`.
   */
  async effectiveEntitlements(): Promise<EffectiveEntitlement[]> {
    const resp = await this.request<{ data: EffectiveEntitlement[] }>(
      'GET',
      '/api/entitlements/effective',
    );
    return resp.data;
  }

  // ===== Pricing — typed shapes =====

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
  async pricingPreviewTyped(req: PricingPreviewRequest): Promise<PricingPreview> {
    const resp = await this.request<{ data: PricingPreview }>(
      'POST',
      '/api/pricing/preview',
      { body: req },
    );
    return resp.data;
  }

  /**
   * Lock a signed price quote (10-minute TTL). Pass `quote_id` to
   * `checkoutSessionTyped` to guarantee the price the user saw.
   *
   * POST /api/pricing/quote  →  `{ data: unknown }`
   *
   * Mirrors `pricing_quote(bearer, req)` in the Rust SDK.
   */
  async pricingQuoteTyped(req: PricingPreviewRequest): Promise<unknown> {
    const resp = await this.request<{ data: unknown }>(
      'POST',
      '/api/pricing/quote',
      { body: req },
    );
    return resp.data;
  }

  /**
   * Create a checkout session. Blocked for sandbox credentials on the backend.
   *
   * POST /api/pricing/checkout-session  →  `{ data: CheckoutSession }`
   *
   * Mirrors `checkout_session(bearer, req)` in the Rust SDK.
   */
  async checkoutSessionTyped(req: CheckoutSessionRequest): Promise<CheckoutSession> {
    const resp = await this.request<{ data: CheckoutSession }>(
      'POST',
      '/api/pricing/checkout-session',
      { body: req },
    );
    return resp.data;
  }

  // ===== Wallet =====

  /**
   * Get the authenticated user's wallet balance and budget.
   *
   * GET /api/wallet  →  `{ data: WalletSummary }`
   *
   * Mirrors `wallet(bearer)` in the Rust SDK.
   * The pre-existing `getWallet()` returns `Record<string,unknown>` (untyped);
   * this canonical variant returns a typed `WalletSummary`.
   */
  async walletSummary(): Promise<WalletSummary> {
    const resp = await this.request<{ data: WalletSummary }>('GET', '/api/wallet');
    return resp.data;
  }

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
  async walletTransactions(limit = 20, offset = 0): Promise<WalletTransaction[]> {
    const resp = await this.request<{ data: WalletTransaction[] }>(
      'GET',
      '/api/wallet/transactions',
      { query: { limit, offset } },
    );
    return resp.data;
  }

  // ===== Subscriptions =====

  /**
   * List the authenticated user's subscriptions.
   *
   * GET /api/subscriptions  →  `{ data: SubscriptionItem[] }`
   *
   * Mirrors `subscriptions(bearer)` in the Rust SDK.
   */
  async listSubscriptions(): Promise<SubscriptionItem[]> {
    const resp = await this.request<{ data: SubscriptionItem[] }>('GET', '/api/subscriptions');
    return resp.data;
  }

  /**
   * Create a subscription for a price.
   *
   * POST /api/subscriptions  →  `{ data: SubscriptionItem }`
   *
   * Mirrors `create_subscription(bearer, body)` in the Rust SDK.
   *
   * @param body  Subscription creation payload (at minimum `{ price_id: number }`).
   */
  async createSubscription(body: Record<string, unknown>): Promise<SubscriptionItem> {
    const resp = await this.request<{ data: SubscriptionItem }>(
      'POST',
      '/api/subscriptions',
      { body },
    );
    return resp.data;
  }

  /**
   * Cancel a subscription by its integer ID.
   *
   * DELETE /api/subscriptions/{subscriptionId}
   *
   * Mirrors `cancel_subscription(bearer, subscription_id)` in the Rust SDK.
   */
  cancelSubscription(subscriptionId: number): Promise<void> {
    return this.request<void>('DELETE', `/api/subscriptions/${subscriptionId}`);
  }

  // ===== Billing history — typed =====

  /**
   * Get the authenticated user's billing history (invoices).
   *
   * GET /api/billing/history  →  `{ data: Invoice[] }`
   *
   * Mirrors `billing_history(bearer)` in the Rust SDK.
   * The pre-existing `getBillingHistory()` returns `Record<string,unknown>`;
   * this canonical variant returns `Invoice[]`.
   */
  async billingHistory(): Promise<Invoice[]> {
    const resp = await this.request<{ data: Invoice[] }>('GET', '/api/billing/history');
    return resp.data;
  }

  // ===== Usage — typed (canonical) =====

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
  reportUsage(event: UsageEvent): Promise<void> {
    return this.request<void>('POST', '/api/usage/report', { body: event });
  }

  // ===== Analytics — canonical names =====

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
  ingestEvent(event: AnalyticsEvent): Promise<void> {
    return this.request<void>('POST', '/api/analytics/events', { body: event });
  }

  /**
   * Get analytics overview for an app (uses the SDK's app-server bearer).
   *
   * GET /api/analytics/apps/{appUuid}/overview?period={period}
   *
   * Mirrors `app_analytics_overview(app_uuid, period)` in the Rust SDK.
   * The pre-existing `analyticsAppOverview(appUuid)` does not accept a period;
   * this canonical variant adds the required `period` parameter.
   */
  appAnalyticsOverview(appUuid: string, period: string): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>(
      'GET',
      `/api/analytics/apps/${encodeURIComponent(appUuid)}/overview`,
      { query: { period } },
    );
  }

  /**
   * Get analytics overview for an org.
   *
   * GET /api/analytics/organizations/{orgUuid}/overview?period={period}
   *
   * Mirrors `org_analytics_overview(bearer, org_uuid, period)` in the Rust SDK.
   * The pre-existing `analyticsOrgOverview(orgUuid)` does not accept a period;
   * this canonical variant adds the required `period` parameter.
   */
  orgAnalyticsOverview(orgUuid: string, period: string): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>(
      'GET',
      `/api/analytics/organizations/${encodeURIComponent(orgUuid)}/overview`,
      { query: { period } },
    );
  }

  // ===== Teams — canonical typed =====

  /**
   * List active teams in an org (typed).
   *
   * GET /api/organizations/{orgUuid}/teams  →  `{ data: TeamItem[] }`
   *
   * Mirrors `org_teams(bearer, org_uuid)` in the Rust SDK.
   * The pre-existing `listOrgTeams(orgUuid)` returns `unknown[]`; this
   * canonical variant returns the typed `TeamItem[]`.
   */
  async orgTeams(orgUuid: string): Promise<TeamItem[]> {
    const resp = await this.request<{ data: TeamItem[] }>(
      'GET',
      `/api/organizations/${encodeURIComponent(orgUuid)}/teams`,
    );
    return resp.data;
  }

  /**
   * List teams a user is a member of (typed).
   *
   * GET /api/users/{userUuid}/teams  →  `{ data: TeamItem[] }`
   *
   * Mirrors `user_teams(bearer, user_uuid)` in the Rust SDK.
   * The pre-existing `getUserTeams(userUuid)` returns `unknown[]`; this
   * canonical variant returns the typed `TeamItem[]`.
   */
  async userTeams(userUuid: string): Promise<TeamItem[]> {
    const resp = await this.request<{ data: TeamItem[] }>(
      'GET',
      `/api/users/${encodeURIComponent(userUuid)}/teams`,
    );
    return resp.data;
  }

  // ===== App management =====

  /**
   * List apps the authenticated user belongs to.
   *
   * GET /api/me/apps  →  `{ data: AppEntry[] }`
   *
   * Mirrors `my_apps(bearer)` in the Rust SDK.
   */
  async myApps(): Promise<AppEntry[]> {
    const resp = await this.request<{ data: AppEntry[] }>('GET', '/api/me/apps');
    return resp.data;
  }

  /**
   * List orgs within an app that the user belongs to.
   *
   * GET /api/apps/{appUuid}/organizations  →  `{ data: OrgEntry[] }`
   *
   * Mirrors `app_orgs(bearer, app_uuid)` in the Rust SDK.
   */
  async appOrgs(appUuid: string): Promise<OrgEntry[]> {
    const resp = await this.request<{ data: OrgEntry[] }>(
      'GET',
      `/api/apps/${encodeURIComponent(appUuid)}/organizations`,
    );
    return resp.data;
  }

  /**
   * Get live/sandbox credential info for an app (admin only).
   *
   * GET /api/apps/{appUuid}/credentials  →  `{ data: AppCredentialsResponse }`
   *
   * Mirrors `app_credentials(bearer, app_uuid)` in the Rust SDK.
   */
  async appCredentials(appUuid: string): Promise<AppCredentialsResponse> {
    const resp = await this.request<{ data: AppCredentialsResponse }>(
      'GET',
      `/api/apps/${encodeURIComponent(appUuid)}/credentials`,
    );
    return resp.data;
  }

  /**
   * Enable sandbox mode for an app.
   *
   * PATCH /api/apps/{appUuid}  body: `{ sandbox_enabled: true }`
   *
   * Mirrors `enable_sandbox(bearer, app_uuid)` in the Rust SDK.
   */
  enableSandbox(appUuid: string): Promise<void> {
    return this.request<void>(
      'PATCH',
      `/api/apps/${encodeURIComponent(appUuid)}`,
      { body: { sandbox_enabled: true } },
    );
  }

  /**
   * Rotate credentials for a given environment (`"live"` or `"sandbox"`).
   *
   * POST /api/apps/{appUuid}/credentials/{environment}/rotate
   *    →  `{ data: unknown }`
   *
   * Mirrors `rotate_credentials(bearer, app_uuid, environment)` in the Rust SDK.
   */
  async rotateCredentials(appUuid: string, environment: string): Promise<unknown> {
    const resp = await this.request<{ data: unknown }>(
      'POST',
      `/api/apps/${encodeURIComponent(appUuid)}/credentials/${encodeURIComponent(environment)}/rotate`,
    );
    return resp.data;
  }
}
