/**
 * JWT helpers for buttrbase-issued tokens.
 *
 * Two tiers:
 *
 * 1. **Decode-only** (`decodeJwtPayload`, `decodeButtrbaseClaims`,
 *    `claimsToAuthContext`) — no crypto dependency, no network. Parse the
 *    payload after you have already verified the signature externally.
 *
 * 2. **Cryptographic verifier** (`Verifier`) — fetches the org's JWKS,
 *    validates the RS256 signature, issuer, expiry, and optionally audience.
 *    Mirrors `Verifier` / `VerifierConfig` / `verify` / `verify_bearer` from
 *    the Rust SDK (buttrbase-sdk-rust src/verify/verifier.rs).
 *
 * Mirrors the Rust SDK's `ClaimsData` / `Claims` / `AuthContext` additions
 * (Rust SDK 0.6.0).
 */

import { createRemoteJWKSet, jwtVerify, decodeProtectedHeader } from 'jose';
import type { Claims, AuthContext } from './types.js';

/**
 * Decode the base64url payload of a JWT string and return the raw
 * {@link Claims} object.  Throws a `TypeError` if the token is not a
 * three-part JWT or the payload is not valid JSON.
 *
 * **No signature verification is performed.** Always verify the token with
 * the JWKS before trusting the returned claims.
 */
export function decodeJwtPayload(token: string): Claims {
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new TypeError('Invalid JWT: expected three dot-separated parts');
  }
  const payloadB64 = parts[1];
  // base64url → base64 → binary → UTF-8
  const padded = payloadB64.replace(/-/g, '+').replace(/_/g, '/');
  const padLength = (4 - (padded.length % 4)) % 4;
  const b64 = padded + '='.repeat(padLength);

  let jsonStr: string;
  try {
    if (typeof atob !== 'undefined') {
      // Browser / modern Node (≥ 16 with the global)
      jsonStr = atob(b64);
    } else {
      // Older Node (Buffer is always available here)
      jsonStr = Buffer.from(b64, 'base64').toString('utf-8');
    }
  } catch {
    throw new TypeError('Invalid JWT: payload base64url is malformed');
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(jsonStr);
  } catch {
    throw new TypeError('Invalid JWT: payload is not valid JSON');
  }
  return parsed as Claims;
}

/**
 * Decode a buttrbase JWT string and return a typed {@link AuthContext} that
 * surfaces `roles` (split from `data.roles`) and `email` from the `data`
 * envelope.
 *
 * **No signature verification is performed.** Always verify the token with
 * the JWKS before trusting the returned principal.
 *
 * ```ts
 * // After verifying the JWT signature against the JWKS:
 * const ctx = decodeButtrbaseClaims(accessToken);
 * if (ctx.roles.includes('owner')) { ... }
 * console.log(ctx.email);
 * ```
 *
 * Mirrors `AuthContext::from(Claims)` in the Rust SDK (added in 0.6.0).
 */
export function decodeButtrbaseClaims(token: string): AuthContext {
  const claims = decodeJwtPayload(token);
  return claimsToAuthContext(claims);
}

/**
 * Convert a {@link Claims} object (e.g. from your own JWKS verification
 * library) into a typed {@link AuthContext} with `roles` and `email` surfaced
 * from the `data` envelope.
 *
 * Mirrors `AuthContext::from(Claims)` in the Rust SDK.
 */
export function claimsToAuthContext(claims: Claims): AuthContext {
  const data = claims.data;
  // Split "owner" or "org_admin,leadership" or "admin member" on comma/space.
  const roles: string[] =
    data?.roles
      ? data.roles.split(/[, ]+/).filter((p) => p.length > 0)
      : [];
  const email: string | undefined = data?.email;
  return {
    userId: claims.sub,
    orgId: claims.org,
    scopes: Array.isArray(claims.scope) ? claims.scope : [],
    roles,
    email,
  };
}

// ---------------------------------------------------------------------------
// Cryptographic verifier — RS256 + JWKS (mirrors Rust SDK Verifier)
// ---------------------------------------------------------------------------

/**
 * Configuration for {@link Verifier}.
 *
 * `audience` is **optional**. buttrbase access tokens do not carry a stable,
 * per-application `aud` claim — magic-link tokens set `aud` to the org name
 * (or omit it), and client-credential tokens omit it entirely. So most
 * consumers should leave this `undefined` (no `aud` validation) and rely on
 * the `iss` + signature + `org`/`sub` claims. Set `audience` only if you
 * mint tokens with a known audience and want it enforced.
 *
 * Mirrors `VerifierConfig` in the Rust SDK.
 */
export interface VerifierConfig {
  /** Full URL to the JWKS endpoint, e.g. `https://api.buttrbase.com/jwks.json`. */
  jwksUrl: string;
  /** Expected `iss` claim value, e.g. `https://api.buttrbase.com`. */
  issuer: string;
  /**
   * Expected `aud` claim. When omitted (default) the `aud` claim is not
   * validated, matching the Rust SDK's `audience: None` behaviour.
   */
  audience?: string;
}

/**
 * Cryptographic JWT verifier. Fetches the remote JWKS (with built-in caching
 * via `jose`), validates the RS256 signature, issuer, and expiry; optionally
 * enforces the audience claim.
 *
 * Construct once at startup and share across requests (the JWKS cache is
 * internal to the instance).
 *
 * Mirrors `Verifier` in the Rust SDK (src/verify/verifier.rs).
 *
 * ```ts
 * const verifier = new Verifier({
 *   jwksUrl: 'https://api.buttrbase.com/jwks.json',
 *   issuer: 'https://api.buttrbase.com',
 * });
 *
 * // In an HTTP handler:
 * const ctx = await verifier.verifyBearer(req.headers.authorization ?? '');
 * if (ctx.roles.includes('owner')) { ... }
 * ```
 */
export class Verifier {
  private readonly config: VerifierConfig;
  /** `jose` remote JWKS set — handles fetch, caching, and key-id lookup. */
  private readonly jwks: ReturnType<typeof createRemoteJWKSet>;

  constructor(config: VerifierConfig) {
    this.config = { ...config };
    this.jwks = createRemoteJWKSet(new URL(config.jwksUrl));
  }

  /**
   * Verify a bare RS256 token string against the remote JWKS.
   *
   * - Validates the RS256 signature using the `kid`-matched key from the JWKS.
   * - Enforces `iss` and token expiry.
   * - Enforces `aud` only when {@link VerifierConfig.audience} is set (mirrors
   *   the Rust SDK's `validate_aud = false` when `audience: None`).
   *
   * Returns the typed {@link Claims} on success; throws on any failure.
   */
  async verifyToken(token: string): Promise<Claims> {
    const header = decodeProtectedHeader(token);

    if (header.alg === 'HS256') {
      const introspectionKey = process.env.INTROSPECTION_API_KEY || '';
      const f = globalThis.fetch;
      if (!f) {
        throw new Error('No fetch implementation available');
      }

      const res = await f(`${this.config.issuer}/api/auth/introspect`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Introspection-Key': introspectionKey,
        },
        body: JSON.stringify({ token }),
      });

      if (!res.ok) {
        throw new Error(`Introspection request failed: ${res.status}`);
      }

      const data = await res.json();
      if (data.active === true) {
        return {
          sub: data.data?.user_uuid || '',
          org: data.data?.org_uuid || '',
          exp: data.exp,
          iat: 0,
          data: data.data,
        } as Claims;
      } else {
        throw new Error('Token is inactive');
      }
    }

    const verifyOptions: Parameters<typeof jwtVerify>[2] = {
      algorithms: ['RS256'],
      issuer: this.config.issuer,
    };

    if (this.config.audience !== undefined) {
      verifyOptions.audience = this.config.audience;
    }

    const { payload } = await jwtVerify(token, this.jwks, verifyOptions);

    // Cast: the payload matches our Claims shape (sub, org, exp, iat, scope?, data?).
    // `jose` has already validated exp/nbf/iss/(aud), so we can trust the fields.
    return payload as unknown as Claims;
  }

  /**
   * Extract a `Bearer <token>` from an `Authorization` header value, verify it,
   * and return the caller's {@link AuthContext}.
   *
   * Throws if the header is missing, malformed, or the token is invalid.
   *
   * Mirrors `verify_bearer(headers) -> AuthContext` in the Rust SDK.
   */
  async verifyBearer(authHeader: string): Promise<AuthContext> {
    const prefix = 'Bearer ';
    if (!authHeader.startsWith(prefix)) {
      throw new Error(
        'Missing or malformed Authorization header: expected "Bearer <token>"',
      );
    }
    const token = authHeader.slice(prefix.length).trim();
    if (!token) {
      throw new Error('Authorization header contained an empty Bearer token');
    }
    const claims = await this.verifyToken(token);
    return claimsToAuthContext(claims);
  }

  /** Read-only accessor for the configured issuer. Useful for diagnostics. */
  get issuer(): string {
    return this.config.issuer;
  }

  /**
   * Read-only accessor for the configured audience, if any.
   * `undefined` means `aud` is not validated.
   */
  get audience(): string | undefined {
    return this.config.audience;
  }
}
