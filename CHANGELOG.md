# Changelog

## 0.1.1 (2026-10-21)

- Repository hygiene: `.gitignore` now excludes APK/AAB files, keystores and local live-test state. No code changes.

## 0.1.0 — 2026-10-21

- First release.
- `com.identvia:identvia-core` (pure JVM, Kotlin coroutines):
  - Authorization code flow with mandatory PKCE S256, `state`, `nonce` and the RFC 9207 `iss` check.
  - ID token validation: RS256/ES256 via java.security, plus `iss`, `aud`/`azp`, `exp`, `iat`, `nonce`, `at_hash` and `max_age`. Rejects `none` and HS*. An unknown `kid` triggers a JWKS refetch, at most every 30 s.
  - Refresh-token rotation with single-flight refresh. A reused refresh token signs the user out locally (`LoginRequired`).
  - `userinfo()`, `signOut()` (revocation and RP-initiated logout), `session` StateFlow.
  - `AuthorizationDetail.agentTask` (RFC 9396): requires server 2026-10-21_5+, and throws `Unsupported` otherwise.
- `com.identvia:identvia-android`:
  - Custom Tabs sign-in (falls back to the default browser, never a WebView), with redirect capture through a manifest placeholder.
  - `KeystoreTokenStore`: AES-256-GCM with an AndroidKeyStore key.
  - `SignInWithIdentviaButton` view.
