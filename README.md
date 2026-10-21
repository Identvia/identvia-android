# Identvia for Android

Sign in with [Identvia](https://identvia.com) on Android 6.0+ (API 23). OpenID Connect with PKCE in **Chrome Custom Tabs**, AndroidKeyStore-encrypted session storage, refresh-token rotation, Kotlin coroutines and a branded button.

- **Public client.** Never ship a client secret in an app; the SDK has no secret option.
- **Pairwise `sub`.** Each app gets its own stable user ID. Key your users on `session.user.sub`.

## Install

```kotlin
dependencies {
    implementation("com.identvia:identvia-android:0.1.0")
}

android {
    defaultConfig {
        // The scheme of your redirect URI
        manifestPlaceholders["identviaRedirectScheme"] = "com.example.app"
    }
}
```

`identvia-core` is a pure-JVM artifact. It's pulled in automatically, and it also works in Kotlin desktop or server code.

## 1. Register

At <https://identvia.com/developers>, create a **public** (native) client with the redirect URI `com.example.app:/oauth/identvia`. That's a reverse-domain scheme (RFC 8252 §7.1). Verified App Links (`https://`) work too: add your own `autoVerify` intent filter to `com.identvia.android.IdentviaRedirectActivity`.

## 2. Quickstart

```kotlin
val identvia = Identvia.client(applicationContext, clientId = "oid_…", redirectUri = "com.example.app:/oauth/identvia")

// On launch
lifecycleScope.launch { val existing = identvia.currentSession() }

// Sign in (from an Activity)
button.setOnClickListener {
    lifecycleScope.launch {
        try {
            val session = identvia.signIn(this@MainActivity)
            Log.i("app", session.user.sub)
        } catch (_: IdentviaException.Cancelled) { }
    }
}

// Call your API. The access token is refreshed and rotated automatically.
val token = identvia.getAccessToken()

// Observe the session
identvia.session.collect { s -> render(s) }

// Sign out. federated = true also ends the Identvia browser session.
identvia.signOut(this, federated = false)
```

The button in XML:

```xml
<com.identvia.android.SignInWithIdentviaButton
    android:layout_width="wrap_content" android:layout_height="wrap_content"
    app:identviaTheme="dark" app:identviaText="continueWith" />
```

`getAccessToken()` throws `IdentviaException.LoginRequired` when the session has ended (expired, revoked, or the refresh token was reused).

### Agent authorization (requires server 2026-10-21_5+)

```kotlin
identvia.signIn(activity, authorizationDetails = listOf(AuthorizationDetail.agentTask("Book a table for two on Friday")))
```

This throws `Unsupported` when the server doesn't advertise `authorization_details_types_supported`. Token exchange (RFC 8693) and CIBA need a client secret, so they belong on your backend (`@identvia/js/server` or `Identvia.AspNetCore`).

## Security

- Every sign-in uses PKCE S256, `state`, `nonce` and RFC 9207 `iss`. The redirect must match exactly, and `IdentviaRedirectActivity` ignores intents when no sign-in is pending.
- ID tokens are verified: RS256/ES256 signature, plus `iss`, `aud`, `azp`, `exp`, `iat`, `nonce` and `at_hash`.
- The session is encrypted with a non-exportable AndroidKeyStore AES-GCM key. The refresh token is stored as its own entry. Restored backups read as signed out.
- Sign-in always uses Custom Tabs or the system browser, never a WebView.

## Tests

```sh
./gradlew :identvia-core:test                                     # unit tests (JVM)
IDENTVIA_LIVE_STATE=/tmp/live-state.json ./gradlew :identvia-core:test   # + live test against a real server
./gradlew :identvia-android:assembleRelease :identvia-android:lintRelease :example:assembleDebug
```

## Limitations (0.1.0)

- If Android kills the app process while the Custom Tab is open, that sign-in attempt is lost; the user taps sign-in again.
- `ephemeralSession` is ignored on Android; use `prompt = "login"`.

MIT © Identvia
