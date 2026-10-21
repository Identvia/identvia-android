package com.identvia.core

/** Every error the SDK throws. */
sealed class IdentviaException(message: String) : Exception(message) {
    /** The SDK was set up wrongly (issuer, client ID, redirect URI). */
    class Configuration(message: String) : IdentviaException(message)
    /** The user closed the browser. */
    class Cancelled : IdentviaException("Sign-in was cancelled.")
    /** The redirect didn't belong to this sign-in (state, iss or redirect mismatch). */
    class InvalidState(message: String) : IdentviaException(message)
    /** Identvia sent an error to the redirect URI, for example `access_denied`. */
    class Authorization(val error: String, val description: String?) : IdentviaException("Authorization failed: $error${description?.let { " ($it)" } ?: ""}")
    /** The token, userinfo or revocation endpoint returned an error. */
    class Token(val error: String, val description: String?, val status: Int) : IdentviaException("Token request failed ($status): $error${description?.let { " ($it)" } ?: ""}")
    /** An ID token or response failed validation. */
    class Validation(message: String) : IdentviaException(message)
    class Network(message: String, cause: Throwable? = null) : IdentviaException(message) { init { cause?.let { initCause(it) } } }
    /** The server doesn't support this yet (stage-5 features need server 2026-10-21_5+). */
    class Unsupported(message: String) : IdentviaException(message)
    /** The session ended (refresh token expired, revoked or reused). Sign in again. */
    class LoginRequired : IdentviaException("The session has ended; sign in again.")
}
