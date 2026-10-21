package com.identvia.core

/** Proof Key for Code Exchange (RFC 7636), S256 only. Identvia rejects `plain`. */
data class Pkce(val verifier: String, val challenge: String) {
    val method: String get() = "S256"

    companion object {
        private val unreserved = Regex("^[A-Za-z0-9._~-]{43,128}$")

        /** A fresh verifier with 256 bits of entropy (43 chars). */
        fun generate(): Pkce = randomToken(32).let { Pkce(it, challenge(it)) }

        fun challenge(verifier: String): String {
            if (!unreserved.matches(verifier)) throw IdentviaException.Configuration("A PKCE verifier must be 43-128 unreserved characters.")
            return sha256(verifier).b64url()
        }
    }
}
