package com.identvia.core

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** The signed-in user, from the validated ID token. `sub` is pairwise: stable for your app, different for other apps. */
@Serializable
data class IdentviaUser(
    val sub: String,
    val email: String? = null,
    val emailVerified: Boolean? = null,
    val name: String? = null,
    val givenName: String? = null,
    val familyName: String? = null,
    val picture: String? = null,
    val locale: String? = null,
    val authTime: Long? = null,
    /** All ID token claims. */
    val claims: JsonObject = JsonObject(emptyMap()),
) {
    companion object {
        fun from(c: JsonObject) = IdentviaUser(
            sub = c.str("sub") ?: "", email = c.str("email"), emailVerified = c.bool("email_verified"), name = c.str("name"),
            givenName = c.str("given_name"), familyName = c.str("family_name"), picture = c.str("picture"), locale = c.str("locale"),
            authTime = c.num("auth_time")?.toLong(), claims = c,
        )
    }
}

internal class IdTokenOptions(
    val issuer: String, val clientId: String, val nonce: String?, val maxAge: Int?, val accessToken: String?,
    val nowSeconds: Long, val leewaySeconds: Long = 60,
)

/** OIDC Core §3.1.3.7 ID token validation. */
internal object IdTokenValidator {
    suspend fun validate(token: String, o: IdTokenOptions, key: suspend (String?, String) -> Jwk?): JsonObject {
        val jws = CompactJws(token)
        val alg = jws.header.str("alg") ?: throw IdentviaException.Validation("ID token has no alg.")
        if (alg !in JwsVerifier.allowed) throw IdentviaException.Validation("ID token alg $alg is not allowed (expected RS256 or ES256; never none or HS*).")
        if (!jws.header["crit"].isNullOrJsonNull()) throw IdentviaException.Validation("Unsupported crit header.")
        val kid = jws.header.str("kid")
        val k = key(kid, alg) ?: throw IdentviaException.Validation("ID token is signed with an unknown key (kid ${kid ?: "none"}).")
        if (!JwsVerifier.verify(jws, alg, k)) throw IdentviaException.Validation("ID token signature is invalid.")

        val c = jws.payload
        if (c.str("iss") != o.issuer) throw IdentviaException.Validation("ID token issuer ${c.str("iss")} is not ${o.issuer}.")
        if (c.str("sub").isNullOrEmpty()) throw IdentviaException.Validation("ID token has no sub.")
        val aud = when (val a = c["aud"]) {
            is JsonPrimitive -> if (a.isString) listOf(a.content) else emptyList()
            is JsonArray -> a.mapNotNull { (it as? JsonPrimitive)?.content }
            else -> emptyList()
        }
        if (o.clientId !in aud) throw IdentviaException.Validation("ID token aud does not include this client.")
        val azp = c.str("azp")
        if (aud.size > 1 && azp == null) throw IdentviaException.Validation("ID token with several audiences needs azp.")
        if (azp != null && azp != o.clientId) throw IdentviaException.Validation("ID token azp is another client.")
        val exp = c.num("exp") ?: throw IdentviaException.Validation("ID token has no exp.")
        if (o.nowSeconds >= exp + o.leewaySeconds) throw IdentviaException.Validation("ID token expired.")
        val iat = c.num("iat") ?: throw IdentviaException.Validation("ID token has no iat.")
        if (iat > o.nowSeconds + o.leewaySeconds) throw IdentviaException.Validation("ID token was issued in the future.")
        if (o.nonce != null) {
            val n = c.str("nonce")
            if (n == null || !constantTimeEquals(n, o.nonce)) throw IdentviaException.Validation("ID token nonce does not match (replay?).")
        }
        if (o.maxAge != null) {
            val at = c.num("auth_time") ?: throw IdentviaException.Validation("max_age was requested but auth_time is missing.")
            if (o.nowSeconds > at + o.maxAge + o.leewaySeconds) throw IdentviaException.Validation("auth_time is older than max_age.")
        }
        val atHash = c.str("at_hash")
        if (atHash != null && o.accessToken != null) {
            if (!constantTimeEquals(atHash, sha256(o.accessToken).copyOf(16).b64url())) throw IdentviaException.Validation("ID token at_hash does not match the access token.")
        }
        return c
    }
}
