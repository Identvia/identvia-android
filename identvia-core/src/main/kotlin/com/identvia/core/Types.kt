package com.identvia.core

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * Opens the authorization URL in a **system** browser (Custom Tabs on Android) and returns the redirect URI
 * Identvia sent back. Throw [IdentviaException.Cancelled] when the user closes it. Never use a WebView (RFC 8252 §8.12).
 */
fun interface AuthBrowser {
    suspend fun authenticate(url: String, redirectUri: String, ephemeral: Boolean): String
}

/** Secure storage for the session. On Android, use `KeystoreTokenStore`. */
interface TokenStore {
    suspend fun get(key: String): String?
    suspend fun set(key: String, value: String)
    suspend fun delete(key: String)
}

/** For tests. Not persistent. */
class InMemoryTokenStore : TokenStore {
    val values = java.util.concurrent.ConcurrentHashMap<String, String>()
    override suspend fun get(key: String) = values[key]
    override suspend fun set(key: String, value: String) { values[key] = value }
    override suspend fun delete(key: String) { values.remove(key) }
}

@Serializable
data class TokenSet(
    val accessToken: String,
    val tokenType: String = "Bearer",
    /** Epoch milliseconds. */
    val expiresAt: Long,
    val refreshToken: String? = null,
    val idToken: String? = null,
    val scope: String? = null,
    /** RFC 9396 details the user approved (server 2026-10-21_5+). */
    val authorizationDetails: JsonArray? = null,
)

@Serializable
data class IdentviaSession(val user: IdentviaUser, val tokens: TokenSet)

/** One RFC 9396 authorization detail. Requires server 2026-10-21_5+. */
data class AuthorizationDetail(val type: String, val fields: Map<String, JsonElement> = emptyMap()) {
    fun toJson() = JsonObject(fields + ("type" to JsonPrimitive(type)))

    companion object {
        /** An `agent_task` detail, shown to the user on the consent screen. */
        fun agentTask(description: String, actions: List<String>? = null, locations: List<String>? = null): AuthorizationDetail {
            require(description.isNotBlank()) { "agentTask needs a description." }
            val f = mutableMapOf<String, JsonElement>("description" to JsonPrimitive(description))
            actions?.let { a -> f["actions"] = JsonArray(a.map(::JsonPrimitive)) }
            locations?.let { l -> f["locations"] = JsonArray(l.map(::JsonPrimitive)) }
            return AuthorizationDetail("agent_task", f)
        }
    }
}

/** What one sign-in attempt remembers between opening the browser and handling the redirect. */
@Serializable
data class AuthorizationTransaction(val state: String, val nonce: String, val codeVerifier: String, val redirectUri: String, val maxAge: Int? = null)
