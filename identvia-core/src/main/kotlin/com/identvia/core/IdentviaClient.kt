package com.identvia.core

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import java.net.URI
import java.util.concurrent.atomic.AtomicBoolean

const val DEFAULT_ISSUER = "https://id.identvia.com"

/**
 * Sign in with Identvia: the authorization code flow with PKCE S256 in the system browser, ID token
 * validation, secure session storage and refresh-token rotation. This is a public client, so never give it a client secret.
 */
class IdentviaClient(
    issuer: String = DEFAULT_ISSUER,
    val clientId: String,
    redirectUri: String,
    scopes: List<String> = listOf("email", "profile", "offline_access"),
    private val browser: AuthBrowser? = null,
    private val store: TokenStore,
    private val transport: HttpTransport = UrlConnectionTransport(),
    val ephemeralSession: Boolean = false,
    private val refreshLeewayMs: Long = 60_000,
    private val clock: () -> Long = System::currentTimeMillis,
) {
    val issuer: String = normalizeIssuer(issuer)
    val redirectUri: URI = RedirectUri.validate(redirectUri)
    val scopes: List<String> = (listOf("openid") + scopes).distinct()

    init {
        if (clientId.isBlank()) throw IdentviaException.Configuration("clientId is required.")
    }

    private val metaMutex = Mutex()
    private var metadata: ProviderMetadata? = null
    private var jwks: JwksCache? = null
    private val sessionMutex = Mutex()
    private var loaded = false
    private val refreshLock = Mutex()
    private var refreshing: CompletableDeferred<IdentviaSession>? = null
    private val signingIn = AtomicBoolean(false)
    private val _session = MutableStateFlow<IdentviaSession?>(null)

    /** The current session. It updates on sign-in, refresh and sign-out. Call [currentSession] once to load it from storage. */
    val session: StateFlow<IdentviaSession?> = _session.asStateFlow()

    // ---------------------------------------------------------------- discovery

    suspend fun discovery(): ProviderMetadata = metaMutex.withLock {
        metadata?.let { return it }
        val r = transport.send(HttpRequest("GET", "$issuer/.well-known/openid-configuration", mapOf("Accept" to "application/json")))
        val m = (if (r.status == 200) parseObject(r.body) else null)?.let(ProviderMetadata::from)
            ?: throw IdentviaException.Network("Discovery failed (${r.status}).")
        if (m.issuer != issuer) throw IdentviaException.Validation("Discovery issuer ${m.issuer} is not $issuer.")
        if (m.codeChallengeMethodsSupported != null && "S256" !in m.codeChallengeMethodsSupported) throw IdentviaException.Unsupported("Server does not support PKCE S256.")
        metadata = m
        jwks = JwksCache(endpoint(m.jwksUri), transport, clock)
        m
    }

    private fun endpoint(s: String?): String {
        val u = s?.let { runCatching { URI(it) }.getOrNull() }
        val ok = u != null && (u.scheme == "https" || (u.scheme == "http" && u.host?.lowercase() in loopbackHosts))
        if (!ok) throw IdentviaException.Unsupported("Endpoint missing or not https: $s")
        return s!!
    }

    // ------------------------------------------------------------------ sign-in

    /** Builds the authorization URL. Use with [completeAuthorization] if you open the browser yourself. */
    suspend fun createAuthorizationRequest(
        scopes: List<String>? = null, prompt: String? = null, maxAge: Int? = null, loginHint: String? = null,
        uiLocales: List<String>? = null, authorizationDetails: List<AuthorizationDetail>? = null,
    ): Pair<String, AuthorizationTransaction> {
        val m = discovery()
        val pkce = Pkce.generate()
        val tx = AuthorizationTransaction(randomToken(), randomToken(), pkce.verifier, redirectUri.toString(), maxAge)
        val q = mutableListOf(
            "response_type" to "code", "client_id" to clientId, "redirect_uri" to tx.redirectUri,
            "scope" to (this.scopes + scopes.orEmpty()).distinct().joinToString(" "),
            "state" to tx.state, "nonce" to tx.nonce, "code_challenge" to pkce.challenge, "code_challenge_method" to "S256",
        )
        prompt?.let { q += "prompt" to it }
        maxAge?.let { q += "max_age" to it.toString() }
        loginHint?.let { q += "login_hint" to it }
        if (!uiLocales.isNullOrEmpty()) q += "ui_locales" to uiLocales.joinToString(" ")
        if (!authorizationDetails.isNullOrEmpty()) {
            val supported = m.authorizationDetailsTypesSupported.orEmpty()
            authorizationDetails.firstOrNull { it.type !in supported }?.let {
                throw IdentviaException.Unsupported("authorization_details type ${it.type} needs server 2026-10-21_5+ (not advertised in discovery).")
            }
            q += "authorization_details" to JsonArray(authorizationDetails.map { it.toJson() }).toString()
        }
        val base = endpoint(m.authorizationEndpoint)
        return (base + (if ('?' in base) "&" else "?") + formEncode(q)) to tx
    }

    /** Checks the redirect (URI, state, RFC 9207 iss), redeems the code and validates the ID token. */
    suspend fun completeAuthorization(callback: String, tx: AuthorizationTransaction): IdentviaSession {
        val m = discovery()
        val cb = runCatching { URI(callback) }.getOrElse { throw IdentviaException.InvalidState("The callback is not a valid URI.") }
        if (!RedirectUri.matches(cb, URI(tx.redirectUri))) throw IdentviaException.InvalidState("The callback is not this app's redirect URI.")
        val p = parseQuery(cb.rawQuery)
        val state = p["state"]
        if (state == null || !constantTimeEquals(state, tx.state)) throw IdentviaException.InvalidState("state does not match this sign-in.")
        val iss = p["iss"]
        if (iss != null) {
            if (iss != issuer) throw IdentviaException.InvalidState("iss $iss is not $issuer (mix-up attack?).")
        } else if (m.authorizationResponseIssParameterSupported) {
            throw IdentviaException.InvalidState("iss is missing from the authorization response.")
        }
        p["error"]?.let { throw IdentviaException.Authorization(it, p["error_description"]) }
        val code = p["code"] ?: throw IdentviaException.InvalidState("No code in the authorization response.")
        val t = tokenRequest(listOf("grant_type" to "authorization_code", "code" to code, "redirect_uri" to tx.redirectUri, "code_verifier" to tx.codeVerifier, "client_id" to clientId))
        val idToken = t.idToken ?: throw IdentviaException.Validation("The token response has no id_token.")
        val claims = validateIdToken(idToken, tx.nonce, tx.maxAge, t.accessToken)
        return IdentviaSession(IdentviaUser.from(claims), t)
    }

    /** Opens the system browser, signs the user in and stores the session. On Android, call `signIn(activity)`. */
    suspend fun signIn(
        browser: AuthBrowser? = null, scopes: List<String>? = null, prompt: String? = null, maxAge: Int? = null,
        loginHint: String? = null, uiLocales: List<String>? = null, authorizationDetails: List<AuthorizationDetail>? = null,
    ): IdentviaSession {
        val b = browser ?: this.browser ?: throw IdentviaException.Configuration("No AuthBrowser; on Android use signIn(activity).")
        if (!signingIn.compareAndSet(false, true)) throw IdentviaException.Configuration("A sign-in is already in progress.")
        try {
            val (url, tx) = createAuthorizationRequest(scopes, prompt, maxAge, loginHint, uiLocales, authorizationDetails)
            val back = b.authenticate(url, redirectUri.toString(), ephemeralSession)
            val s = completeAuthorization(back, tx)
            save(s)
            return s
        } finally {
            signingIn.set(false)
        }
    }

    // ------------------------------------------------------------------ session

    private fun key(n: String) = "identvia.${clientId.replace(Regex("[^A-Za-z0-9._-]"), "_")}.$n"

    /** The stored session, if any. No network. */
    suspend fun currentSession(): IdentviaSession? = sessionMutex.withLock {
        if (loaded) return _session.value
        val s = store.get(key("session"))?.let { runCatching { json.decodeFromString(IdentviaSession.serializer(), it) }.getOrNull() }
        val withRt = s?.copy(tokens = s.tokens.copy(refreshToken = store.get(key("rt"))))
        _session.value = withRt
        loaded = true
        withRt
    }

    private suspend fun save(s: IdentviaSession?) = sessionMutex.withLock {
        if (s != null) {
            val rt = s.tokens.refreshToken
            if (rt != null) store.set(key("rt"), rt) else store.delete(key("rt"))
            // The refresh token lives in its own entry.
            store.set(key("session"), json.encodeToString(IdentviaSession.serializer(), s.copy(tokens = s.tokens.copy(refreshToken = null))))
        } else {
            store.delete(key("session"))
            store.delete(key("rt"))
        }
        loaded = true
        _session.value = s
    }

    /**
     * Returns a valid access token, refreshing it (and rotating the refresh token) shortly before it expires.
     * Concurrent callers share one refresh. Throws [IdentviaException.LoginRequired] when the session has ended.
     */
    suspend fun getAccessToken(forceRefresh: Boolean = false): String {
        val s = currentSession() ?: throw IdentviaException.LoginRequired()
        if (!forceRefresh && s.tokens.expiresAt - clock() > refreshLeewayMs) return s.tokens.accessToken
        return refresh(s).tokens.accessToken
    }

    private suspend fun refresh(s: IdentviaSession): IdentviaSession {
        val (d, owner) = refreshLock.withLock {
            refreshing?.let { it to false } ?: CompletableDeferred<IdentviaSession>().also { refreshing = it }.let { it to true }
        }
        if (!owner) return d.await()
        try {
            val n = doRefresh(s)
            d.complete(n)
            return n
        } catch (e: Throwable) {
            d.completeExceptionally(e)
            throw e
        } finally {
            refreshLock.withLock { refreshing = null }
        }
    }

    private suspend fun doRefresh(s: IdentviaSession): IdentviaSession {
        val rt = s.tokens.refreshToken ?: run { save(null); throw IdentviaException.LoginRequired() }
        val t = try {
            tokenRequest(listOf("grant_type" to "refresh_token", "refresh_token" to rt, "client_id" to clientId))
        } catch (e: IdentviaException.Token) {
            // Expired, revoked, or reused (then Identvia revokes the whole token family).
            if (e.error == "invalid_grant") { save(null); throw IdentviaException.LoginRequired() }
            throw e
        }
        var user = s.user
        if (t.idToken != null) {
            val c = validateIdToken(t.idToken, null, null, t.accessToken)
            if (c.str("sub") != s.user.sub) throw IdentviaException.Validation("Refreshed ID token is for a different user.")
            user = IdentviaUser.from(c)
        }
        val n = IdentviaSession(user, t.copy(
            refreshToken = t.refreshToken ?: rt, idToken = t.idToken ?: s.tokens.idToken,
            scope = t.scope ?: s.tokens.scope, authorizationDetails = t.authorizationDetails ?: s.tokens.authorizationDetails,
        ))
        save(n)
        return n
    }

    /** Calls userinfo with the current access token and checks `sub`. */
    suspend fun userinfo(): JsonObject {
        val m = discovery()
        val at = getAccessToken()
        val r = transport.send(HttpRequest("GET", endpoint(m.userinfoEndpoint), mapOf("Authorization" to "Bearer $at", "Accept" to "application/json")))
        val o = parseObject(r.body) ?: throw IdentviaException.Network("userinfo returned invalid JSON (${r.status}).")
        if (r.status != 200) throw IdentviaException.Token(o.str("error") ?: "http_${r.status}", o.str("error_description"), r.status)
        val sub = o.str("sub")
        val s = currentSession()
        if (sub == null || (s != null && !constantTimeEquals(sub, s.user.sub))) throw IdentviaException.Validation("userinfo is for a different user.")
        return o
    }

    /**
     * Deletes the local session and revokes the refresh token. Pass a [browser] (`signOut(activity, federated = true)`
     * on Android) with [federated] to also end the Identvia browser session.
     */
    suspend fun signOut(federated: Boolean = false, browser: AuthBrowser? = null, postLogoutRedirectUri: String? = null) {
        val s = currentSession()
        save(null)
        val m = discovery()
        if (s != null && m.revocationEndpoint != null) {
            runCatching {
                val tok = s.tokens.refreshToken ?: s.tokens.accessToken
                transport.send(HttpRequest("POST", endpoint(m.revocationEndpoint), mapOf("Content-Type" to "application/x-www-form-urlencoded"),
                    formEncode(listOf("token" to tok, "token_type_hint" to (if (s.tokens.refreshToken != null) "refresh_token" else "access_token"), "client_id" to clientId))))
            }
        }
        val b = browser ?: this.browser
        if (federated && b != null && m.endSessionEndpoint != null) {
            val back = RedirectUri.validate(postLogoutRedirectUri ?: redirectUri.toString()).toString()
            val q = mutableListOf("client_id" to clientId, "post_logout_redirect_uri" to back)
            s?.tokens?.idToken?.let { q += "id_token_hint" to it }
            val base = endpoint(m.endSessionEndpoint)
            runCatching { b.authenticate(base + (if ('?' in base) "&" else "?") + formEncode(q), back, ephemeralSession) }
        }
    }

    // --------------------------------------------------------------------- http

    private suspend fun validateIdToken(t: String, nonce: String?, maxAge: Int?, accessToken: String?): JsonObject {
        discovery()
        val cache = jwks!!
        return IdTokenValidator.validate(t, IdTokenOptions(issuer, clientId, nonce, maxAge, accessToken, clock() / 1000)) { kid, alg -> cache.key(kid, alg) }
    }

    private suspend fun tokenRequest(fields: List<Pair<String, String>>): TokenSet {
        val m = discovery()
        val r = transport.send(HttpRequest("POST", endpoint(m.tokenEndpoint), mapOf("Content-Type" to "application/x-www-form-urlencoded", "Accept" to "application/json"), formEncode(fields)))
        val o = parseObject(r.body) ?: throw IdentviaException.Network("Token endpoint returned invalid JSON (${r.status}).")
        if (r.status != 200) throw IdentviaException.Token(o.str("error") ?: "http_${r.status}", o.str("error_description"), r.status)
        val at = o.str("access_token")
        if (at == null || !o.str("token_type").equals("bearer", ignoreCase = true)) throw IdentviaException.Validation("Token response has no Bearer access_token.")
        return TokenSet(at, "Bearer", clock() + ((o.num("expires_in") ?: 600.0) * 1000).toLong(), o.str("refresh_token"), o.str("id_token"), o.str("scope"), o["authorization_details"] as? JsonArray)
    }
}
