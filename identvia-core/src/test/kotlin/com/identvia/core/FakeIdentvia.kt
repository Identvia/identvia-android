package com.identvia.core

import kotlinx.coroutines.delay
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.math.BigInteger
import java.net.URI
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.ECGenParameterSpec

const val ISSUER = "https://id.identvia.test"
const val CLIENT_ID = "oid_android_test"
const val REDIRECT = "com.example.notes:/oauth/identvia"

fun rsaKeys(): KeyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
fun ecKeys(): KeyPair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
val sharedRsa: KeyPair by lazy { rsaKeys() }

fun b64json(o: JsonObject) = o.toString().toByteArray().b64url()
fun BigInteger.unsigned(len: Int? = null): ByteArray {
    var b = toByteArray().dropWhile { it == 0.toByte() }.toByteArray()
    if (len != null && b.size < len) b = ByteArray(len - b.size) + b
    return b
}

fun signRs256(header: JsonObject, claims: JsonObject, kp: KeyPair): String {
    val input = "${b64json(header)}.${b64json(claims)}"
    val sig = Signature.getInstance("SHA256withRSA").run { initSign(kp.private); update(input.toByteArray()); sign() }
    return "$input.${sig.b64url()}"
}

fun signEs256(header: JsonObject, claims: JsonObject, kp: KeyPair): String {
    val input = "${b64json(header)}.${b64json(claims)}"
    val der = Signature.getInstance("SHA256withECDSA").run { initSign(kp.private); update(input.toByteArray()); sign() }
    // DER SEQUENCE { INTEGER r, INTEGER s } -> r||s
    var i = 2
    fun int(): ByteArray { check(der[i] == 0x02.toByte()); val l = der[i + 1].toInt(); val v = der.copyOfRange(i + 2, i + 2 + l); i += 2 + l; return BigInteger(1, v).unsigned(32) }
    return "$input.${(int() + int()).b64url()}"
}

fun JsonObject.with(vararg kv: Pair<String, JsonElement?>): JsonObject {
    val m = toMutableMap()
    for ((k, v) in kv) if (v == null) m.remove(k) else m[k] = v
    return JsonObject(m)
}

/** In-memory Identvia that enforces the real server's rules (PKCE S256, nonce, iss, rotation with reuse detection). */
class FakeIdentvia(var stage5: Boolean = false) : HttpTransport {
    var rsa = sharedRsa
    var ec: KeyPair? = null
    var kid = "k1"
    val redirectUris = mutableListOf(REDIRECT)
    var forceNonce: String? = null
    var wrongIss = false
    var omitIss = false
    var idTokenOverride: ((JsonObject) -> String)? = null
    val userSub = "pw_" + randomToken(9)
    private val codes = HashMap<String, MutableMap<String, Any?>>()
    private val refresh = HashMap<String, MutableMap<String, Any?>>()
    val revokedFamilies = HashSet<String>()
    private val access = HashMap<String, String>()
    val requests = mutableListOf<HttpRequest>()
    var jwksFetches = 0
    var tokenDelayMs = 0L

    private fun discovery() = buildJsonObject {
        put("issuer", ISSUER)
        put("authorization_endpoint", "$ISSUER/oauth/authorize")
        put("token_endpoint", "$ISSUER/oauth/token")
        put("userinfo_endpoint", "$ISSUER/oauth/userinfo")
        put("jwks_uri", "$ISSUER/oauth/jwks.json")
        put("revocation_endpoint", "$ISSUER/oauth/revoke")
        put("end_session_endpoint", "$ISSUER/oauth/logout")
        put("code_challenge_methods_supported", JsonArray(listOf(JsonPrimitive("S256"))))
        put("authorization_response_iss_parameter_supported", true)
        if (stage5) put("authorization_details_types_supported", JsonArray(listOf(JsonPrimitive("agent_task"))))
    }

    private fun jwks(): JsonObject {
        val pub = rsa.public as RSAPublicKey
        val keys = mutableListOf<JsonElement>(buildJsonObject {
            put("kty", "RSA"); put("kid", kid); put("use", "sig"); put("alg", "RS256")
            put("n", pub.modulus.unsigned().b64url()); put("e", pub.publicExponent.unsigned().b64url())
        })
        ec?.let { k ->
            val p = (k.public as ECPublicKey).w
            keys += buildJsonObject {
                put("kty", "EC"); put("kid", "ec1"); put("use", "sig"); put("alg", "ES256"); put("crv", "P-256")
                put("x", p.affineX.unsigned(32).b64url()); put("y", p.affineY.unsigned(32).b64url())
            }
        }
        return JsonObject(mapOf("keys" to JsonArray(keys)))
    }

    fun idToken(sub: String, nonce: String?, at: String): String {
        val now = System.currentTimeMillis() / 1000
        val c = buildJsonObject {
            put("iss", ISSUER); put("sub", sub); put("aud", CLIENT_ID); put("azp", CLIENT_ID)
            put("iat", now); put("exp", now + 600); put("auth_time", now)
            put("email", "ada@example.com"); put("email_verified", true); put("name", "Ada")
            put("at_hash", MessageDigest.getInstance("SHA-256").digest(at.toByteArray()).copyOf(16).b64url())
            nonce?.let { put("nonce", it) }
        }
        idTokenOverride?.let { return it(c) }
        return signRs256(buildJsonObject { put("alg", "RS256"); put("kid", kid); put("typ", "JWT") }, c, rsa)
    }

    private fun issue(sub: String, scope: String, nonce: String?, family: String? = null): JsonObject {
        val at = "at_" + randomToken(18)
        val out = mutableMapOf<String, JsonElement>("token_type" to JsonPrimitive("Bearer"), "access_token" to JsonPrimitive(at), "expires_in" to JsonPrimitive(600), "scope" to JsonPrimitive(scope))
        val scopes = scope.split(" ")
        if ("openid" in scopes && family == null) out["id_token"] = JsonPrimitive(idToken(sub, nonce, at))
        var fam = family ?: ""
        if ("offline_access" in scopes) {
            if (fam.isEmpty()) fam = randomToken(6)
            val rt = "rt_" + randomToken(18)
            refresh[rt] = mutableMapOf("family" to fam, "used" to false, "sub" to sub, "scope" to scope)
            out["refresh_token"] = JsonPrimitive(rt)
        }
        access[at] = fam
        return JsonObject(out)
    }

    private fun err(status: Int, e: String, d: String? = null) = HttpResponse(status, buildJsonObject { put("error", e); d?.let { put("error_description", it) } }.toString())

    override suspend fun send(request: HttpRequest): HttpResponse {
        if (request.url.endsWith("/oauth/token") && tokenDelayMs > 0) delay(tokenDelayMs)
        synchronized(this) { return handle(request) }
    }

    private fun handle(r: HttpRequest): HttpResponse {
        requests += r
        val f = parseQuery(r.body)
        return when (URI(r.url).path) {
            "/.well-known/openid-configuration" -> HttpResponse(200, discovery().toString())
            "/oauth/jwks.json" -> { jwksFetches++; HttpResponse(200, jwks().toString()) }
            "/oauth/token" -> {
                if (f["client_id"] != CLIENT_ID || "client_secret" in f) return err(401, "invalid_client")
                when (f["grant_type"]) {
                    "authorization_code" -> {
                        val c = codes[f["code"]] ?: return err(400, "invalid_grant")
                        if (c["used"] == true) return err(400, "invalid_grant")
                        c["used"] = true
                        if (c["redirect_uri"] != f["redirect_uri"]) return err(400, "invalid_grant")
                        if (sha256(f["code_verifier"] ?: "").b64url() != c["challenge"]) return err(400, "invalid_grant", "PKCE verification failed")
                        var out = issue(c["sub"] as String, c["scope"] as String, c["nonce"] as String?)
                        (c["details"] as String?)?.let { out = out.with("authorization_details" to json.parseToJsonElement(it)) }
                        HttpResponse(200, out.toString())
                    }
                    "refresh_token" -> {
                        val x = refresh[f["refresh_token"]] ?: return err(400, "invalid_grant")
                        val fam = x["family"] as String
                        if (fam in revokedFamilies) return err(400, "invalid_grant")
                        if (x["used"] == true) { revokedFamilies += fam; return err(400, "invalid_grant", "Refresh token reuse detected") }
                        x["used"] = true
                        HttpResponse(200, issue(x["sub"] as String, x["scope"] as String, null, fam).toString())
                    }
                    else -> err(400, "unsupported_grant_type")
                }
            }
            "/oauth/userinfo" -> {
                val fam = access[(r.headers["Authorization"] ?: "").removePrefix("Bearer ")]
                if (fam == null || fam in revokedFamilies) err(401, "invalid_token")
                else HttpResponse(200, buildJsonObject { put("sub", userSub); put("email", "ada@example.com") }.toString())
            }
            "/oauth/revoke" -> { refresh[f["token"]]?.let { revokedFamilies += it["family"] as String }; HttpResponse(200, "") }
            else -> err(404, "not_found")
        }
    }

    /** The user signs in and approves; returns the redirect Identvia would send. */
    @Synchronized
    fun authorize(url: String, deny: Boolean = false): String {
        val q = parseQuery(URI(url).rawQuery)
        val ru = q["redirect_uri"]
        check(ru in redirectUris) { "Invalid redirect" }
        check(q["code_challenge_method"] == "S256" && q["nonce"] != null && q["state"] != null) { "bad request" }
        val p = mutableListOf("state" to q["state"]!!)
        if (!omitIss) p += "iss" to (if (wrongIss) "https://evil.example" else ISSUER)
        if (deny) {
            p += "error" to "access_denied"; p += "error_description" to "The user denied access"
        } else {
            val code = "c_" + randomToken(18)
            codes[code] = mutableMapOf("challenge" to q["code_challenge"], "redirect_uri" to ru, "nonce" to (forceNonce ?: q["nonce"]),
                "scope" to q["scope"], "sub" to userSub, "used" to false, "details" to q["authorization_details"])
            p += "code" to code
        }
        return "$ru?${formEncode(p)}"
    }
}

class FakeBrowser(private val idp: FakeIdentvia) : AuthBrowser {
    var deny = false
    var cancel = false
    var tamper: ((String) -> String)? = null
    val opened = mutableListOf<String>()
    override suspend fun authenticate(url: String, redirectUri: String, ephemeral: Boolean): String {
        opened += url
        if (cancel) throw IdentviaException.Cancelled()
        if (URI(url).path == "/oauth/logout") return redirectUri
        val cb = idp.authorize(url, deny)
        return tamper?.invoke(cb) ?: cb
    }
}
