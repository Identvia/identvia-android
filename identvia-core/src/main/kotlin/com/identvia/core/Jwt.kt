package com.identvia.core

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.security.spec.RSAPublicKeySpec

/** A key from the Identvia JWKS. */
data class Jwk(val kty: String, val kid: String?, val use: String?, val alg: String?, val n: String?, val e: String?, val crv: String?, val x: String?, val y: String?) {
    companion object {
        fun from(o: JsonObject) = o.str("kty")?.let { Jwk(it, o.str("kid"), o.str("use"), o.str("alg"), o.str("n"), o.str("e"), o.str("crv"), o.str("x"), o.str("y")) }
    }
}

internal class CompactJws(token: String) {
    val header: JsonObject
    val payload: JsonObject
    val signingInput: ByteArray
    val signature: ByteArray

    init {
        val parts = token.split('.')
        if (parts.size != 3) throw IdentviaException.Validation("ID token is not a compact JWS.")
        header = parts[0].b64urlDecode()?.let { parseObject(String(it, Charsets.UTF_8)) } ?: throw IdentviaException.Validation("ID token is malformed.")
        payload = parts[1].b64urlDecode()?.let { parseObject(String(it, Charsets.UTF_8)) } ?: throw IdentviaException.Validation("ID token is malformed.")
        signature = parts[2].b64urlDecode() ?: throw IdentviaException.Validation("ID token is malformed.")
        signingInput = "${parts[0]}.${parts[1]}".toByteArray(Charsets.US_ASCII)
    }
}

internal object JwsVerifier {
    val allowed = setOf("RS256", "ES256")

    private val p256: ECParameterSpec by lazy {
        AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec("secp256r1")) }.getParameterSpec(ECParameterSpec::class.java)
    }

    fun verify(jws: CompactJws, alg: String, key: Jwk): Boolean {
        if (key.alg != null && key.alg != alg) throw IdentviaException.Validation("Key ${key.kid} is for ${key.alg}, not $alg.")
        if (key.use != null && key.use != "sig") throw IdentviaException.Validation("Key is not a signing key.")
        return when (alg) {
            "RS256" -> {
                val n = key.n?.b64urlDecode(); val e = key.e?.b64urlDecode()
                if (key.kty != "RSA" || n == null || e == null) throw IdentviaException.Validation("RS256 needs an RSA key.")
                val pk = KeyFactory.getInstance("RSA").generatePublic(RSAPublicKeySpec(BigInteger(1, n), BigInteger(1, e)))
                if (BigInteger(1, n).bitLength() < 2048) throw IdentviaException.Validation("RSA key is shorter than 2048 bits.")
                Signature.getInstance("SHA256withRSA").run { initVerify(pk); update(jws.signingInput); verify(jws.signature) }
            }
            "ES256" -> {
                val x = key.x?.b64urlDecode(); val y = key.y?.b64urlDecode()
                if (key.kty != "EC" || key.crv != "P-256" || x?.size != 32 || y?.size != 32) throw IdentviaException.Validation("ES256 needs a P-256 key.")
                if (jws.signature.size != 64) return false
                val pk = KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(ECPoint(BigInteger(1, x), BigInteger(1, y)), p256))
                Signature.getInstance("SHA256withECDSA").run { initVerify(pk); update(jws.signingInput); verify(rawToDer(jws.signature)) }
            }
            else -> throw IdentviaException.Validation("alg $alg is not allowed.")
        }
    }

    /** JOSE r||s to ASN.1 DER, which java.security expects. */
    fun rawToDer(raw: ByteArray): ByteArray {
        fun int(b: ByteArray): ByteArray {
            var v = b.dropWhile { it == 0.toByte() }.toByteArray()
            if (v.isEmpty()) v = byteArrayOf(0)
            if (v[0].toInt() and 0x80 != 0) v = byteArrayOf(0) + v
            return byteArrayOf(0x02, v.size.toByte()) + v
        }
        val body = int(raw.copyOfRange(0, 32)) + int(raw.copyOfRange(32, 64))
        return byteArrayOf(0x30, body.size.toByte()) + body
    }
}

/** Caches the JWKS. An unknown `kid` triggers one refetch, at most every 30 seconds (key rotation). */
internal class JwksCache(private val url: String, private val transport: HttpTransport, private val clock: () -> Long) {
    private val mutex = Mutex()
    private var keys: List<Jwk>? = null
    private var lastFetch = 0L
    var fetchCount = 0; private set

    suspend fun key(kid: String?, alg: String): Jwk? = mutex.withLock {
        if (keys == null) load()
        find(kid, alg)?.let { return it }
        if (clock() - lastFetch < 30_000) return null
        load()
        find(kid, alg)
    }

    private fun find(kid: String?, alg: String): Jwk? {
        val kty = if (alg.startsWith("ES")) "EC" else "RSA"
        val c = keys.orEmpty().filter { it.kty == kty && (it.use == null || it.use == "sig") }
        return if (kid != null) c.firstOrNull { it.kid == kid } else c.singleOrNull()
    }

    private suspend fun load() {
        val r = transport.send(HttpRequest("GET", url, mapOf("Accept" to "application/json")))
        fetchCount++
        lastFetch = clock()
        val arr = parseObject(r.body)?.get("keys") as? JsonArray
        if (r.status != 200 || arr == null) throw IdentviaException.Network("Could not load the JWKS (${r.status}).")
        keys = arr.mapNotNull { (it as? JsonObject)?.let(Jwk::from) }
    }
}
