package com.identvia.core

import java.net.URLDecoder
import java.net.URLEncoder
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64

private val rng = SecureRandom()

fun ByteArray.b64url(): String = Base64.getUrlEncoder().withoutPadding().encodeToString(this)

fun String.b64urlDecode(): ByteArray? {
    if (!all { it.isLetterOrDigit() && it.code < 128 || it == '-' || it == '_' }) return null
    return try { Base64.getUrlDecoder().decode(this) } catch (_: IllegalArgumentException) { null }
}

/** `n` bytes from SecureRandom, base64url encoded. */
fun randomToken(bytes: Int = 32): String = ByteArray(bytes).also { rng.nextBytes(it) }.b64url()

internal fun sha256(s: String): ByteArray = MessageDigest.getInstance("SHA-256").digest(s.toByteArray(Charsets.US_ASCII))

internal fun constantTimeEquals(a: String, b: String): Boolean =
    MessageDigest.isEqual(a.toByteArray(Charsets.UTF_8), b.toByteArray(Charsets.UTF_8))

internal fun enc(s: String): String = URLEncoder.encode(s, "UTF-8").replace("+", "%20")

internal fun formEncode(fields: List<Pair<String, String>>): String = fields.joinToString("&") { "${enc(it.first)}=${enc(it.second)}" }

internal fun parseQuery(q: String?): Map<String, String> {
    if (q.isNullOrEmpty()) return emptyMap()
    val out = LinkedHashMap<String, String>()
    for (part in q.split('&')) {
        if (part.isEmpty()) continue
        val i = part.indexOf('=')
        val k = URLDecoder.decode(if (i < 0) part else part.substring(0, i), "UTF-8")
        val v = if (i < 0) "" else URLDecoder.decode(part.substring(i + 1), "UTF-8")
        if (k !in out) out[k] = v
    }
    return out
}
