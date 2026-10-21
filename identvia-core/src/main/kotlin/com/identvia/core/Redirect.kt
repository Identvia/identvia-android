package com.identvia.core

import java.net.URI

internal val loopbackHosts = setOf("localhost", "127.0.0.1", "[::1]", "::1")
private val reverseDomain = Regex("^[a-z][a-z0-9+-]*(\\.[a-z0-9+-]+)+$")

object RedirectUri {
    /**
     * Checks a native-app redirect URI (RFC 8252): a verified App Link `https://` URL, an `http://localhost`
     * URL (desktop JVM only), or a reverse-domain private-use scheme such as `com.example.app:/oauth/identvia`.
     */
    fun validate(s: String): URI {
        val u = try { URI(s) } catch (e: Exception) { throw IdentviaException.Configuration("redirectUri is not a valid URI: $s") }
        val scheme = u.scheme?.lowercase() ?: throw IdentviaException.Configuration("redirectUri needs a scheme: $s")
        if (u.rawFragment != null) throw IdentviaException.Configuration("redirectUri must not contain a fragment.")
        if (scheme == "https" && !u.host.isNullOrEmpty()) return u
        if (scheme == "http" && u.host?.lowercase() in loopbackHosts) return u
        if (scheme != "http" && scheme != "https" && reverseDomain.matches(scheme)) return u
        throw IdentviaException.Configuration("redirectUri must be https://, http://localhost, or a reverse-domain scheme such as com.example.app:/callback (RFC 8252). Got $s")
    }

    /** True when [callback] was sent to [registered]: same scheme, host, port and path. */
    fun matches(callback: URI, registered: URI): Boolean {
        fun path(u: URI) = (u.rawPath ?: u.rawSchemeSpecificPart.substringBefore('?')).ifEmpty { "/" }
        return callback.scheme.equals(registered.scheme, ignoreCase = true) &&
            (callback.host ?: "").equals(registered.host ?: "", ignoreCase = true) &&
            callback.port == registered.port &&
            path(callback) == path(registered)
    }
}

internal fun normalizeIssuer(s: String): String {
    val i = s.trim().trimEnd('/')
    val u = try { URI(i) } catch (_: Exception) { null }
    val scheme = u?.scheme?.lowercase()
    val host = u?.host?.lowercase()
    if (u == null || host == null || u.rawQuery != null || u.rawFragment != null ||
        !(scheme == "https" || (scheme == "http" && host in loopbackHosts))) {
        throw IdentviaException.Configuration("issuer must be an https:// URL without query or fragment.")
    }
    return i
}
