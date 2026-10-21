package com.identvia.android

import kotlinx.coroutines.CompletableDeferred

/** The one sign-in in flight. The redirect is only accepted while an attempt is pending. */
internal object PendingAuth {
    @Volatile var current: Attempt? = null

    class Attempt(val url: String, val redirectUri: String) {
        val result = CompletableDeferred<String>()
    }

    /** True when [uri] is for the redirect URI of the current attempt (same scheme, host and path). */
    fun accepts(uri: android.net.Uri): Boolean {
        val a = current ?: return false
        val r = android.net.Uri.parse(a.redirectUri)
        return uri.scheme.equals(r.scheme, true) && (uri.host ?: "").equals(r.host ?: "", true) &&
            uri.port == r.port && (uri.path ?: "").ifEmpty { "/" } == (r.path ?: "").ifEmpty { "/" }
    }
}
