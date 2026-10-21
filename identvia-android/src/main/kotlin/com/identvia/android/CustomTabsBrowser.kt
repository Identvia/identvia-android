package com.identvia.android

import android.app.Activity
import android.content.Intent
import com.identvia.core.AuthBrowser
import com.identvia.core.IdentviaException
import kotlinx.coroutines.CancellationException

/**
 * The Android [AuthBrowser]: a Custom Tab started from [activity]. `ephemeral` is ignored on Android;
 * use `prompt = "login"` to force a fresh sign-in.
 */
class CustomTabsBrowser(private val activity: Activity) : AuthBrowser {
    override suspend fun authenticate(url: String, redirectUri: String, ephemeral: Boolean): String {
        PendingAuth.current?.result?.completeExceptionally(IdentviaException.Cancelled())
        val attempt = PendingAuth.Attempt(url, redirectUri)
        PendingAuth.current = attempt
        activity.startActivity(Intent(activity, IdentviaAuthActivity::class.java))
        try {
            return attempt.result.await()
        } catch (e: CancellationException) {
            if (PendingAuth.current === attempt) PendingAuth.current = null
            throw e
        }
    }
}
