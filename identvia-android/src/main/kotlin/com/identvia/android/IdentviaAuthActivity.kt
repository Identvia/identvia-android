package com.identvia.android

import android.app.Activity
import android.content.ActivityNotFoundException
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import androidx.browser.customtabs.CustomTabsIntent
import com.identvia.core.IdentviaException

/**
 * Opens the authorization URL in a Custom Tab (or, without a Custom Tabs browser, the default browser),
 * never a WebView, and waits for the redirect. If the user comes back without one, the sign-in is cancelled.
 */
class IdentviaAuthActivity : Activity() {
    private var browserStarted = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        browserStarted = savedInstanceState?.getBoolean(KEY_STARTED) ?: false
        if (PendingAuth.current == null) finish() // process was recreated; the attempt is gone
    }

    override fun onResume() {
        super.onResume()
        val attempt = PendingAuth.current ?: return finish()
        if (!browserStarted) {
            browserStarted = true
            val uri = Uri.parse(attempt.url)
            try {
                CustomTabsIntent.Builder().setShowTitle(true).setShareState(CustomTabsIntent.SHARE_STATE_OFF).build().launchUrl(this, uri)
            } catch (_: ActivityNotFoundException) {
                try {
                    startActivity(Intent(Intent.ACTION_VIEW, uri).addCategory(Intent.CATEGORY_BROWSABLE))
                } catch (e: ActivityNotFoundException) {
                    attempt.result.completeExceptionally(IdentviaException.Configuration("No browser is installed."))
                    finish()
                }
            }
        } else {
            // Back from the browser with no redirect: the user closed it.
            attempt.result.completeExceptionally(IdentviaException.Cancelled())
            PendingAuth.current = null
            finish()
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        val data = intent.data
        val attempt = PendingAuth.current
        if (data != null && attempt != null && PendingAuth.accepts(data)) {
            PendingAuth.current = null
            attempt.result.complete(data.toString())
        }
        finish()
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putBoolean(KEY_STARTED, browserStarted)
    }

    companion object { private const val KEY_STARTED = "identvia.started" }
}

/** Receives the redirect from the browser and hands it to [IdentviaAuthActivity]. Ignores stray intents. */
class IdentviaRedirectActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val data = intent?.data
        if (data != null && PendingAuth.accepts(data)) {
            startActivity(Intent(this, IdentviaAuthActivity::class.java).setData(data).addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP))
        }
        finish()
    }
}
