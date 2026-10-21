package com.example.identvianotes

import android.app.Activity
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.TextView
import androidx.activity.ComponentActivity
import androidx.lifecycle.lifecycleScope
import com.identvia.android.Identvia
import com.identvia.android.signIn
import com.identvia.android.signOut
import com.identvia.core.IdentviaException
import com.identvia.core.IdentviaSession
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {
    // Public client: never put a client secret in an app.
    private val identvia by lazy {
        Identvia.client(applicationContext, BuildConfig.IDENTVIA_CLIENT_ID, "com.example.identvianotes:/oauth/identvia")
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        val activity: Activity = this
        findViewById<View>(R.id.signIn).setOnClickListener { run { render(identvia.signIn(activity)) } }
        findViewById<Button>(R.id.userinfo).setOnClickListener { run { status("userinfo: ${identvia.userinfo()}") } }
        findViewById<Button>(R.id.signOut).setOnClickListener { run { identvia.signOut(activity); render(null) } }
        lifecycleScope.launch { render(identvia.currentSession()) }
    }

    private fun run(block: suspend () -> Unit) = lifecycleScope.launch {
        try { block() } catch (_: IdentviaException.Cancelled) {} catch (e: IdentviaException) { status(e.message ?: "error") }
    }

    private fun status(s: String) { findViewById<TextView>(R.id.status).text = s }

    private fun render(s: IdentviaSession?) {
        findViewById<View>(R.id.signIn).visibility = if (s == null) View.VISIBLE else View.GONE
        findViewById<View>(R.id.userinfo).visibility = if (s == null) View.GONE else View.VISIBLE
        findViewById<View>(R.id.signOut).visibility = if (s == null) View.GONE else View.VISIBLE
        status(s?.let { "Signed in as ${it.user.name ?: it.user.email ?: it.user.sub}\nPairwise sub: ${it.user.sub}" } ?: "")
    }
}
