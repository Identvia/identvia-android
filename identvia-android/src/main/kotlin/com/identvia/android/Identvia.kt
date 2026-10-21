package com.identvia.android

import android.app.Activity
import android.content.Context
import com.identvia.core.AuthorizationDetail
import com.identvia.core.DEFAULT_ISSUER
import com.identvia.core.IdentviaClient
import com.identvia.core.IdentviaSession

object Identvia {
    /**
     * The usual Android setup: Custom Tabs + AndroidKeyStore storage. A public client, so there's no secret.
     * Create it once (for example in your Application) and reuse it.
     */
    fun client(
        context: Context,
        clientId: String,
        redirectUri: String,
        issuer: String = DEFAULT_ISSUER,
        scopes: List<String> = listOf("email", "profile", "offline_access"),
    ): IdentviaClient = IdentviaClient(issuer = issuer, clientId = clientId, redirectUri = redirectUri, scopes = scopes,
        store = KeystoreTokenStore(context, "identvia_" + clientId.replace(Regex("[^A-Za-z0-9_]"), "_")))
}

/** Signs in with a Custom Tab started from [activity]. */
suspend fun IdentviaClient.signIn(
    activity: Activity, scopes: List<String>? = null, prompt: String? = null, maxAge: Int? = null, loginHint: String? = null,
    uiLocales: List<String>? = null, authorizationDetails: List<AuthorizationDetail>? = null,
): IdentviaSession = signIn(CustomTabsBrowser(activity), scopes, prompt, maxAge, loginHint, uiLocales, authorizationDetails)

/** Signs out. With [federated], it also ends the Identvia browser session in a Custom Tab. */
suspend fun IdentviaClient.signOut(activity: Activity, federated: Boolean = false) =
    signOut(federated = federated, browser = CustomTabsBrowser(activity))
