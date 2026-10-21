package com.identvia.core

import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import java.net.URI
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class Ctx(val idp: FakeIdentvia = FakeIdentvia(), leewayMs: Long = 60_000) {
    val browser = FakeBrowser(idp)
    val store = InMemoryTokenStore()
    val client = IdentviaClient(ISSUER, CLIENT_ID, REDIRECT, browser = browser, store = store, transport = idp, refreshLeewayMs = leewayMs)
}

fun query(url: String) = parseQuery(URI(url).rawQuery)

suspend inline fun <reified T : Throwable> fails(noinline f: suspend () -> Unit): T {
    try { f() } catch (e: Throwable) { if (e is T) return e; throw AssertionError("expected ${T::class.simpleName}, got $e", e) }
    throw AssertionError("expected ${T::class.simpleName}")
}

class PkceTest {
    @Test fun rfc7636Vector() = assertEquals("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", Pkce.challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"))
    @Test fun generate() {
        val a = Pkce.generate(); val b = Pkce.generate()
        assertEquals(43, a.verifier.length); assertNotEquals(a.verifier, b.verifier)
        assertEquals(Pkce.challenge(a.verifier), a.challenge)
        assertFailsWith<IdentviaException.Configuration> { Pkce.challenge("short") }
        assertFailsWith<IdentviaException.Configuration> { Pkce.challenge("a".repeat(42) + "!") }
    }
    @Test fun base64url() {
        assertEquals("-_8", byteArrayOf(0xfb.toByte(), 0xff.toByte()).b64url())
        assertNull("a+b=".b64urlDecode())
    }
}

class ConfigTest {
    @Test fun redirectRules() {
        RedirectUri.validate("com.example.app:/cb"); RedirectUri.validate("https://app.example.com/cb"); RedirectUri.validate("http://127.0.0.1:8123/cb")
        for (bad in listOf("myapp://cb", "http://app.example.com/cb", "com.example.app:/cb#x", "javascript:alert(1)", "not a uri")) {
            assertFailsWith<IdentviaException.Configuration>(bad) { RedirectUri.validate(bad) }
        }
        assertTrue(RedirectUri.matches(URI("com.example.app:/cb?code=1"), URI("com.example.app:/cb")))
        assertFalse(RedirectUri.matches(URI("com.example.app:/cb2?code=1"), URI("com.example.app:/cb")))
        assertFalse(RedirectUri.matches(URI("https://evil.example/cb"), URI("https://app.example.com/cb")))
    }
    @Test fun issuerAndClient() {
        assertFailsWith<IdentviaException.Configuration> { IdentviaClient("http://id.identvia.com", "x", REDIRECT, store = InMemoryTokenStore()) }
        assertFailsWith<IdentviaException.Configuration> { IdentviaClient(clientId = " ", redirectUri = REDIRECT, store = InMemoryTokenStore()) }
        assertEquals("https://id.identvia.com", IdentviaClient("https://id.identvia.com/", "x", REDIRECT, store = InMemoryTokenStore()).issuer)
    }
}

class SignInTest {
    @Test fun fullFlow() = runTest {
        val c = Ctx()
        val s = c.client.signIn(prompt = "login")
        assertEquals(c.idp.userSub, s.user.sub); assertEquals("ada@example.com", s.user.email)
        val q = query(c.browser.opened.single())
        assertEquals("S256", q["code_challenge_method"]); assertEquals("openid email profile offline_access", q["scope"]); assertEquals("login", q["prompt"])
        assertEquals(setOf("identvia.$CLIENT_ID.session", "identvia.$CLIENT_ID.rt"), c.store.values.keys)
        assertFalse(c.store.values["identvia.$CLIENT_ID.session"]!!.contains("rt_"))
        assertTrue(c.idp.requests.none { it.body?.contains("client_secret") == true })
        assertEquals(s, c.client.session.value)
    }
    @Test fun cancelled() = runTest {
        val c = Ctx().apply { browser.cancel = true }
        fails<IdentviaException.Cancelled> { c.client.signIn() }
        assertTrue(c.store.values.isEmpty())
    }
    @Test fun accessDenied() = runTest {
        val c = Ctx().apply { browser.deny = true }
        val e = fails<IdentviaException.Authorization> { c.client.signIn() }
        assertEquals("access_denied", e.error); assertEquals("The user denied access", e.description)
    }
    @Test fun forgedState() = runTest {
        val c = Ctx().apply { browser.tamper = { it.replace(Regex("state=[^&]+"), "state=forged") } }
        fails<IdentviaException.InvalidState> { c.client.signIn() }
    }
    @Test fun otherAppsRedirect() = runTest {
        val c = Ctx().apply { browser.tamper = { it.replace("com.example.notes:", "com.evil.app:") } }
        fails<IdentviaException.InvalidState> { c.client.signIn() }
    }
    @Test fun issMixUp() = runTest {
        fails<IdentviaException.InvalidState> { Ctx(FakeIdentvia().apply { wrongIss = true }).client.signIn() }
        fails<IdentviaException.InvalidState> { Ctx(FakeIdentvia().apply { omitIss = true }).client.signIn() }
    }
    @Test fun nonceReplay() = runTest {
        val e = fails<IdentviaException.Validation> { Ctx(FakeIdentvia().apply { forceNonce = "attacker" }).client.signIn() }
        assertTrue("nonce" in e.message!!)
    }
    @Test fun codeReplayAndWrongVerifier() = runTest {
        val c = Ctx()
        val (url, tx) = c.client.createAuthorizationRequest()
        val cb = c.idp.authorize(url)
        c.client.completeAuthorization(cb, tx)
        assertEquals("invalid_grant", fails<IdentviaException.Token> { c.client.completeAuthorization(cb, tx) }.error)
        val (url2, tx2) = c.client.createAuthorizationRequest()
        val e = fails<IdentviaException.Token> { c.client.completeAuthorization(c.idp.authorize(url2), tx2.copy(codeVerifier = Pkce.generate().verifier)) }
        assertTrue("PKCE" in e.description!!)
    }
}

class IdTokenTest {
    private val k1 = buildJsonObject { put("alg", "RS256"); put("kid", "k1") }

    private suspend fun reject(needle: String, header: JsonObject = k1, key: java.security.KeyPair? = null, patch: (JsonObject) -> JsonObject = { it }) {
        val idp = FakeIdentvia()
        idp.idTokenOverride = { signRs256(header, patch(it), key ?: idp.rsa) }
        val e = fails<IdentviaException.Validation> { Ctx(idp).client.signIn() }
        assertTrue(needle in e.message!!, "expected '$needle' in '${e.message}'")
    }

    @Test fun wrongIssuer() = runTest { reject("issuer") { it.with("iss" to JsonPrimitive("https://evil.example")) } }
    @Test fun wrongAudience() = runTest { reject("aud") { it.with("aud" to JsonPrimitive("other"), "azp" to JsonPrimitive("other")) } }
    @Test fun multiAudNeedsAzp() = runTest { reject("azp") { it.with("aud" to JsonArray(listOf(JsonPrimitive(CLIENT_ID), JsonPrimitive("other"))), "azp" to null) } }
    @Test fun expired() = runTest { reject("expired") { it.with("exp" to JsonPrimitive(1000), "iat" to JsonPrimitive(900)) } }
    @Test fun futureIat() = runTest { reject("future") { it.with("iat" to JsonPrimitive(System.currentTimeMillis() / 1000 + 3600)) } }
    @Test fun missingSub() = runTest { reject("sub") { it.with("sub" to null) } }
    @Test fun atHash() = runTest { reject("at_hash") { it.with("at_hash" to JsonPrimitive("AAAAAAAAAAAAAAAAAAAAAA")) } }
    @Test fun otherKey() = runTest { reject("signature", key = rsaKeys()) }
    @Test fun unknownKid() = runTest { reject("unknown key", header = buildJsonObject { put("alg", "RS256"); put("kid", "nope") }) }
    @Test fun algNone() = runTest {
        val idp = FakeIdentvia().apply { idTokenOverride = { "${b64json(buildJsonObject { put("alg", "none"); put("kid", "k1") })}.${b64json(it)}." } }
        assertTrue("none" in fails<IdentviaException.Validation> { Ctx(idp).client.signIn() }.message!!)
    }
    @Test fun hs256Confusion() = runTest {
        val idp = FakeIdentvia()
        idp.idTokenOverride = {
            val input = "${b64json(buildJsonObject { put("alg", "HS256"); put("kid", "k1") })}.${b64json(it)}"
            val n = (idp.rsa.public as java.security.interfaces.RSAPublicKey).modulus.unsigned()
            val mac = Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(n, "HmacSHA256")) }.doFinal(input.toByteArray())
            "$input.${mac.b64url()}"
        }
        assertTrue("HS256" in fails<IdentviaException.Validation> { Ctx(idp).client.signIn() }.message!!)
    }
    @Test fun es256Accepted() = runTest {
        val idp = FakeIdentvia(); val ec = ecKeys(); idp.ec = ec
        idp.idTokenOverride = { signEs256(buildJsonObject { put("alg", "ES256"); put("kid", "ec1") }, it, ec) }
        assertEquals(idp.userSub, Ctx(idp).client.signIn().user.sub)
    }
    @Test fun keyRotationRefetchIsRateLimited() = runTest {
        val idp = FakeIdentvia(); val c = Ctx(idp)
        c.client.signIn(); assertEquals(1, idp.jwksFetches)
        idp.rsa = rsaKeys(); idp.kid = "k2"
        fails<IdentviaException.Validation> { c.client.signIn() }
        assertEquals(1, idp.jwksFetches, "refetch is rate limited within 30 s")
        Ctx(idp).client.signIn()
    }
    @Test fun maxAge() = runTest {
        val idp = FakeIdentvia()
        idp.idTokenOverride = { signRs256(k1, it.with("auth_time" to JsonPrimitive(System.currentTimeMillis() / 1000 - 7200)), idp.rsa) }
        assertTrue("max_age" in fails<IdentviaException.Validation> { Ctx(idp).client.signIn(maxAge = 60) }.message!!)
    }
}

class TokenTest {
    @Test fun rotationSingleFlight() = runTest {
        val c = Ctx(leewayMs = 3_600_000)
        c.client.signIn()
        val rt1 = c.store.values["identvia.$CLIENT_ID.rt"]
        c.idp.tokenDelayMs = 50
        val r = (1..3).map { async { c.client.getAccessToken() } }.awaitAll()
        assertEquals(1, r.toSet().size)
        assertEquals(1, c.idp.requests.count { it.url.endsWith("/oauth/token") && it.body!!.contains("grant_type=refresh_token") })
        assertNotEquals(rt1, c.store.values["identvia.$CLIENT_ID.rt"])
    }
    @Test fun reuseDetectionSignsOut() = runTest {
        val c = Ctx(leewayMs = 3_600_000)
        c.client.signIn()
        val old = c.store.values["identvia.$CLIENT_ID.rt"]!!
        c.client.getAccessToken()
        c.idp.send(HttpRequest("POST", "$ISSUER/oauth/token", body = "grant_type=refresh_token&refresh_token=$old&client_id=$CLIENT_ID"))
        fails<IdentviaException.LoginRequired> { c.client.getAccessToken() }
        assertTrue(c.store.values.isEmpty()); assertNull(c.client.currentSession()); assertNull(c.client.session.value)
    }
    @Test fun freshTokenNoRefresh() = runTest {
        val c = Ctx()
        val s = c.client.signIn()
        assertEquals(s.tokens.accessToken, c.client.getAccessToken())
        assertEquals(1, c.idp.requests.count { it.url.endsWith("/oauth/token") })
    }
    @Test fun restoreAndUserinfo() = runTest {
        val c = Ctx(); c.client.signIn()
        val again = IdentviaClient(ISSUER, CLIENT_ID, REDIRECT, browser = c.browser, store = c.store, transport = c.idp)
        val s = again.currentSession()
        assertEquals(c.idp.userSub, s?.user?.sub); assertNotNull(s?.tokens?.refreshToken)
        assertEquals(c.idp.userSub, again.userinfo()["sub"]!!.jsonPrimitive.content)
    }
    @Test fun signOut() = runTest {
        val c = Ctx(); c.client.signIn()
        c.client.signOut(federated = true)
        assertEquals(1, c.idp.revokedFamilies.size); assertTrue(c.store.values.isEmpty())
        val q = query(c.browser.opened.last())
        assertNotNull(q["id_token_hint"]); assertEquals(REDIRECT, q["post_logout_redirect_uri"])
    }
    @Test fun rarNeedsStage5() = runTest {
        val e = fails<IdentviaException.Unsupported> { Ctx().client.signIn(authorizationDetails = listOf(AuthorizationDetail.agentTask("x"))) }
        assertTrue("2026-10-21_5" in e.message!!)
        val s = Ctx(FakeIdentvia(stage5 = true)).client.signIn(authorizationDetails = listOf(AuthorizationDetail.agentTask("Order groceries", actions = listOf("order"))))
        val d = s.tokens.authorizationDetails!!.first().jsonObject
        assertEquals("agent_task", d["type"]!!.jsonPrimitive.content)
        assertEquals("order", (d["actions"] as JsonArray).first().jsonPrimitive.content)
    }
}
