package com.identvia.core

import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Test
import java.io.File
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/** Against a REAL Identvia (stage 4+): IDENTVIA_LIVE_STATE=/tmp/live-state.json ./gradlew :identvia-core:test --tests '*LiveTest*' */
class LiveTest {
    @Test fun signInRefreshUserinfoSignOut() = runBlocking {
        val path = System.getenv("IDENTVIA_LIVE_STATE").orEmpty()
        assumeTrue(path.isNotEmpty(), "set IDENTVIA_LIVE_STATE")
        val s = parseObject(File(path).readText())!!
        val helper = File("../../tools/live/helper.php").canonicalPath
        val browser = AuthBrowser { url, redirect, _ ->
            if (url.contains("/oauth/logout")) redirect
            else ProcessBuilder("php", helper, "browse", path, url).start().run { val o = inputStream.bufferedReader().readText().trim(); check(waitFor() == 0) { "helper failed" }; o }
        }
        val store = InMemoryTokenStore()
        val c = IdentviaClient(s.str("base")!!, s.str("publicClientId")!!, s.str("publicRedirect")!!, browser = browser, store = store, refreshLeewayMs = 3_600_000)
        val session = c.signIn()
        assertEquals(s.str("userEmail"), session.user.email)
        val rt1 = store.values.entries.first { it.key.endsWith(".rt") }.value
        c.getAccessToken()
        assertNotEquals(rt1, store.values.entries.first { it.key.endsWith(".rt") }.value)
        assertEquals(session.user.sub, c.userinfo().str("sub"))
        c.signOut()
        assertTrue(store.values.isEmpty())
    }
}
