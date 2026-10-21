package com.identvia.core

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL

class HttpRequest(val method: String, val url: String, val headers: Map<String, String> = emptyMap(), val body: String? = null)
class HttpResponse(val status: Int, val body: String)

/** Sends HTTP requests. Swap it for tests, OkHttp or certificate pinning. */
fun interface HttpTransport {
    suspend fun send(request: HttpRequest): HttpResponse
}

/** The default transport: HttpURLConnection on Dispatchers.IO. */
class UrlConnectionTransport(private val timeoutMs: Int = 15_000) : HttpTransport {
    override suspend fun send(request: HttpRequest): HttpResponse = withContext(Dispatchers.IO) {
        try {
            val c = URL(request.url).openConnection() as HttpURLConnection
            c.requestMethod = request.method
            c.connectTimeout = timeoutMs
            c.readTimeout = timeoutMs
            c.instanceFollowRedirects = false
            c.useCaches = false
            request.headers.forEach { (k, v) -> c.setRequestProperty(k, v) }
            if (request.body != null) {
                c.doOutput = true
                c.outputStream.use { it.write(request.body.toByteArray(Charsets.UTF_8)) }
            }
            val status = c.responseCode
            val stream = if (status >= 400) c.errorStream else c.inputStream
            val body = stream?.bufferedReader()?.use { it.readText() } ?: ""
            c.disconnect()
            HttpResponse(status, body)
        } catch (e: IOException) {
            throw IdentviaException.Network(e.message ?: "Network error", e)
        }
    }
}
