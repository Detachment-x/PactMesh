package org.pactmesh.android.net

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import org.pactmesh.android.Core
import java.util.concurrent.TimeUnit

/**
 * The console's HTTP API, over loopback. The same endpoints the desktop web UI calls;
 * the phone is just another client of them.
 */
object ApiClient {
    private val http = OkHttpClient.Builder()
        .callTimeout(10, TimeUnit.SECONDS)
        .build()

    suspend fun get(path: String): String = withContext(Dispatchers.IO) {
        val request = Request.Builder()
            .url("http://127.0.0.1:${Core.webPort}$path")
            .header("Authorization", "Bearer ${Core.token}")
            .build()
        http.newCall(request).execute().use { response ->
            val body = response.body?.string().orEmpty()
            require(response.isSuccessful) { "HTTP ${response.code}: $body" }
            body
        }
    }
}
