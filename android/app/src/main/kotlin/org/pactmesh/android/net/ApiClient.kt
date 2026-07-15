package org.pactmesh.android.net

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.pactmesh.android.Core
import java.util.concurrent.TimeUnit

/**
 * The console's HTTP API, over loopback. The same endpoints the desktop web UI calls;
 * the phone is just another client of them.
 */
object ApiClient {
    private val http = OkHttpClient.Builder()
        .callTimeout(15, TimeUnit.SECONDS)
        .build()

    // proto `optional` fields ride the wire as an explicit `null` when unset; coerce lets
    // any such null fall back to the model's default instead of throwing mid-parse.
    val json = Json {
        ignoreUnknownKeys = true
        coerceInputValues = true
    }

    private val JSON_MEDIA = "application/json".toMediaType()

    suspend fun get(path: String): String = call(
        Request.Builder().url(url(path)).get()
    )

    suspend fun post(path: String, body: String): String = call(
        Request.Builder().url(url(path)).post(body.toRequestBody(JSON_MEDIA))
    )

    private fun url(path: String) = "http://127.0.0.1:${Core.webPort}$path"

    private suspend fun call(builder: Request.Builder): String = withContext(Dispatchers.IO) {
        val request = builder.header("Authorization", "Bearer ${Core.token}").build()
        http.newCall(request).execute().use { response ->
            val body = response.body?.string().orEmpty()
            require(response.isSuccessful) { "HTTP ${response.code}: $body" }
            body
        }
    }
}
