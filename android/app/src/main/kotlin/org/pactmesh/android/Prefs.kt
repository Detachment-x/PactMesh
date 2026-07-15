package org.pactmesh.android

import android.content.Context

/**
 * How the phone carries mesh traffic. Not a fallback pair — both are first-class.
 *
 * Android hands the VPN slot to exactly one app. [COEXIST] gives it up on purpose so
 * another VPN (FlClash and the like) can hold it and forward into the mesh through the
 * local proxy this mode listens on.
 */
enum class RunMode {
    COEXIST,
    VPN;

    companion object {
        fun parse(name: String?) = entries.firstOrNull { it.name == name } ?: COEXIST
    }
}

object Prefs {
    const val DEFAULT_SOCKS5_PORT = 11080

    private const val FILE = "pactmesh"
    private const val KEY_MODE = "run_mode"
    private const val KEY_PORT = "socks5_port"

    private lateinit var store: android.content.SharedPreferences

    fun init(context: Context) {
        store = context.getSharedPreferences(FILE, Context.MODE_PRIVATE)
    }

    var mode: RunMode
        get() = RunMode.parse(store.getString(KEY_MODE, null))
        set(value) = store.edit().putString(KEY_MODE, value.name).apply()

    var socks5Port: Int
        get() = store.getInt(KEY_PORT, DEFAULT_SOCKS5_PORT)
        set(value) = store.edit().putInt(KEY_PORT, value).apply()
}
