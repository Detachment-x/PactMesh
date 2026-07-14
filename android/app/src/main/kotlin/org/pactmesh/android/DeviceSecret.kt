package org.pactmesh.android

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.File
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * The device identity `secret_seal` keys off.
 *
 * On desktop that role is played by the OS machine id, which Android does not hand
 * out to apps. So we mint 32 random bytes on first launch and keep them wrapped by a
 * hardware-backed AES key that never leaves the Keystore. Uninstalling drops the key,
 * which is correct: the sealed device key it protected goes with the app data anyway.
 *
 * No user authentication is required to unwrap it, deliberately. The network has to
 * come back after a reboot without anyone typing anything — which means whoever owns
 * the unlocked device can recover it too. That trade is the same one the desktop
 * makes, and pretending otherwise would just be theatre.
 */
object DeviceSecret {
    private const val KEY_ALIAS = "pactmesh-device-secret"
    private const val FILE_NAME = "device-secret.bin"
    private const val TRANSFORMATION = "AES/GCM/NoPadding"
    private const val IV_BYTES = 12
    private const val TAG_BITS = 128
    private const val SECRET_BYTES = 32

    fun load(context: Context): String {
        val file = File(context.filesDir, FILE_NAME)
        return if (file.exists()) decrypt(file.readBytes()) else create(file)
    }

    private fun create(file: File): String {
        val secret = ByteArray(SECRET_BYTES).also { SecureRandom().nextBytes(it) }.toHex()
        val cipher = Cipher.getInstance(TRANSFORMATION).apply { init(Cipher.ENCRYPT_MODE, key()) }
        file.writeBytes(cipher.iv + cipher.doFinal(secret.toByteArray()))
        return secret
    }

    private fun decrypt(blob: ByteArray): String {
        val spec = GCMParameterSpec(TAG_BITS, blob, 0, IV_BYTES)
        val cipher = Cipher.getInstance(TRANSFORMATION).apply { init(Cipher.DECRYPT_MODE, key(), spec) }
        return String(cipher.doFinal(blob, IV_BYTES, blob.size - IV_BYTES))
    }

    private fun key(): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (store.getEntry(KEY_ALIAS, null) as? KeyStore.SecretKeyEntry)?.let { return it.secretKey }

        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply {
            init(
                KeyGenParameterSpec.Builder(
                    KEY_ALIAS,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
                )
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .build()
            )
        }.generateKey()
    }

    private fun ByteArray.toHex() = joinToString("") { "%02x".format(it) }
}
