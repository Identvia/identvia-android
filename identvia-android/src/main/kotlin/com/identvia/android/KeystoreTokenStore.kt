package com.identvia.android

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import com.identvia.core.TokenStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Encrypts each value with AES-256-GCM under a non-exportable AndroidKeyStore key and keeps the ciphertext in
 * private SharedPreferences. (This is what EncryptedSharedPreferences does, without the deprecated security-crypto
 * library.) Restored backups can't be decrypted, because the key never leaves the device; they read as signed out.
 */
class KeystoreTokenStore(context: Context, private val name: String = "identvia_session") : TokenStore {
    private val prefs = context.applicationContext.getSharedPreferences(name, Context.MODE_PRIVATE)
    private val alias = "identvia.$name.v1"

    private fun key(): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (ks.getEntry(alias, null) as? KeyStore.SecretKeyEntry)?.let { return it.secretKey }
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply {
            init(KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build())
        }.generateKey()
    }

    override suspend fun get(key: String): String? = withContext(Dispatchers.IO) {
        val v = prefs.getString(key, null) ?: return@withContext null
        try {
            val raw = Base64.decode(v, Base64.NO_WRAP)
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            c.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, raw, 0, 12))
            c.updateAAD(key.toByteArray())
            String(c.doFinal(raw, 12, raw.size - 12), Charsets.UTF_8)
        } catch (_: Exception) {
            prefs.edit().remove(key).apply() // key lost (restore, lock-screen reset): treat as signed out
            null
        }
    }

    override suspend fun set(key: String, value: String): Unit = withContext(Dispatchers.IO) {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, key())
        c.updateAAD(key.toByteArray())
        val out = c.iv + c.doFinal(value.toByteArray(Charsets.UTF_8))
        check(prefs.edit().putString(key, Base64.encodeToString(out, Base64.NO_WRAP)).commit()) { "Could not save the session." }
    }

    override suspend fun delete(key: String): Unit = withContext(Dispatchers.IO) { prefs.edit().remove(key).commit(); Unit }
}
