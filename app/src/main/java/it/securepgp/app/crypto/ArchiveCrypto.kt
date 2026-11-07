package it.securepgp.app.crypto

import java.security.SecureRandom
import java.util.Arrays
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

open class CryptoException(message: String, cause: Throwable? = null) : Exception(message, cause)

class InvalidKdfParamsException(message: String) : CryptoException(message)

class InvalidInputException(message: String) : CryptoException(message)

class AuthenticationFailedException(message: String, cause: Throwable? = null) : CryptoException(message, cause)

/**
 * Core cryptographic engine for SecurePGP archive protection.
 *
 * Design and Security Guarantees:
 * - KDF: PBKDF2-HMAC-SHA256 via JCA. Standard iteration count is 600,000 (OWASP baseline).
 *   Note: PBKDF2 is CPU-bound and does not provide memory-hardness against GPU/ASIC brute-force
 *   like Argon2id. It is selected here as a native, dependency-free JCA algorithm with strict bounds.
 * - Authenticated Encryption: AES-256-GCM (12-byte nonce, 128-bit tag, optional AAD).
 * - Architecture: KEK/DEK two-layer envelope model.
 * - Memory & Passphrase: Prefers `CharArray` for passphrases and zeroizes internal temporary
 *   buffers using `Arrays.fill`. Callers retain ownership of their own buffers.
 */
object ArchiveCrypto {

    const val STANDARD_KDF_ITERATIONS = 600_000
    const val MIN_KDF_ITERATIONS = 100_000
    const val MAX_KDF_ITERATIONS = 2_000_000

    const val SALT_BYTE_SIZE = 32
    const val NONCE_BYTE_SIZE = 12
    const val KEY_BYTE_SIZE = 32 // 256 bits
    const val GCM_TAG_BIT_LENGTH = 128
    const val GCM_TAG_BYTE_SIZE = 16

    private const val KDF_ALGORITHM = "PBKDF2WithHmacSHA256"
    private const val CIPHER_ALGORITHM = "AES/GCM/NoPadding"
    private const val KEY_ALGORITHM = "AES"

    private val secureRandom = SecureRandom()

    fun generateSalt(): ByteArray {
        val salt = ByteArray(SALT_BYTE_SIZE)
        secureRandom.nextBytes(salt)
        return salt
    }

    fun generateNonce(): ByteArray {
        val nonce = ByteArray(NONCE_BYTE_SIZE)
        secureRandom.nextBytes(nonce)
        return nonce
    }

    fun generateDek(): ByteArray {
        val dek = ByteArray(KEY_BYTE_SIZE)
        secureRandom.nextBytes(dek)
        return dek
    }

    /**
     * Derives a 256-bit Key Encryption Key (KEK) from a passphrase and salt.
     *
     * Validates iteration count BEFORE invoking the KDF factory.
     */
    fun deriveKek(
        passphrase: CharArray,
        salt: ByteArray,
        iterations: Int = STANDARD_KDF_ITERATIONS,
    ): ByteArray {
        if (salt.size != SALT_BYTE_SIZE) {
            throw InvalidInputException("Salt must be exactly $SALT_BYTE_SIZE bytes, got ${salt.size}.")
        }

        if ((iterations < MIN_KDF_ITERATIONS) || (iterations > MAX_KDF_ITERATIONS)) {
            throw InvalidKdfParamsException(
                "KDF iteration count ($iterations) is outside allowed bounds [$MIN_KDF_ITERATIONS..$MAX_KDF_ITERATIONS].",
            )
        }

        val keySpec = PBEKeySpec(passphrase, salt, iterations, KEY_BYTE_SIZE * 8)
        return try {
            val keyFactory = SecretKeyFactory.getInstance(KDF_ALGORITHM)
            val secretKey = keyFactory.generateSecret(keySpec)
            secretKey.encoded
        } catch (e: Exception) {
            throw CryptoException("Key derivation failed: ${e.localizedMessage}", e)
        } finally {
            keySpec.clearPassword()
        }
    }

    fun encryptAead(
        key: ByteArray,
        nonce: ByteArray,
        plaintext: ByteArray,
        aad: ByteArray? = null,
    ): ByteArray {
        validateKeyAndNonce(key, nonce)

        return try {
            val cipher = Cipher.getInstance(CIPHER_ALGORITHM)
            val secretKeySpec = SecretKeySpec(key, KEY_ALGORITHM)
            val gcmSpec = GCMParameterSpec(GCM_TAG_BIT_LENGTH, nonce)

            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, gcmSpec)
            if ((aad != null) && aad.isNotEmpty()) {
                cipher.updateAAD(aad)
            }
            cipher.doFinal(plaintext)
        } catch (e: Exception) {
            throw CryptoException("Encryption failed: ${e.localizedMessage}", e)
        }
    }

    fun decryptAead(
        key: ByteArray,
        nonce: ByteArray,
        ciphertextWithTag: ByteArray,
        aad: ByteArray? = null,
    ): ByteArray {
        validateKeyAndNonce(key, nonce)

        if (ciphertextWithTag.size < GCM_TAG_BYTE_SIZE) {
            throw InvalidInputException("Ciphertext is too short to contain a GCM tag.")
        }

        return try {
            val cipher = Cipher.getInstance(CIPHER_ALGORITHM)
            val secretKeySpec = SecretKeySpec(key, KEY_ALGORITHM)
            val gcmSpec = GCMParameterSpec(GCM_TAG_BIT_LENGTH, nonce)

            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, gcmSpec)
            if ((aad != null) && aad.isNotEmpty()) {
                cipher.updateAAD(aad)
            }
            cipher.doFinal(ciphertextWithTag)
        } catch (e: Exception) {
            // AEAD authentication failure (wrong key, tampered ciphertext, or altered AAD)
            throw AuthenticationFailedException("Authentication failed: invalid key, corrupted data, or tampered AAD.", e)
        }
    }

    fun encryptDek(
        dek: ByteArray,
        kek: ByteArray,
        nonce: ByteArray,
        aad: ByteArray? = null,
    ): ByteArray {
        if (dek.size != KEY_BYTE_SIZE) {
            throw InvalidInputException("DEK must be exactly $KEY_BYTE_SIZE bytes, got ${dek.size}.")
        }
        return encryptAead(kek, nonce, dek, aad)
    }

    fun decryptDek(
        encryptedDekWithTag: ByteArray,
        kek: ByteArray,
        nonce: ByteArray,
        aad: ByteArray? = null,
    ): ByteArray {
        val decryptedDek = decryptAead(kek, nonce, encryptedDekWithTag, aad)
        if (decryptedDek.size != KEY_BYTE_SIZE) {
            zeroize(decryptedDek)
            throw AuthenticationFailedException("Decrypted DEK length is invalid.")
        }
        return decryptedDek
    }

    fun encryptPayload(
        payload: ByteArray,
        dek: ByteArray,
        nonce: ByteArray,
        aad: ByteArray? = null,
    ): ByteArray {
        if (dek.size != KEY_BYTE_SIZE) {
            throw InvalidInputException("DEK must be exactly $KEY_BYTE_SIZE bytes, got ${dek.size}.")
        }
        return encryptAead(dek, nonce, payload, aad)
    }

    fun decryptPayload(
        ciphertextWithTag: ByteArray,
        dek: ByteArray,
        nonce: ByteArray,
        aad: ByteArray? = null,
    ): ByteArray {
        if (dek.size != KEY_BYTE_SIZE) {
            throw InvalidInputException("DEK must be exactly $KEY_BYTE_SIZE bytes, got ${dek.size}.")
        }
        return decryptAead(dek, nonce, ciphertextWithTag, aad)
    }

    fun zeroize(array: ByteArray) {
        Arrays.fill(array, 0.toByte())
    }

    fun zeroize(array: CharArray) {
        Arrays.fill(array, '\u0000')
    }

    private fun validateKeyAndNonce(key: ByteArray, nonce: ByteArray) {
        if (key.size != KEY_BYTE_SIZE) {
            throw InvalidInputException("Key must be exactly $KEY_BYTE_SIZE bytes, got ${key.size}.")
        }
        if (nonce.size != NONCE_BYTE_SIZE) {
            throw InvalidInputException("Nonce must be exactly $NONCE_BYTE_SIZE bytes, got ${nonce.size}.")
        }
    }
}
