package it.securepgp.app.storage

import it.securepgp.app.crypto.ArchiveCrypto
import it.securepgp.app.crypto.AuthenticationFailedException
import it.securepgp.app.crypto.InvalidInputException
import it.securepgp.app.crypto.InvalidKdfParamsException
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.nio.charset.StandardCharsets

open class ArchiveStorageException(message: String, cause: Throwable? = null) : Exception(message, cause)

class InvalidArchiveFormatException(message: String, cause: Throwable? = null) : ArchiveStorageException(message, cause)

class UnsupportedArchiveVersionException(message: String, cause: Throwable? = null) : ArchiveStorageException(message, cause)

class CorruptedArchiveException(message: String, cause: Throwable? = null) : ArchiveStorageException(message, cause)

/**
 * Binary structure representing the unencrypted header and envelope parameters of a SecurePGP archive.
 */
data class ArchiveHeader(
    val formatVersion: Byte = ArchiveFormat.CURRENT_FORMAT_VERSION,
    val kdfAlgoId: Byte = ArchiveFormat.KDF_ALGO_PBKDF2_SHA256,
    val kdfSalt: ByteArray,
    val kdfIterations: Int,
    val kekNonce: ByteArray,
    val encryptedDek: ByteArray,
    val contentNonce: ByteArray,
    val encryptedPayloadLength: Int,
) {
    init {
        require(kdfSalt.size == ArchiveCrypto.SALT_BYTE_SIZE) { "Salt must be ${ArchiveCrypto.SALT_BYTE_SIZE} bytes." }
        require(kekNonce.size == ArchiveCrypto.NONCE_BYTE_SIZE) { "KEK nonce must be ${ArchiveCrypto.NONCE_BYTE_SIZE} bytes." }
        require(encryptedDek.size == (ArchiveCrypto.KEY_BYTE_SIZE + ArchiveCrypto.GCM_TAG_BYTE_SIZE)) {
            "Encrypted DEK must be ${ArchiveCrypto.KEY_BYTE_SIZE + ArchiveCrypto.GCM_TAG_BYTE_SIZE} bytes."
        }
        require(contentNonce.size == ArchiveCrypto.NONCE_BYTE_SIZE) { "Content nonce must be ${ArchiveCrypto.NONCE_BYTE_SIZE} bytes." }
    }

    /**
     * Layer 1 AAD: Authenticates Magic, Version, KDF Algo ID, Salt, Iterations, and KEK Nonce.
     */
    fun computeKekAad(): ByteArray {
        val out = ByteArrayOutputStream()
        val data = DataOutputStream(out)
        data.write(ArchiveFormat.MAGIC_BYTES)
        data.writeByte(formatVersion.toInt())
        data.writeByte(kdfAlgoId.toInt())
        data.write(kdfSalt)
        data.writeInt(kdfIterations)
        data.write(kekNonce)
        data.flush()
        return out.toByteArray()
    }

    /**
     * Layer 2 AAD: Authenticates the entire fixed header (Layer 1 AAD + Encrypted DEK + Content Nonce + Payload Length).
     */
    fun computePayloadAad(): ByteArray {
        val out = ByteArrayOutputStream()
        val data = DataOutputStream(out)
        data.write(computeKekAad())
        data.write(encryptedDek)
        data.write(contentNonce)
        data.writeInt(encryptedPayloadLength)
        data.flush()
        return out.toByteArray()
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is ArchiveHeader) return false
        if (formatVersion != other.formatVersion) return false
        if (kdfAlgoId != other.kdfAlgoId) return false
        if (!kdfSalt.contentEquals(other.kdfSalt)) return false
        if (kdfIterations != other.kdfIterations) return false
        if (!kekNonce.contentEquals(other.kekNonce)) return false
        if (!encryptedDek.contentEquals(other.encryptedDek)) return false
        if (!contentNonce.contentEquals(other.contentNonce)) return false
        return encryptedPayloadLength == other.encryptedPayloadLength
    }

    override fun hashCode(): Int {
        var result = formatVersion.toInt()
        result = (31 * result) + kdfAlgoId.toInt()
        result = (31 * result) + kdfSalt.contentHashCode()
        result = (31 * result) + kdfIterations
        result = (31 * result) + kekNonce.contentHashCode()
        result = (31 * result) + encryptedDek.contentHashCode()
        result = (31 * result) + contentNonce.contentHashCode()
        result = (31 * result) + encryptedPayloadLength
        return result
    }
}

/**
 * Binary format encoder, decoder, and validator for SecurePGP archives.
 */
object ArchiveFormat {

    val MAGIC_BYTES = "SPGP_ARC".toByteArray(StandardCharsets.US_ASCII)
    const val CURRENT_FORMAT_VERSION: Byte = 0x01
    const val KDF_ALGO_PBKDF2_SHA256: Byte = 0x01

    const val FIXED_HEADER_SIZE = 8 + 1 + 1 + 32 + 4 + 12 + (32 + 16) + 12 + 4 // 122 bytes
    const val MAX_PAYLOAD_SIZE = 10 * 1024 * 1024 // 10 MB maximum encrypted payload

    fun serializeArchive(header: ArchiveHeader, encryptedPayload: ByteArray): ByteArray {
        require(encryptedPayload.size == header.encryptedPayloadLength) {
            "Payload size (${encryptedPayload.size}) does not match header declaration (${header.encryptedPayloadLength})."
        }

        val out = ByteArrayOutputStream()
        val data = DataOutputStream(out)

        // Write fixed header
        data.write(header.computePayloadAad())
        // Write encrypted payload
        data.write(encryptedPayload)
        data.flush()

        return out.toByteArray()
    }

    fun parseAndValidateArchive(bytes: ByteArray): Pair<ArchiveHeader, ByteArray> {
        if (bytes.size < FIXED_HEADER_SIZE) {
            throw InvalidArchiveFormatException("Archive file is too short (${bytes.size} bytes < min $FIXED_HEADER_SIZE bytes).")
        }

        val data = DataInputStream(ByteArrayInputStream(bytes))

        // 1. Magic Bytes Check
        val magic = ByteArray(MAGIC_BYTES.size)
        data.readFully(magic)
        if (!magic.contentEquals(MAGIC_BYTES)) {
            throw InvalidArchiveFormatException("Invalid magic bytes in header.")
        }

        // 2. Format Version Check
        val version = data.readByte()
        if (version != CURRENT_FORMAT_VERSION) {
            throw UnsupportedArchiveVersionException("Unsupported archive format version $version (expected $CURRENT_FORMAT_VERSION).")
        }

        // 3. KDF Algorithm Check
        val kdfAlgoId = data.readByte()
        if (kdfAlgoId != KDF_ALGO_PBKDF2_SHA256) {
            throw InvalidArchiveFormatException("Unknown KDF algorithm ID $kdfAlgoId.")
        }

        // 4. KDF Salt
        val salt = ByteArray(ArchiveCrypto.SALT_BYTE_SIZE)
        data.readFully(salt)

        // 5. KDF Iterations Check
        val iterations = data.readInt()
        if ((iterations < ArchiveCrypto.MIN_KDF_ITERATIONS) || (iterations > ArchiveCrypto.MAX_KDF_ITERATIONS)) {
            throw InvalidKdfParamsException(
                "KDF iterations ($iterations) outside allowed bounds [${ArchiveCrypto.MIN_KDF_ITERATIONS}..${ArchiveCrypto.MAX_KDF_ITERATIONS}].",
            )
        }

        // 6. KEK Nonce
        val kekNonce = ByteArray(ArchiveCrypto.NONCE_BYTE_SIZE)
        data.readFully(kekNonce)

        // 7. Encrypted DEK
        val encryptedDek = ByteArray(ArchiveCrypto.KEY_BYTE_SIZE + ArchiveCrypto.GCM_TAG_BYTE_SIZE)
        data.readFully(encryptedDek)

        // 8. Content Nonce
        val contentNonce = ByteArray(ArchiveCrypto.NONCE_BYTE_SIZE)
        data.readFully(contentNonce)

        // 9. Encrypted Payload Length Check
        val payloadLength = data.readInt()
        if ((payloadLength < 1) || (payloadLength > MAX_PAYLOAD_SIZE)) {
            throw InvalidArchiveFormatException("Invalid payload length ($payloadLength bytes). Must be between 1 and $MAX_PAYLOAD_SIZE bytes.")
        }

        val expectedTotalSize = FIXED_HEADER_SIZE + payloadLength
        if (bytes.size < expectedTotalSize) {
            throw InvalidArchiveFormatException("Truncated archive: expected $expectedTotalSize bytes, got ${bytes.size} bytes.")
        }

        if (bytes.size > expectedTotalSize) {
            throw InvalidArchiveFormatException("Unexpected trailing bytes in archive: expected $expectedTotalSize bytes, got ${bytes.size} bytes.")
        }

        // 10. Read Encrypted Payload
        val encryptedPayload = ByteArray(payloadLength)
        data.readFully(encryptedPayload)

        val header = ArchiveHeader(
            formatVersion = version,
            kdfAlgoId = kdfAlgoId,
            kdfSalt = salt,
            kdfIterations = iterations,
            kekNonce = kekNonce,
            encryptedDek = encryptedDek,
            contentNonce = contentNonce,
            encryptedPayloadLength = payloadLength,
        )

        return Pair(header, encryptedPayload)
    }

    fun openArchive(
        archiveBytes: ByteArray,
        passphrase: CharArray,
    ): ByteArray {
        val (header, encryptedPayload) = parseAndValidateArchive(archiveBytes)

        val kekAad = header.computeKekAad()
        val kek = try {
            ArchiveCrypto.deriveKek(passphrase, header.kdfSalt, header.kdfIterations)
        } catch (e: InvalidKdfParamsException) {
            throw e
        } catch (e: Exception) {
            throw InvalidKdfParamsException("KDF derivation failed: ${e.localizedMessage}")
        }

        val dek = try {
            ArchiveCrypto.decryptDek(header.encryptedDek, kek, header.kekNonce, kekAad)
        } catch (e: AuthenticationFailedException) {
            ArchiveCrypto.zeroize(kek)
            throw CorruptedArchiveException("Archive authentication failed: wrong passphrase or tampered header.", e)
        } catch (e: InvalidInputException) {
            ArchiveCrypto.zeroize(kek)
            throw CorruptedArchiveException("Archive input invalid.", e)
        } finally {
            ArchiveCrypto.zeroize(kek)
        }

        val payloadAad = header.computePayloadAad()
        return try {
            ArchiveCrypto.decryptPayload(encryptedPayload, dek, header.contentNonce, payloadAad)
        } catch (e: AuthenticationFailedException) {
            ArchiveCrypto.zeroize(dek)
            throw CorruptedArchiveException("Payload authentication failed: corrupted or tampered payload.", e)
        } catch (e: InvalidInputException) {
            ArchiveCrypto.zeroize(dek)
            throw CorruptedArchiveException("Payload input invalid.", e)
        } finally {
            ArchiveCrypto.zeroize(dek)
        }
    }

    fun createArchive(
        payloadBytes: ByteArray,
        passphrase: CharArray,
        iterations: Int = ArchiveCrypto.STANDARD_KDF_ITERATIONS,
    ): ByteArray {
        require(payloadBytes.isNotEmpty()) { "Payload cannot be empty." }
        require(payloadBytes.size <= (MAX_PAYLOAD_SIZE - ArchiveCrypto.GCM_TAG_BYTE_SIZE)) {
            "Payload size exceeds max allowed archive limit."
        }

        val salt = ArchiveCrypto.generateSalt()
        val kekNonce = ArchiveCrypto.generateNonce()
        val contentNonce = ArchiveCrypto.generateNonce()
        val dek = ArchiveCrypto.generateDek()

        val kek = ArchiveCrypto.deriveKek(passphrase, salt, iterations)

        return try {
            val dummyHeader = ArchiveHeader(
                formatVersion = CURRENT_FORMAT_VERSION,
                kdfAlgoId = KDF_ALGO_PBKDF2_SHA256,
                kdfSalt = salt,
                kdfIterations = iterations,
                kekNonce = kekNonce,
                encryptedDek = ByteArray(ArchiveCrypto.KEY_BYTE_SIZE + ArchiveCrypto.GCM_TAG_BYTE_SIZE),
                contentNonce = contentNonce,
                encryptedPayloadLength = 0,
            )

            val kekAad = dummyHeader.computeKekAad()
            val encryptedDek = ArchiveCrypto.encryptDek(dek, kek, kekNonce, kekAad)

            val fullEncryptedPayloadLength = payloadBytes.size + ArchiveCrypto.GCM_TAG_BYTE_SIZE

            val finalHeader = ArchiveHeader(
                formatVersion = CURRENT_FORMAT_VERSION,
                kdfAlgoId = KDF_ALGO_PBKDF2_SHA256,
                kdfSalt = salt,
                kdfIterations = iterations,
                kekNonce = kekNonce,
                encryptedDek = encryptedDek,
                contentNonce = contentNonce,
                encryptedPayloadLength = fullEncryptedPayloadLength,
            )

            val payloadAad = finalHeader.computePayloadAad()
            val encryptedPayload = ArchiveCrypto.encryptPayload(payloadBytes, dek, contentNonce, payloadAad)

            serializeArchive(finalHeader, encryptedPayload)
        } finally {
            ArchiveCrypto.zeroize(kek)
            ArchiveCrypto.zeroize(dek)
        }
    }
}
