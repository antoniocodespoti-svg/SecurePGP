package it.securepgp.app.crypto

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

object SymmetricKeyExchangeCrypto {

    private const val TAG_KEYID_REPLAY = "SECUREPGP-KEYID-REPLAY-V1"
    private const val TAG_NONCE_REPLAY = "SECUREPGP-NONCE-REPLAY-V1"
    private const val TAG_SAS_V1 = "SECUREPGP-SAS-V1"

    fun calculateSymmetricKeyIdHash(
        userA: String,
        fingerprintA: ByteArray,
        userB: String,
        fingerprintB: ByteArray,
        symmetricKeyId: String,
    ): ByteArray {
        validateInputs(userA, fingerprintA, userB, fingerprintB, symmetricKeyId)

        val canonicalHeader = buildCanonicalHeader(userA, fingerprintA, userB, fingerprintB)
        val out = ByteArrayOutputStream()
        val data = DataOutputStream(out)

        val tagBytes = TAG_KEYID_REPLAY.toByteArray(StandardCharsets.US_ASCII)
        data.write(tagBytes)
        data.write(canonicalHeader)

        val keyIdBytes = symmetricKeyId.toByteArray(StandardCharsets.UTF_8)
        if (keyIdBytes.size > 65535) {
            throw InvalidInputException("SymmetricKeyId string is too long.")
        }
        data.writeShort(keyIdBytes.size)
        data.write(keyIdBytes)

        data.flush()
        return MessageDigest.getInstance("SHA-256").digest(out.toByteArray())
    }

    fun calculateExchangeNonceHash(
        userA: String,
        fingerprintA: ByteArray,
        userB: String,
        fingerprintB: ByteArray,
        exchangeNonce: ByteArray,
    ): ByteArray {
        validateInputs(userA, fingerprintA, userB, fingerprintB, symmetricKeyId = "valid_key_id")
        if (exchangeNonce.size != 16) {
            throw InvalidInputException("ExchangeNonce must be exactly 16 bytes, got ${exchangeNonce.size}.")
        }

        val canonicalHeader = buildCanonicalHeader(userA, fingerprintA, userB, fingerprintB)
        val out = ByteArrayOutputStream()
        val data = DataOutputStream(out)

        val tagBytes = TAG_NONCE_REPLAY.toByteArray(StandardCharsets.US_ASCII)
        data.write(tagBytes)
        data.write(canonicalHeader)
        data.write(exchangeNonce)

        data.flush()
        return MessageDigest.getInstance("SHA-256").digest(out.toByteArray())
    }

    fun calculateSasCode(
        rawSymmetricKeyData: ByteArray,
        userA: String,
        fingerprintA: ByteArray,
        userB: String,
        fingerprintB: ByteArray,
        symmetricKeyId: String,
        exchangeNonce: ByteArray,
    ): String {
        if (rawSymmetricKeyData.size != 32) {
            throw InvalidInputException("RawSymmetricKeyData must be exactly 32 bytes (AES-256), got ${rawSymmetricKeyData.size}.")
        }
        if (exchangeNonce.size != 16) {
            throw InvalidInputException("ExchangeNonce must be exactly 16 bytes, got ${exchangeNonce.size}.")
        }
        validateInputs(userA, fingerprintA, userB, fingerprintB, symmetricKeyId)

        val canonicalHeader = buildCanonicalHeader(userA, fingerprintA, userB, fingerprintB)
        val out = ByteArrayOutputStream()
        val data = DataOutputStream(out)

        val tagBytes = TAG_SAS_V1.toByteArray(StandardCharsets.US_ASCII)
        data.write(tagBytes)
        data.write(canonicalHeader)

        val keyIdBytes = symmetricKeyId.toByteArray(StandardCharsets.UTF_8)
        if (keyIdBytes.size > 65535) {
            throw InvalidInputException("SymmetricKeyId string is too long.")
        }
        data.writeShort(keyIdBytes.size)
        data.write(keyIdBytes)

        data.write(exchangeNonce)
        data.flush()

        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(rawSymmetricKeyData, "HmacSHA256"))
        val hmacResult = mac.doFinal(out.toByteArray())

        return truncateHmacToSasCode(hmacResult)
    }

    internal fun truncateHmacToSasCode(hmacResult: ByteArray): String {
        if (hmacResult.size != 32) {
            throw InvalidInputException("HMAC result must be 32 bytes, got ${hmacResult.size}.")
        }

        val offset = (hmacResult[31].toInt() and 0x0F)
        val binaryCode = ((hmacResult[offset].toInt() and 0x7F) shl 24) or
            ((hmacResult[offset + 1].toInt() and 0xFF) shl 16) or
            ((hmacResult[offset + 2].toInt() and 0xFF) shl 8) or
            (hmacResult[offset + 3].toInt() and 0xFF)

        val modCode = binaryCode % 100_000_000
        val part1 = modCode / 10000
        val part2 = modCode % 10000

        return "%04d-%04d".format(part1, part2)
    }

    private fun buildCanonicalHeader(
        userA: String,
        fingerprintA: ByteArray,
        userB: String,
        fingerprintB: ByteArray,
    ): ByteArray {
        val (firstUser, firstFp, secondUser, secondFp) = if (userA <= userB) {
            Quadruple(userA, fingerprintA, userB, fingerprintB)
        } else {
            Quadruple(userB, fingerprintB, userA, fingerprintA)
        }

        val out = ByteArrayOutputStream()
        val data = DataOutputStream(out)

        val user1Bytes = firstUser.toByteArray(StandardCharsets.UTF_8)
        if (user1Bytes.isEmpty() || user1Bytes.size > 65535) {
            throw InvalidInputException("User ID string 1 is invalid or too long.")
        }
        data.writeShort(user1Bytes.size)
        data.write(user1Bytes)

        val user2Bytes = secondUser.toByteArray(StandardCharsets.UTF_8)
        if (user2Bytes.isEmpty() || user2Bytes.size > 65535) {
            throw InvalidInputException("User ID string 2 is invalid or too long.")
        }
        data.writeShort(user2Bytes.size)
        data.write(user2Bytes)

        if (firstFp.size != 20 && firstFp.size != 32) {
            throw InvalidInputException("OpenPGP fingerprint 1 must be 20 or 32 bytes, got ${firstFp.size}.")
        }
        data.writeByte(firstFp.size)
        data.write(firstFp)

        if (secondFp.size != 20 && secondFp.size != 32) {
            throw InvalidInputException("OpenPGP fingerprint 2 must be 20 or 32 bytes, got ${secondFp.size}.")
        }
        data.writeByte(secondFp.size)
        data.write(secondFp)

        data.flush()
        return out.toByteArray()
    }

    private fun validateInputs(
        userA: String,
        fingerprintA: ByteArray,
        userB: String,
        fingerprintB: ByteArray,
        symmetricKeyId: String,
    ) {
        if (userA.trim().isEmpty() || userB.trim().isEmpty()) {
            throw InvalidInputException("User identity ID strings must not be empty.")
        }
        if (symmetricKeyId.trim().isEmpty()) {
            throw InvalidInputException("Symmetric key ID string must not be empty.")
        }
        if ((fingerprintA.size != 20 && fingerprintA.size != 32) || (fingerprintB.size != 20 && fingerprintB.size != 32)) {
            throw InvalidInputException("OpenPGP fingerprints must be exactly 20 or 32 bytes.")
        }
    }

    private data class Quadruple<A, B, C, D>(
        val first: A,
        val second: B,
        val third: C,
        val fourth: D,
    )
}
