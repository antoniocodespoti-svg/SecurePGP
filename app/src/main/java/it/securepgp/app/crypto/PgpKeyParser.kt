package it.securepgp.app.crypto

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets
import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.openpgp.PGPCompressedData
import org.bouncycastle.openpgp.PGPEncryptedDataList
import org.bouncycastle.openpgp.PGPOnePassSignatureList
import org.bouncycastle.openpgp.PGPObjectFactory
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection
import org.bouncycastle.openpgp.PGPSignatureList
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.bouncycastle.util.encoders.Hex

sealed class ParsedPgpKeyResult {
    data class PublicKeyResult(
        val keyIdHex: String,
        val fingerprintHex: String,
        val userId: String?,
        val rawKeyData: ByteArray,
        val isMasterKey: Boolean,
    ) : ParsedPgpKeyResult() {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is PublicKeyResult) return false
            if (keyIdHex != other.keyIdHex) return false
            if (fingerprintHex != other.fingerprintHex) return false
            if (userId != other.userId) return false
            if (isMasterKey != other.isMasterKey) return false
            return rawKeyData.contentEquals(other.rawKeyData)
        }

        override fun hashCode(): Int {
            var result = keyIdHex.hashCode()
            result = (31 * result) + fingerprintHex.hashCode()
            result = (31 * result) + (userId?.hashCode() ?: 0)
            result = (31 * result) + isMasterKey.hashCode()
            result = (31 * result) + rawKeyData.contentHashCode()
            return result
        }
    }

    data class PrivateKeyResult(
        val keyIdHex: String,
        val fingerprintHex: String,
        val userId: String?,
        val rawKeyData: ByteArray,
        val isMasterKey: Boolean,
        val rawPublicKeyData: ByteArray? = null,
    ) : ParsedPgpKeyResult() {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is PrivateKeyResult) return false
            if (keyIdHex != other.keyIdHex) return false
            if (fingerprintHex != other.fingerprintHex) return false
            if (userId != other.userId) return false
            if (isMasterKey != other.isMasterKey) return false
            if (!rawKeyData.contentEquals(other.rawKeyData)) return false
            return if (rawPublicKeyData != null && other.rawPublicKeyData != null) {
                rawPublicKeyData.contentEquals(other.rawPublicKeyData)
            } else {
                rawPublicKeyData == null && other.rawPublicKeyData == null
            }
        }

        override fun hashCode(): Int {
            var result = keyIdHex.hashCode()
            result = (31 * result) + fingerprintHex.hashCode()
            result = (31 * result) + (userId?.hashCode() ?: 0)
            result = (31 * result) + isMasterKey.hashCode()
            result = (31 * result) + rawKeyData.contentHashCode()
            result = (31 * result) + (rawPublicKeyData?.contentHashCode() ?: 0)
            return result
        }
    }

    data class Error(val message: String, val cause: Throwable? = null) : ParsedPgpKeyResult()
}

/**
 * Isolated OpenPGP key parser helper utilizing Bouncy Castle 1.80 PGP APIs.
 */
object PgpKeyParser {

    fun parseKeyData(bytes: ByteArray): ParsedPgpKeyResult {
        if (bytes.isEmpty()) {
            return ParsedPgpKeyResult.Error("Input PGP key data is empty.")
        }

        val fingerprintCalculator = JcaKeyFingerprintCalculator()

        return try {
            val decoderStream = PGPUtil.getDecoderStream(ByteArrayInputStream(bytes))
            val objectFactory = PGPObjectFactory(decoderStream, fingerprintCalculator)

            var foundResult: ParsedPgpKeyResult? = null

            while (true) {
                val pgpObject = try {
                    objectFactory.nextObject()
                } catch (e: Exception) {
                    return ParsedPgpKeyResult.Error("Failed to parse OpenPGP object: ${e.localizedMessage}", e)
                } ?: break

                when (pgpObject) {
                    is PGPPublicKeyRing -> {
                        val masterKey = pgpObject.publicKey
                        val keyIdHex = formatKeyId(masterKey.keyID)
                        val fpHex = Hex.toHexString(masterKey.fingerprint).uppercase()
                        val userId = masterKey.userIDs.asSequence().firstOrNull()

                        foundResult = ParsedPgpKeyResult.PublicKeyResult(
                            keyIdHex = keyIdHex,
                            fingerprintHex = fpHex,
                            userId = userId,
                            rawKeyData = bytes,
                            isMasterKey = masterKey.isMasterKey,
                        )
                        break
                    }
                    is PGPPublicKeyRingCollection -> {
                        val keyRing = pgpObject.keyRings.asSequence().firstOrNull()
                        if (keyRing != null) {
                            val masterKey = keyRing.publicKey
                            val keyIdHex = formatKeyId(masterKey.keyID)
                            val fpHex = Hex.toHexString(masterKey.fingerprint).uppercase()
                            val userId = keyRing.publicKeys.asSequence().mapNotNull { k -> k.userIDs.asSequence().firstOrNull() }.firstOrNull() ?: masterKey.userIDs.asSequence().firstOrNull()

                            foundResult = ParsedPgpKeyResult.PublicKeyResult(
                                keyIdHex = keyIdHex,
                                fingerprintHex = fpHex,
                                userId = userId,
                                rawKeyData = bytes,
                                isMasterKey = masterKey.isMasterKey,
                            )
                            break
                        }
                    }
                    is PGPSecretKeyRing -> {
                        val secretKey = pgpObject.secretKey
                        val pubKey = secretKey.publicKey
                        val keyIdHex = formatKeyId(secretKey.keyID)
                        val fpHex = Hex.toHexString(pubKey.fingerprint).uppercase()
                        val userId = pubKey.userIDs.asSequence().firstOrNull()
                        val isAscii = isAsciiArmored(bytes)
                        val extractedPubKeyData = extractPublicKeyBytes(pgpObject, isAscii)

                        foundResult = ParsedPgpKeyResult.PrivateKeyResult(
                            keyIdHex = keyIdHex,
                            fingerprintHex = fpHex,
                            userId = userId,
                            rawKeyData = bytes,
                            isMasterKey = pubKey.isMasterKey,
                            rawPublicKeyData = extractedPubKeyData,
                        )
                        break
                    }
                    is PGPSecretKeyRingCollection -> {
                        val keyRing = pgpObject.keyRings.asSequence().firstOrNull()
                        if (keyRing != null) {
                            val secretKey = keyRing.secretKey
                            val pubKey = secretKey.publicKey
                            val keyIdHex = formatKeyId(secretKey.keyID)
                            val fpHex = Hex.toHexString(pubKey.fingerprint).uppercase()
                            val userId = pubKey.userIDs.asSequence().firstOrNull()
                            val isAscii = isAsciiArmored(bytes)
                            val extractedPubKeyData = extractPublicKeyBytes(keyRing, isAscii)

                            foundResult = ParsedPgpKeyResult.PrivateKeyResult(
                                keyIdHex = keyIdHex,
                                fingerprintHex = fpHex,
                                userId = userId,
                                rawKeyData = bytes,
                                isMasterKey = pubKey.isMasterKey,
                                rawPublicKeyData = extractedPubKeyData,
                            )
                            break
                        }
                    }
                    is PGPEncryptedDataList -> {
                        return ParsedPgpKeyResult.Error("The selected file is a PGP encrypted message, not a key.")
                    }
                    is PGPSignatureList, is PGPOnePassSignatureList -> {
                        return ParsedPgpKeyResult.Error("The selected file is a PGP signature, not a key.")
                    }
                    is PGPCompressedData -> {
                        val compStream = PGPObjectFactory(pgpObject.dataStream, fingerprintCalculator)
                        val innerObject = compStream.nextObject()
                        if (innerObject is PGPPublicKeyRing) {
                            val masterKey = innerObject.publicKey
                            val keyIdHex = formatKeyId(masterKey.keyID)
                            val fpHex = Hex.toHexString(masterKey.fingerprint).uppercase()
                            val userId = masterKey.userIDs.asSequence().firstOrNull()

                            foundResult = ParsedPgpKeyResult.PublicKeyResult(
                                keyIdHex = keyIdHex,
                                fingerprintHex = fpHex,
                                userId = userId,
                                rawKeyData = bytes,
                                isMasterKey = masterKey.isMasterKey,
                            )
                            break
                        } else if (innerObject is PGPSecretKeyRing) {
                            val secretKey = innerObject.secretKey
                            val pubKey = secretKey.publicKey
                            val keyIdHex = formatKeyId(secretKey.keyID)
                            val fpHex = Hex.toHexString(pubKey.fingerprint).uppercase()
                            val userId = pubKey.userIDs.asSequence().firstOrNull()
                            val isAscii = isAsciiArmored(bytes)
                            val extractedPubKeyData = extractPublicKeyBytes(innerObject, isAscii)

                            foundResult = ParsedPgpKeyResult.PrivateKeyResult(
                                keyIdHex = keyIdHex,
                                fingerprintHex = fpHex,
                                userId = userId,
                                rawKeyData = bytes,
                                isMasterKey = pubKey.isMasterKey,
                                rawPublicKeyData = extractedPubKeyData,
                            )
                            break
                        } else {
                            return ParsedPgpKeyResult.Error("Compressed PGP payload does not contain an OpenPGP key.")
                        }
                    }
                }
            }

            foundResult ?: ParsedPgpKeyResult.Error("No valid OpenPGP key found in the input data.")
        } catch (e: Exception) {
            ParsedPgpKeyResult.Error("OpenPGP parsing error: ${e.localizedMessage ?: "Invalid or malformed input"}", e)
        }
    }

    private fun isAsciiArmored(bytes: ByteArray): Boolean {
        val sample = String(bytes.take(100).toByteArray(), StandardCharsets.UTF_8)
        return sample.contains("-----BEGIN PGP")
    }

    private fun extractPublicKeyBytes(secretKeyRing: PGPSecretKeyRing, isAsciiArmor: Boolean): ByteArray? {
        return try {
            val pubKeys = secretKeyRing.publicKeys.asSequence().toList()
            if (pubKeys.isEmpty()) return null

            val pubRing = PGPPublicKeyRing(pubKeys)
            val encoded = pubRing.encoded

            if (isAsciiArmor) {
                val armorOut = ByteArrayOutputStream()
                ArmoredOutputStream(armorOut).use { it.write(encoded) }
                armorOut.toByteArray()
            } else {
                encoded
            }
        } catch (_: Exception) {
            null
        }
    }

    fun formatKeyId(keyId: Long): String {
        return "0x%016X".format(keyId)
    }
}
