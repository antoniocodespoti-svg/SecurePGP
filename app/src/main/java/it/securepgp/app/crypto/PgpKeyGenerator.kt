package it.securepgp.app.crypto

import java.io.ByteArrayOutputStream
import java.security.KeyPairGenerator
import java.security.Security
import java.util.Date
import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openpgp.PGPKeyRingGenerator
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder
import org.bouncycastle.util.encoders.Hex

enum class PgpProfile(val label: String, val isV6: Boolean, val description: String) {
    RSA_3072("RSA 3072 bit (v4)", false, "Standard raccomandato, massima compatibilità universale con tutti i software PGP."),
    RSA_4096("RSA 4096 bit (v4)", false, "Massima sicurezza RSA, ampiamente supportato."),
    ED25519_V4_LEGACY("Ed25519 / X25519 (v4 Legacy)", false, "Curve ellittiche in formato v4 compatibile con GnuPG 2.2+ ed OpenKeychain."),
    ED25519_V6_NATIVE("Ed25519 / X25519 (v6 Nativo RFC 9580)", true, "Formato moderno v6 con fingerprint SHA-256 a 32 byte. Avviso: compatibilità limitata con app esterne datate."),
}

data class GeneratedPgpKeypairResult(
    val keyIdHex: String,
    val fingerprintHex: String,
    val userId: String,
    val privateKeyAsciiArmor: ByteArray,
    val publicKeyAsciiArmor: ByteArray,
    val profile: PgpProfile,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is GeneratedPgpKeypairResult) return false
        if (keyIdHex != other.keyIdHex) return false
        if (fingerprintHex != other.fingerprintHex) return false
        if (userId != other.userId) return false
        if (profile != other.profile) return false
        if (!privateKeyAsciiArmor.contentEquals(other.privateKeyAsciiArmor)) return false
        return publicKeyAsciiArmor.contentEquals(other.publicKeyAsciiArmor)
    }

    override fun hashCode(): Int {
        var result = keyIdHex.hashCode()
        result = (31 * result) + fingerprintHex.hashCode()
        result = (31 * result) + userId.hashCode()
        result = (31 * result) + profile.hashCode()
        result = (31 * result) + privateKeyAsciiArmor.contentHashCode()
        result = (31 * result) + publicKeyAsciiArmor.contentHashCode()
        return result
    }
}

object PgpKeyGenerator {

    init {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(BouncyCastleProvider())
        }
    }

    @Suppress("DEPRECATION")
    fun generateKeypair(
        userId: String,
        passphrase: CharArray,
        profile: PgpProfile = PgpProfile.RSA_3072,
    ): GeneratedPgpKeypairResult {
        val creationDate = Date()
        val checksumCalculator = JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1)

        val (masterPgpKeyPair, subkeyPgpKeyPair) = when (profile) {
            PgpProfile.RSA_3072 -> {
                val masterKpg = KeyPairGenerator.getInstance("RSA", "BC")
                masterKpg.initialize(3072)
                val masterKp = masterKpg.generateKeyPair()

                val subkeyKpg = KeyPairGenerator.getInstance("RSA", "BC")
                subkeyKpg.initialize(3072)
                val subkeyKp = subkeyKpg.generateKeyPair()

                val masterKeyPair = JcaPGPKeyPair(PGPPublicKey.RSA_GENERAL, masterKp, creationDate)
                val subkeyKeyPair = JcaPGPKeyPair(PGPPublicKey.RSA_GENERAL, subkeyKp, creationDate)

                Pair(masterKeyPair, subkeyKeyPair)
            }
            PgpProfile.RSA_4096 -> {
                val masterKpg = KeyPairGenerator.getInstance("RSA", "BC")
                masterKpg.initialize(4096)
                val masterKp = masterKpg.generateKeyPair()

                val subkeyKpg = KeyPairGenerator.getInstance("RSA", "BC")
                subkeyKpg.initialize(4096)
                val subkeyKp = subkeyKpg.generateKeyPair()

                val masterKeyPair = JcaPGPKeyPair(PGPPublicKey.RSA_GENERAL, masterKp, creationDate)
                val subkeyKeyPair = JcaPGPKeyPair(PGPPublicKey.RSA_GENERAL, subkeyKp, creationDate)

                Pair(masterKeyPair, subkeyKeyPair)
            }
            PgpProfile.ED25519_V4_LEGACY -> {
                val masterKpg = KeyPairGenerator.getInstance("Ed25519", "BC")
                val masterKp = masterKpg.generateKeyPair()

                val subkeyKpg = KeyPairGenerator.getInstance("X25519", "BC")
                val subkeyKp = subkeyKpg.generateKeyPair()

                val masterKeyPair = JcaPGPKeyPair(PublicKeyAlgorithmTags.EDDSA_LEGACY, masterKp, creationDate)
                val subkeyKeyPair = JcaPGPKeyPair(PublicKeyAlgorithmTags.ECDH, subkeyKp, creationDate)

                Pair(masterKeyPair, subkeyKeyPair)
            }
            PgpProfile.ED25519_V6_NATIVE -> {
                val masterKpg = KeyPairGenerator.getInstance("Ed25519", "BC")
                val masterKp = masterKpg.generateKeyPair()

                val subkeyKpg = KeyPairGenerator.getInstance("X25519", "BC")
                val subkeyKp = subkeyKpg.generateKeyPair()

                val masterKeyPair = JcaPGPKeyPair(PublicKeyAlgorithmTags.Ed25519, masterKp, creationDate)
                val subkeyKeyPair = JcaPGPKeyPair(PublicKeyAlgorithmTags.X25519, subkeyKp, creationDate)

                Pair(masterKeyPair, subkeyKeyPair)
            }
        }

        val signerBuilder = JcaPGPContentSignerBuilder(
            masterPgpKeyPair.publicKey.algorithm,
            HashAlgorithmTags.SHA256,
        )

        val encryptorBuilder = JcePBESecretKeyEncryptorBuilder(
            SymmetricKeyAlgorithmTags.AES_256,
            checksumCalculator,
        ).build(passphrase)

        val keyRingGen = PGPKeyRingGenerator(
            PGPSignature.POSITIVE_CERTIFICATION,
            masterPgpKeyPair,
            userId,
            checksumCalculator,
            null,
            null,
            signerBuilder,
            encryptorBuilder,
        )

        keyRingGen.addSubKey(subkeyPgpKeyPair)

        val secretKeyRing = keyRingGen.generateSecretKeyRing()
        val publicKeyRing = keyRingGen.generatePublicKeyRing()

        val masterPublicKey = secretKeyRing.secretKey.publicKey
        val keyIdHex = PgpKeyParser.formatKeyId(masterPublicKey.keyID)
        val fpHex = Hex.toHexString(masterPublicKey.fingerprint).uppercase()

        val privStream = ByteArrayOutputStream()
        ArmoredOutputStream(privStream).use { it.write(secretKeyRing.encoded) }

        val pubStream = ByteArrayOutputStream()
        ArmoredOutputStream(pubStream).use { it.write(publicKeyRing.encoded) }

        return GeneratedPgpKeypairResult(
            keyIdHex = keyIdHex,
            fingerprintHex = fpHex,
            userId = userId,
            privateKeyAsciiArmor = privStream.toByteArray(),
            publicKeyAsciiArmor = pubStream.toByteArray(),
            profile = profile,
        )
    }
}
