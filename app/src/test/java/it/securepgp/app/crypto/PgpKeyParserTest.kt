package it.securepgp.app.crypto

import java.io.ByteArrayOutputStream
import java.security.KeyPairGenerator
import java.security.Security
import java.util.Date
import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openpgp.PGPKeyRingGenerator
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.BeforeClass
import org.junit.Test

class PgpKeyParserTest {

    companion object {
        @BeforeClass
        @JvmStatic
        fun setUpProvider() {
            if (Security.getProvider("BC") == null) {
                Security.addProvider(BouncyCastleProvider())
            }
        }

        @Suppress("DEPRECATION")
        private fun generateTestKeyRings(userId: String = "Test User <test@securepgp.app>"): Pair<ByteArray, ByteArray> {
            val kpg = KeyPairGenerator.getInstance("RSA")
            kpg.initialize(2048)
            val kp = kpg.generateKeyPair()

            val pgpKp = JcaPGPKeyPair(PGPPublicKey.RSA_GENERAL, kp, Date())
            val digestCalculator = JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1)

            val keyRingGen = PGPKeyRingGenerator(
                PGPSignature.POSITIVE_CERTIFICATION,
                pgpKp,
                userId,
                digestCalculator,
                null,
                null,
                JcaPGPContentSignerBuilder(pgpKp.publicKey.algorithm, HashAlgorithmTags.SHA256),
                JcePBESecretKeyEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256, digestCalculator).build("testPass".toCharArray()),
            )

            val secretKeyRing = keyRingGen.generateSecretKeyRing()
            val publicKeyRing = keyRingGen.generatePublicKeyRing()

            val pubArmorStream = ByteArrayOutputStream()
            ArmoredOutputStream(pubArmorStream).use { it.write(publicKeyRing.encoded) }

            val privArmorStream = ByteArrayOutputStream()
            ArmoredOutputStream(privArmorStream).use { it.write(secretKeyRing.encoded) }

            return Pair(pubArmorStream.toByteArray(), privArmorStream.toByteArray())
        }
    }

    @Test
    fun testParseValidPublicKey_AsciiArmor() {
        val (pubArmor, _) = generateTestKeyRings("Alice <alice@securepgp.app>")

        val result = PgpKeyParser.parseKeyData(pubArmor)
        assertTrue(result is ParsedPgpKeyResult.PublicKeyResult)

        val pubResult = result as ParsedPgpKeyResult.PublicKeyResult
        assertTrue(pubResult.keyIdHex.startsWith("0x"))
        assertEquals(18, pubResult.keyIdHex.length) // "0x" + 16 hex chars
        assertEquals(40, pubResult.fingerprintHex.length) // 40 hex chars
        assertEquals("Alice <alice@securepgp.app>", pubResult.userId)
        assertArrayEquals(pubArmor, pubResult.rawKeyData)
    }

    @Test
    @Suppress("DEPRECATION")
    fun testParseValidPublicKey_BinaryFormat() {
        val kpg = KeyPairGenerator.getInstance("RSA")
        kpg.initialize(2048)
        val kp = kpg.generateKeyPair()

        val pgpKp = JcaPGPKeyPair(PGPPublicKey.RSA_GENERAL, kp, Date())
        val digestCalculator = JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1)

        val keyRingGen = PGPKeyRingGenerator(
            PGPSignature.POSITIVE_CERTIFICATION,
            pgpKp,
            "Binary User <binary@securepgp.app>",
            digestCalculator,
            null,
            null,
            JcaPGPContentSignerBuilder(pgpKp.publicKey.algorithm, HashAlgorithmTags.SHA256),
            JcePBESecretKeyEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256, digestCalculator).build("pass".toCharArray()),
        )

        val binaryBytes = keyRingGen.generatePublicKeyRing().encoded

        val result = PgpKeyParser.parseKeyData(binaryBytes)
        assertTrue(result is ParsedPgpKeyResult.PublicKeyResult)

        val pubResult = result as ParsedPgpKeyResult.PublicKeyResult
        assertEquals("Binary User <binary@securepgp.app>", pubResult.userId)
        assertArrayEquals(binaryBytes, pubResult.rawKeyData)
    }

    @Test
    fun testParseValidPrivateKey_AsciiArmor() {
        val (_, privArmor) = generateTestKeyRings("Bob <bob@securepgp.app>")

        val result = PgpKeyParser.parseKeyData(privArmor)
        assertTrue(result is ParsedPgpKeyResult.PrivateKeyResult)

        val privResult = result as ParsedPgpKeyResult.PrivateKeyResult
        assertTrue(privResult.keyIdHex.startsWith("0x"))
        assertEquals("Bob <bob@securepgp.app>", privResult.userId)
        assertArrayEquals(privArmor, privResult.rawKeyData)
    }

    @Test
    fun testExtractsPublicKeyFromPrivateKey() {
        val (_, privArmor) = generateTestKeyRings("Carol <carol@securepgp.app>")

        val result = PgpKeyParser.parseKeyData(privArmor)
        assertTrue(result is ParsedPgpKeyResult.PrivateKeyResult)

        val privResult = result as ParsedPgpKeyResult.PrivateKeyResult
        assertNotNull(privResult.rawPublicKeyData)

        val pubParseResult = PgpKeyParser.parseKeyData(privResult.rawPublicKeyData!!)
        assertTrue(pubParseResult is ParsedPgpKeyResult.PublicKeyResult)

        val extractedPubResult = pubParseResult as ParsedPgpKeyResult.PublicKeyResult
        assertEquals(privResult.keyIdHex, extractedPubResult.keyIdHex)
        assertEquals(privResult.fingerprintHex, extractedPubResult.fingerprintHex)
        assertEquals(privResult.userId, extractedPubResult.userId)
    }

    @Test
    fun testKeyWithoutUserId_HandledCorrectly() {
        val (pubArmor, _) = generateTestKeyRings(userId = "")

        val result = PgpKeyParser.parseKeyData(pubArmor)
        assertTrue(result is ParsedPgpKeyResult.PublicKeyResult)

        val pubResult = result as ParsedPgpKeyResult.PublicKeyResult
        assertTrue(pubResult.keyIdHex.isNotEmpty())
    }

    @Test
    fun testRejection_EmptyInput() {
        val result = PgpKeyParser.parseKeyData(ByteArray(0))
        assertTrue(result is ParsedPgpKeyResult.Error)
        val err = result as ParsedPgpKeyResult.Error
        assertTrue(err.message.contains("empty"))
    }

    @Test
    fun testRejection_GenericTextAndMalformedData() {
        val malformedBytes = "This is random text, not a PGP key!".toByteArray(Charsets.UTF_8)

        val result = PgpKeyParser.parseKeyData(malformedBytes)
        assertTrue(result is ParsedPgpKeyResult.Error)
    }

    @Test
    fun testPreservesOriginalKeyBytesLosslessly() {
        val (pubArmor, _) = generateTestKeyRings()

        val result = PgpKeyParser.parseKeyData(pubArmor)
        assertTrue(result is ParsedPgpKeyResult.PublicKeyResult)

        val pubResult = result as ParsedPgpKeyResult.PublicKeyResult
        assertArrayEquals(pubArmor, pubResult.rawKeyData)
    }
}
