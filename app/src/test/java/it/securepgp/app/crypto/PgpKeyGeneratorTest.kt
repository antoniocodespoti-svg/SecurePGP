package it.securepgp.app.crypto

import java.io.ByteArrayInputStream
import java.security.Security
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openpgp.PGPException
import org.bouncycastle.openpgp.PGPObjectFactory
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.BeforeClass
import org.junit.Test

class PgpKeyGeneratorTest {

    companion object {
        @BeforeClass
        @JvmStatic
        fun setUpProvider() {
            if (Security.getProvider("BC") == null) {
                Security.addProvider(BouncyCastleProvider())
            }
        }
    }

    @Test
    fun testGenerateRsa3072_Success() {
        val userId = "Test User RSA3072 <rsa3072@securepgp.app>"
        val passphrase = "testPassphrase123".toCharArray()

        val result = PgpKeyGenerator.generateKeypair(
            userId = userId,
            passphrase = passphrase,
            profile = PgpProfile.RSA_3072,
        )

        assertNotNull(result)
        assertTrue(result.keyIdHex.startsWith("0x"))
        assertEquals(18, result.keyIdHex.length)
        assertEquals(40, result.fingerprintHex.length)
        assertEquals(userId, result.userId)
        assertEquals(PgpProfile.RSA_3072, result.profile)

        val pubParse = PgpKeyParser.parseKeyData(result.publicKeyAsciiArmor)
        assertTrue(pubParse is ParsedPgpKeyResult.PublicKeyResult)
        val pubRes = pubParse as ParsedPgpKeyResult.PublicKeyResult
        assertEquals(result.keyIdHex, pubRes.keyIdHex)
        assertEquals(result.fingerprintHex, pubRes.fingerprintHex)

        val privParse = PgpKeyParser.parseKeyData(result.privateKeyAsciiArmor)
        assertTrue(privParse is ParsedPgpKeyResult.PrivateKeyResult)
        val privRes = privParse as ParsedPgpKeyResult.PrivateKeyResult
        assertEquals(result.keyIdHex, privRes.keyIdHex)
        assertEquals(result.fingerprintHex, privRes.fingerprintHex)
    }

    @Test
    fun testGenerateRsa4096_Success() {
        val userId = "Test User RSA4096 <rsa4096@securepgp.app>"
        val passphrase = "testPassphrase4096".toCharArray()

        val result = PgpKeyGenerator.generateKeypair(
            userId = userId,
            passphrase = passphrase,
            profile = PgpProfile.RSA_4096,
        )

        assertNotNull(result)
        assertTrue(result.keyIdHex.startsWith("0x"))
        assertEquals(userId, result.userId)
        assertEquals(PgpProfile.RSA_4096, result.profile)

        val pubParse = PgpKeyParser.parseKeyData(result.publicKeyAsciiArmor)
        assertTrue(pubParse is ParsedPgpKeyResult.PublicKeyResult)
        assertEquals(result.keyIdHex, (pubParse as ParsedPgpKeyResult.PublicKeyResult).keyIdHex)
    }

    @Test
    fun testGenerateEd25519V4Legacy_Success() {
        val userId = "Test User Ed25519 v4 <ed25519v4@securepgp.app>"
        val passphrase = "ed25519Passphrase".toCharArray()

        val result = PgpKeyGenerator.generateKeypair(
            userId = userId,
            passphrase = passphrase,
            profile = PgpProfile.ED25519_V4_LEGACY,
        )

        assertNotNull(result)
        assertTrue(result.keyIdHex.startsWith("0x"))
        assertEquals(userId, result.userId)
        assertEquals(PgpProfile.ED25519_V4_LEGACY, result.profile)

        val pubParse = PgpKeyParser.parseKeyData(result.publicKeyAsciiArmor)
        assertTrue(pubParse is ParsedPgpKeyResult.PublicKeyResult)

        val privParse = PgpKeyParser.parseKeyData(result.privateKeyAsciiArmor)
        assertTrue(privParse is ParsedPgpKeyResult.PrivateKeyResult)
    }

    @Test
    fun testGenerateEd25519V6Native_Success() {
        val userId = "Test User Ed25519 v6 <ed25519v6@securepgp.app>"
        val passphrase = "ed25519V6Passphrase".toCharArray()

        val result = PgpKeyGenerator.generateKeypair(
            userId = userId,
            passphrase = passphrase,
            profile = PgpProfile.ED25519_V6_NATIVE,
        )

        assertNotNull(result)
        assertTrue(result.keyIdHex.startsWith("0x"))
        assertEquals(userId, result.userId)
        assertEquals(PgpProfile.ED25519_V6_NATIVE, result.profile)

        val pubParse = PgpKeyParser.parseKeyData(result.publicKeyAsciiArmor)
        assertTrue(pubParse is ParsedPgpKeyResult.PublicKeyResult)

        val pubRes = pubParse as ParsedPgpKeyResult.PublicKeyResult
        assertEquals(result.keyIdHex, pubRes.keyIdHex)
    }

    @Test
    fun testPrivateKeyPassphraseProtection() {
        val userId = "Passphrase Check <pass@securepgp.app>"
        val correctPass = "SecureKeyPass2026".toCharArray()

        val result = PgpKeyGenerator.generateKeypair(
            userId = userId,
            passphrase = correctPass,
            profile = PgpProfile.RSA_3072,
        )

        val decoderStream = PGPUtil.getDecoderStream(ByteArrayInputStream(result.privateKeyAsciiArmor))
        val objectFactory = PGPObjectFactory(decoderStream, JcaKeyFingerprintCalculator())
        val pgpObj = objectFactory.nextObject()

        assertTrue(pgpObj is PGPSecretKeyRing)
        val secretKeyRing = pgpObj as PGPSecretKeyRing
        val masterSecretKey = secretKeyRing.secretKey

        val decryptor = JcePBESecretKeyDecryptorBuilder()
            .setProvider("BC")
            .build(correctPass)

        val privateKey = masterSecretKey.extractPrivateKey(decryptor)
        assertNotNull(privateKey)
    }

    @Test(expected = PGPException::class)
    fun testWrongPassphraseRejection() {
        val userId = "Wrong Pass Check <wrongpass@securepgp.app>"
        val correctPass = "CorrectPass123".toCharArray()
        val wrongPass = "WrongPass999".toCharArray()

        val result = PgpKeyGenerator.generateKeypair(
            userId = userId,
            passphrase = correctPass,
            profile = PgpProfile.RSA_3072,
        )

        val decoderStream = PGPUtil.getDecoderStream(ByteArrayInputStream(result.privateKeyAsciiArmor))
        val objectFactory = PGPObjectFactory(decoderStream, JcaKeyFingerprintCalculator())
        val pgpObj = objectFactory.nextObject() as PGPSecretKeyRing
        val masterSecretKey = pgpObj.secretKey

        val wrongDecryptor = JcePBESecretKeyDecryptorBuilder()
            .setProvider("BC")
            .build(wrongPass)

        masterSecretKey.extractPrivateKey(wrongDecryptor)
    }

    @Test
    fun testExportedPrivateKeyReImportRestoresBothRecords() {
        val userId = "Export Import Check <export@securepgp.app>"
        val pass = "ExportPassphrase2026".toCharArray()

        val result = PgpKeyGenerator.generateKeypair(
            userId = userId,
            passphrase = pass,
            profile = PgpProfile.RSA_3072,
        )

        val exportedPrivateKeyBytes = result.privateKeyAsciiArmor
        assertTrue(String(exportedPrivateKeyBytes, Charsets.UTF_8).contains("-----BEGIN PGP PRIVATE KEY BLOCK-----"))

        val parseResult = PgpKeyParser.parseKeyData(exportedPrivateKeyBytes)
        assertTrue(parseResult is ParsedPgpKeyResult.PrivateKeyResult)

        val privResult = parseResult as ParsedPgpKeyResult.PrivateKeyResult
        assertEquals(result.keyIdHex, privResult.keyIdHex)

        assertNotNull(privResult.rawPublicKeyData)

        val pubParseResult = PgpKeyParser.parseKeyData(privResult.rawPublicKeyData!!)
        assertTrue(pubParseResult is ParsedPgpKeyResult.PublicKeyResult)
        assertEquals(result.keyIdHex, (pubParseResult as ParsedPgpKeyResult.PublicKeyResult).keyIdHex)
    }
}
