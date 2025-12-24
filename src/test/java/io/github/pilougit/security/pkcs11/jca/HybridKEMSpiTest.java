package io.github.pilougit.security.pkcs11.jca;

import com.sun.jna.NativeLong;
import com.sun.jna.ptr.NativeLongByReference;
import io.github.pilougit.security.pkcs11.jca.util.jna.PKCS11Library;
import io.github.pilougit.security.pkcs11.jca.kem.Pkcs11HybridKEMSpi;
import io.github.pilougit.security.pkcs11.jca.keygen.Pkcs11HybridKEMKeyPairGeneratorSpi;
import io.github.pilougit.security.pkcs11.jca.keygen.Pkcs11HybridKEMPrivateKey;
import io.github.pilougit.security.pkcs11.jca.keygen.Pkcs11HybridKEMPublicKey;
import org.junit.jupiter.api.*;

import javax.crypto.KEMSpi;
import javax.crypto.SecretKey;
import java.nio.file.Path;
import java.security.KeyPair;

import static io.github.pilougit.security.pkcs11.jca.util.jna.PKCS11Types.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Test suite for Pkcs11HybridKEMSpi.
 * Tests encapsulation/decapsulation operations with hybrid KEM keys.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class HybridKEMSpiTest {

    private static final String LIBRARY_PATH = "/home/pilou/myprojects/postquantum/softhsm2_distrib/lib/softhsm/libsofthsm2.so";
    private static final long SLOT_ID = 1969959532L;
    private static final String USER_PIN = "123456";

    private PKCS11Library pkcs11;
    private NativeLong hSession;

    @BeforeAll
    void setup() throws Exception {
        // Load PKCS#11 library
        pkcs11 = PKCS11Library.getInstance(Path.of(LIBRARY_PATH));

        // Initialize
        NativeLong rv = pkcs11.C_Initialize(null);
        if (!rv.equals(CKR_OK) && !rv.equals(new NativeLong(0x00000191L))) { // CKR_CRYPTOKI_ALREADY_INITIALIZED
            throw new RuntimeException("C_Initialize failed: 0x" + Long.toHexString(rv.longValue()));
        }

        // Open session
        NativeLongByReference phSession = new NativeLongByReference();
        rv = pkcs11.C_OpenSession(
            new NativeLong(SLOT_ID),
            new NativeLong(CKF_SERIAL_SESSION.longValue() | CKF_RW_SESSION.longValue()),
            null,
            null,
            phSession
        );
        if (!rv.equals(CKR_OK)) {
            throw new RuntimeException("C_OpenSession failed: 0x" + Long.toHexString(rv.longValue()));
        }
        hSession = phSession.getValue();

        // Login
        byte[] pin = USER_PIN.getBytes();
        rv = pkcs11.C_Login(hSession, CKU_USER, pin, new NativeLong(pin.length));
        if (!rv.equals(CKR_OK) && !rv.equals(new NativeLong(0x00000100L))) { // CKR_USER_ALREADY_LOGGED_IN
            throw new RuntimeException("C_Login failed: 0x" + Long.toHexString(rv.longValue()));
        }
    }

    @AfterAll
    void cleanup() {
        if (hSession != null) {
            pkcs11.C_Logout(hSession);
            pkcs11.C_CloseSession(hSession);
        }
        if (pkcs11 != null) {
            pkcs11.C_Finalize(null);
        }
    }

    @Test
    @Order(1)
    void testMLKEM768_ECDH_P256_EncapDecap() throws Exception {
        System.out.println("\n=== Test ML-KEM-768 + ECDH P-256 Encap/Decap ===");

        // Generate key pair
        Pkcs11HybridKEMKeyPairGeneratorSpi generator =
                new Pkcs11HybridKEMKeyPairGeneratorSpi(pkcs11, hSession);
        generator.initialize(768, null);
        KeyPair keyPair = generator.generateKeyPair();

        // Create KEM SPI
        Pkcs11HybridKEMSpi kemSpi = new Pkcs11HybridKEMSpi(pkcs11, hSession, "ECDH-P256-ML-KEM-768");

        // Create encapsulator
        KEMSpi.EncapsulatorSpi encapsulator = kemSpi.engineNewEncapsulator(
                keyPair.getPublic(), null, null);

        assertEquals(32, encapsulator.engineSecretSize());
        System.out.println("  Secret size: " + encapsulator.engineSecretSize() + " bytes");

        int encapSize = encapsulator.engineEncapsulationSize();
        assertEquals(65 + 1088, encapSize); // ECDH P-256 uncompressed (65) + ML-KEM-768 (1088)
        System.out.println("  Encapsulation size: " + encapSize + " bytes");

        // Encapsulate
        var encapsulated = encapsulator.engineEncapsulate(0, 32, "AES");
        byte[] ciphertext = encapsulated.encapsulation();
        SecretKey sharedSecret1 = encapsulated.key();

        assertNotNull(ciphertext);
        assertNotNull(sharedSecret1);
        assertEquals(65 + 1088, ciphertext.length); // ECDH P-256 uncompressed (65) + ML-KEM-768 (1088)
        assertEquals(32, sharedSecret1.getEncoded().length);

        System.out.println("✓ Encapsulation successful");
        System.out.println("  Ciphertext: " + ciphertext.length + " bytes");
        System.out.println("  Shared secret: " + sharedSecret1.getEncoded().length + " bytes");

        // Create decapsulator
        KEMSpi.DecapsulatorSpi decapsulator = kemSpi.engineNewDecapsulator(
                keyPair.getPrivate(), null);

        // Decapsulate
        SecretKey sharedSecret2 = decapsulator.engineDecapsulate(ciphertext, 0, 32, "AES");

        assertNotNull(sharedSecret2);
        assertEquals(32, sharedSecret2.getEncoded().length);

        System.out.println("✓ Decapsulation successful");

        // Verify secrets match
        assertArrayEquals(sharedSecret1.getEncoded(), sharedSecret2.getEncoded(),
                "Shared secrets should match");

        System.out.println("✓ Shared secrets match");

        // Cleanup
        Pkcs11HybridKEMPublicKey pubKey = (Pkcs11HybridKEMPublicKey) keyPair.getPublic();
        Pkcs11HybridKEMPrivateKey privKey = (Pkcs11HybridKEMPrivateKey) keyPair.getPrivate();
        pkcs11.C_DestroyObject(hSession, pubKey.getHandle());
        pkcs11.C_DestroyObject(hSession, privKey.getHandle());
    }

    @Test
    @Order(2)
    void testMLKEM1024_ECDH_P384_EncapDecap() throws Exception {
        System.out.println("\n=== Test ML-KEM-1024 + ECDH P-384 Encap/Decap ===");

        // Generate key pair
        Pkcs11HybridKEMKeyPairGeneratorSpi generator =
                new Pkcs11HybridKEMKeyPairGeneratorSpi(pkcs11, hSession);
        generator.initialize(1024, null);
        KeyPair keyPair = generator.generateKeyPair();

        // Create KEM SPI
        Pkcs11HybridKEMSpi kemSpi = new Pkcs11HybridKEMSpi(pkcs11, hSession, "ECDH-P384-ML-KEM-1024");

        // Encapsulate
        KEMSpi.EncapsulatorSpi encapsulator = kemSpi.engineNewEncapsulator(
                keyPair.getPublic(), null, null);
        var encapsulated = encapsulator.engineEncapsulate(0, 32, "AES");
        byte[] ciphertext = encapsulated.encapsulation();
        SecretKey sharedSecret1 = encapsulated.key();

        assertEquals(97 + 1568, ciphertext.length); // ECDH P-384 uncompressed (97) + ML-KEM-1024 (1568)
        assertEquals(32, sharedSecret1.getEncoded().length);

        System.out.println("✓ Encapsulation successful");

        // Decapsulate
        KEMSpi.DecapsulatorSpi decapsulator = kemSpi.engineNewDecapsulator(
                keyPair.getPrivate(), null);
        SecretKey sharedSecret2 = decapsulator.engineDecapsulate(ciphertext, 0, 32, "AES");

        System.out.println("✓ Decapsulation successful");

        // Verify secrets match
        assertArrayEquals(sharedSecret1.getEncoded(), sharedSecret2.getEncoded());

        System.out.println("✓ Shared secrets match");

        // Cleanup
        Pkcs11HybridKEMPublicKey pubKey = (Pkcs11HybridKEMPublicKey) keyPair.getPublic();
        Pkcs11HybridKEMPrivateKey privKey = (Pkcs11HybridKEMPrivateKey) keyPair.getPrivate();
        pkcs11.C_DestroyObject(hSession, pubKey.getHandle());
        pkcs11.C_DestroyObject(hSession, privKey.getHandle());
    }

    @Test
    @Order(3)
    void testMLKEM768_X25519_EncapDecap() throws Exception {
        System.out.println("\n=== Test ML-KEM-768 + X25519 Encap/Decap ===");

        // Generate key pair
        Pkcs11HybridKEMKeyPairGeneratorSpi generator =
                new Pkcs11HybridKEMKeyPairGeneratorSpi(pkcs11, hSession);
        generator.initialize(256, null);
        KeyPair keyPair = generator.generateKeyPair();

        // Create KEM SPI
        Pkcs11HybridKEMSpi kemSpi = new Pkcs11HybridKEMSpi(pkcs11, hSession, "X25519-ML-KEM-768");

        // Encapsulate
        KEMSpi.EncapsulatorSpi encapsulator = kemSpi.engineNewEncapsulator(
                keyPair.getPublic(), null, null);
        var encapsulated = encapsulator.engineEncapsulate(0, 32, "AES");
        byte[] ciphertext = encapsulated.encapsulation();
        SecretKey sharedSecret1 = encapsulated.key();

        assertEquals(32 + 1088, ciphertext.length); // X25519 raw (32) + ML-KEM-768 (1088)
        assertEquals(32, sharedSecret1.getEncoded().length);

        System.out.println("✓ Encapsulation successful");

        // Decapsulate
        KEMSpi.DecapsulatorSpi decapsulator = kemSpi.engineNewDecapsulator(
                keyPair.getPrivate(), null);
        SecretKey sharedSecret2 = decapsulator.engineDecapsulate(ciphertext, 0, 32, "AES");

        System.out.println("✓ Decapsulation successful");

        // Verify secrets match
        assertArrayEquals(sharedSecret1.getEncoded(), sharedSecret2.getEncoded());

        System.out.println("✓ Shared secrets match");

        // Cleanup
        Pkcs11HybridKEMPublicKey pubKey = (Pkcs11HybridKEMPublicKey) keyPair.getPublic();
        Pkcs11HybridKEMPrivateKey privKey = (Pkcs11HybridKEMPrivateKey) keyPair.getPrivate();
        pkcs11.C_DestroyObject(hSession, pubKey.getHandle());
        pkcs11.C_DestroyObject(hSession, privKey.getHandle());
    }

    @Test
    @Order(4)
    void testMultipleEncapsulations() throws Exception {
        System.out.println("\n=== Test Multiple Encapsulations ===");

        // Generate key pair
        Pkcs11HybridKEMKeyPairGeneratorSpi generator =
                new Pkcs11HybridKEMKeyPairGeneratorSpi(pkcs11, hSession);
        generator.initialize(768, null);
        KeyPair keyPair = generator.generateKeyPair();

        // Create KEM SPI
        Pkcs11HybridKEMSpi kemSpi = new Pkcs11HybridKEMSpi(pkcs11, hSession, "ECDH-P256-ML-KEM-768");

        // Perform multiple encapsulations
        KEMSpi.EncapsulatorSpi encapsulator = kemSpi.engineNewEncapsulator(
                keyPair.getPublic(), null, null);
        KEMSpi.DecapsulatorSpi decapsulator = kemSpi.engineNewDecapsulator(
                keyPair.getPrivate(), null);

        for (int i = 0; i < 3; i++) {
            var encapsulated = encapsulator.engineEncapsulate(0, 32, "AES");
            SecretKey sharedSecret1 = encapsulated.key();
            SecretKey sharedSecret2 = decapsulator.engineDecapsulate(
                    encapsulated.encapsulation(), 0, 32, "AES");

            assertArrayEquals(sharedSecret1.getEncoded(), sharedSecret2.getEncoded(),
                    "Shared secrets should match for iteration " + i);
        }

        System.out.println("✓ All 3 encapsulations/decapsulations successful");

        // Cleanup
        Pkcs11HybridKEMPublicKey pubKey = (Pkcs11HybridKEMPublicKey) keyPair.getPublic();
        Pkcs11HybridKEMPrivateKey privKey = (Pkcs11HybridKEMPrivateKey) keyPair.getPrivate();
        pkcs11.C_DestroyObject(hSession, pubKey.getHandle());
        pkcs11.C_DestroyObject(hSession, privKey.getHandle());
    }
}
