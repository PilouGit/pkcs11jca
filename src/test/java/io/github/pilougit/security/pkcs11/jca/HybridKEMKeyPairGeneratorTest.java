package io.github.pilougit.security.pkcs11.jca;

import com.sun.jna.NativeLong;
import com.sun.jna.ptr.NativeLongByReference;
import io.github.pilougit.security.pkcs11.jca.util.jna.PKCS11Library;
import io.github.pilougit.security.pkcs11.jca.keygen.Pkcs11HybridKEMKeyPairGeneratorSpi;
import io.github.pilougit.security.pkcs11.jca.keygen.Pkcs11HybridKEMPrivateKey;
import io.github.pilougit.security.pkcs11.jca.keygen.Pkcs11HybridKEMPublicKey;
import org.junit.jupiter.api.*;

import java.nio.file.Path;
import java.security.KeyPair;

import static io.github.pilougit.security.pkcs11.jca.util.jna.PKCS11Types.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Test suite for Hybrid KEM KeyPairGenerator.
 * Tests key generation for all supported hybrid KEM algorithms.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class HybridKEMKeyPairGeneratorTest {

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
    void testMLKEM768_ECDH_P256_KeyGeneration() throws Exception {
        System.out.println("\n=== Test ML-KEM-768 + ECDH P-256 Key Generation ===");

        // Create key pair generator
        Pkcs11HybridKEMKeyPairGeneratorSpi generator =
                new Pkcs11HybridKEMKeyPairGeneratorSpi(pkcs11, hSession);

        // Initialize with key size hint (768 for P-256)
        generator.initialize(768, null);

        // Generate key pair
        KeyPair keyPair = generator.generateKeyPair();

        assertNotNull(keyPair);
        assertNotNull(keyPair.getPublic());
        assertNotNull(keyPair.getPrivate());

        assertTrue(keyPair.getPublic() instanceof Pkcs11HybridKEMPublicKey);
        assertTrue(keyPair.getPrivate() instanceof Pkcs11HybridKEMPrivateKey);

        Pkcs11HybridKEMPublicKey pubKey = (Pkcs11HybridKEMPublicKey) keyPair.getPublic();
        Pkcs11HybridKEMPrivateKey privKey = (Pkcs11HybridKEMPrivateKey) keyPair.getPrivate();

        assertEquals("MLKEM768-ECDH-P256", pubKey.getAlgorithm());
        assertEquals("MLKEM768-ECDH-P256", privKey.getAlgorithm());

        System.out.println("✓ ML-KEM-768 + ECDH P-256 keys generated successfully");
        System.out.println("  Public key handle: " + pubKey.getHandle().longValue());
        System.out.println("  Private key handle: " + privKey.getHandle().longValue());

        // Cleanup
        pkcs11.C_DestroyObject(hSession, pubKey.getHandle());
        pkcs11.C_DestroyObject(hSession, privKey.getHandle());
    }

    @Test
    @Order(2)
    void testMLKEM1024_ECDH_P384_KeyGeneration() throws Exception {
        System.out.println("\n=== Test ML-KEM-1024 + ECDH P-384 Key Generation ===");

        Pkcs11HybridKEMKeyPairGeneratorSpi generator =
                new Pkcs11HybridKEMKeyPairGeneratorSpi(pkcs11, hSession);

        // Initialize with key size hint (1024 for P-384)
        generator.initialize(1024, null);

        KeyPair keyPair = generator.generateKeyPair();

        assertNotNull(keyPair);
        assertTrue(keyPair.getPublic() instanceof Pkcs11HybridKEMPublicKey);
        assertTrue(keyPair.getPrivate() instanceof Pkcs11HybridKEMPrivateKey);

        Pkcs11HybridKEMPublicKey pubKey = (Pkcs11HybridKEMPublicKey) keyPair.getPublic();
        Pkcs11HybridKEMPrivateKey privKey = (Pkcs11HybridKEMPrivateKey) keyPair.getPrivate();

        assertEquals("MLKEM1024-ECDH-P384", pubKey.getAlgorithm());
        assertEquals("MLKEM1024-ECDH-P384", privKey.getAlgorithm());

        System.out.println("✓ ML-KEM-1024 + ECDH P-384 keys generated successfully");
        System.out.println("  Public key handle: " + pubKey.getHandle().longValue());
        System.out.println("  Private key handle: " + privKey.getHandle().longValue());

        // Cleanup
        pkcs11.C_DestroyObject(hSession, pubKey.getHandle());
        pkcs11.C_DestroyObject(hSession, privKey.getHandle());
    }

    @Test
    @Order(3)
    void testMLKEM768_X25519_KeyGeneration() throws Exception {
        System.out.println("\n=== Test ML-KEM-768 + X25519 Key Generation ===");

        Pkcs11HybridKEMKeyPairGeneratorSpi generator =
                new Pkcs11HybridKEMKeyPairGeneratorSpi(pkcs11, hSession);

        // Initialize with key size hint (256 for X25519)
        generator.initialize(256, null);

        KeyPair keyPair = generator.generateKeyPair();

        assertNotNull(keyPair);
        assertTrue(keyPair.getPublic() instanceof Pkcs11HybridKEMPublicKey);
        assertTrue(keyPair.getPrivate() instanceof Pkcs11HybridKEMPrivateKey);

        Pkcs11HybridKEMPublicKey pubKey = (Pkcs11HybridKEMPublicKey) keyPair.getPublic();
        Pkcs11HybridKEMPrivateKey privKey = (Pkcs11HybridKEMPrivateKey) keyPair.getPrivate();

        assertEquals("MLKEM768-X25519", pubKey.getAlgorithm());
        assertEquals("MLKEM768-X25519", privKey.getAlgorithm());

        System.out.println("✓ ML-KEM-768 + X25519 keys generated successfully");
        System.out.println("  Public key handle: " + pubKey.getHandle().longValue());
        System.out.println("  Private key handle: " + privKey.getHandle().longValue());

        // Cleanup
        pkcs11.C_DestroyObject(hSession, pubKey.getHandle());
        pkcs11.C_DestroyObject(hSession, privKey.getHandle());
    }

    @Test
    @Order(4)
    void testWithParameterSpec() throws Exception {
        System.out.println("\n=== Test with HybridKEMParameterSpec ===");

        Pkcs11HybridKEMKeyPairGeneratorSpi generator =
                new Pkcs11HybridKEMKeyPairGeneratorSpi(pkcs11, hSession);

        // Initialize with parameter spec
        Pkcs11HybridKEMKeyPairGeneratorSpi.HybridKEMParameterSpec params =
                new Pkcs11HybridKEMKeyPairGeneratorSpi.HybridKEMParameterSpec("MLKEM768-ECDH-P256");
        generator.initialize(params, null);

        KeyPair keyPair = generator.generateKeyPair();

        assertNotNull(keyPair);
        Pkcs11HybridKEMPublicKey pubKey = (Pkcs11HybridKEMPublicKey) keyPair.getPublic();
        assertEquals("MLKEM768-ECDH-P256", pubKey.getAlgorithm());

        System.out.println("✓ Key generation with ParameterSpec successful");

        // Cleanup
        pkcs11.C_DestroyObject(hSession, pubKey.getHandle());
        pkcs11.C_DestroyObject(hSession, ((Pkcs11HybridKEMPrivateKey) keyPair.getPrivate()).getHandle());
    }

    @Test
    @Order(5)
    void testInvalidKeySize() {
        System.out.println("\n=== Test Invalid Key Size ===");

        Pkcs11HybridKEMKeyPairGeneratorSpi generator =
                new Pkcs11HybridKEMKeyPairGeneratorSpi(pkcs11, hSession);

        assertThrows(java.security.InvalidParameterException.class, () -> {
            generator.initialize(2048, null);
        });

        System.out.println("✓ Correctly rejected invalid key size");
    }
}
