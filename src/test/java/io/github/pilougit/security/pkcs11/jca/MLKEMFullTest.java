package io.github.pilougit.security.pkcs11.jca;

import com.sun.jna.NativeLong;
import com.sun.jna.ptr.NativeLongByReference;
import io.github.pilougit.security.pkcs11.jca.util.jna.CKAttributeBuilder;
import io.github.pilougit.security.pkcs11.jca.util.jna.PKCS11Helper;
import io.github.pilougit.security.pkcs11.jca.util.jna.PKCS11Library;
import io.github.pilougit.security.pkcs11.jca.util.jna.PKCS11Mechanisms;
import io.github.pilougit.security.pkcs11.jca.util.jna.PKCS11Structures;
import org.junit.jupiter.api.*;

import java.nio.file.Path;

import static io.github.pilougit.security.pkcs11.jca.util.helpers.HybridKemHelper.generateMLKEMKeyPair;
import static io.github.pilougit.security.pkcs11.jca.util.jna.PKCS11Types.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Comprehensive tests for ML-KEM variant mechanisms.
 * Tests key generation, encapsulation, and decapsulation using the low-level PKCS#11 API.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class MLKEMFullTest {

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
    void testMLKEM512KeyGeneration() throws Exception {
        System.out.println("\n=== Test ML-KEM-512 Key Generation ===");

        NativeLong[] keys = generateMLKEMKeyPair(
            pkcs11,
            hSession,
            PKCS11Mechanisms.CKM_MLKEM_512,
            512,
            "mlkem512-test",
            false
        );

        assertNotNull(keys);
        assertEquals(2, keys.length);
        assertNotNull(keys[0]); // Public key
        assertNotNull(keys[1]); // Private key

        System.out.println("✓ ML-KEM-512 keys generated successfully");
        System.out.println("  Public key handle: " + keys[0].longValue());
        System.out.println("  Private key handle: " + keys[1].longValue());

        // Cleanup
        pkcs11.C_DestroyObject(hSession, keys[0]);
        pkcs11.C_DestroyObject(hSession, keys[1]);
    }

    @Test
    @Order(2)
    void testMLKEM768KeyGeneration() throws Exception {
        System.out.println("\n=== Test ML-KEM-768 Key Generation ===");

        NativeLong[] keys = generateMLKEMKeyPair(
            pkcs11,
            hSession,
            PKCS11Mechanisms.CKM_MLKEM_768,
            768,
            "mlkem768-test",
            false
        );

        assertNotNull(keys);
        assertEquals(2, keys.length);

        System.out.println("✓ ML-KEM-768 keys generated successfully");
        System.out.println("  Public key handle: " + keys[0].longValue());
        System.out.println("  Private key handle: " + keys[1].longValue());

        // Cleanup
        pkcs11.C_DestroyObject(hSession, keys[0]);
        pkcs11.C_DestroyObject(hSession, keys[1]);
    }

    @Test
    @Order(3)
    void testMLKEM1024KeyGeneration() throws Exception {
        System.out.println("\n=== Test ML-KEM-1024 Key Generation ===");

        NativeLong[] keys = generateMLKEMKeyPair(
            pkcs11,
            hSession,
            PKCS11Mechanisms.CKM_MLKEM_1024,
            1024,
            "mlkem1024-test",
            false
        );

        assertNotNull(keys);
        assertEquals(2, keys.length);

        System.out.println("✓ ML-KEM-1024 keys generated successfully");
        System.out.println("  Public key handle: " + keys[0].longValue());
        System.out.println("  Private key handle: " + keys[1].longValue());

        // Cleanup
        pkcs11.C_DestroyObject(hSession, keys[0]);
        pkcs11.C_DestroyObject(hSession, keys[1]);
    }

    @Test
    @Order(4)
    void testMLKEM768EncapDecap() throws Exception {
        System.out.println("\n=== Test ML-KEM-768 Encapsulation/Decapsulation ===");

        // Generate key pair
        NativeLong[] keys = generateMLKEMKeyPair(
            pkcs11,
            hSession,
            PKCS11Mechanisms.CKM_MLKEM_768,
            768,
            "mlkem768-encap-test",
            false
        );

        NativeLong hPublicKey = keys[0];
        NativeLong hPrivateKey = keys[1];

        // Prepare mechanism for encapsulation
        PKCS11Structures.CK_MECHANISM mech = new PKCS11Structures.CK_MECHANISM();
        mech.mechanism = PKCS11Mechanisms.CKM_MLKEM_768;
        mech.pParameter = null;
        mech.ulParameterLen = new NativeLong(0);

        // Template for shared secret - use CKAttributeBuilder for proper memory layout
        int templateSize = 3 * NativeLong.SIZE + 1; // 3 NativeLongs + 1 boolean
        CKAttributeBuilder builder =
            new CKAttributeBuilder(3, templateSize);
        builder.setNativeLong(0, CKA_CLASS, CKO_SECRET_KEY.longValue());
        builder.setNativeLong(1, CKA_KEY_TYPE, CKK_GENERIC_SECRET.longValue());
        builder.setBoolean(2, CKA_EXTRACTABLE, true);
        PKCS11Structures.CK_ATTRIBUTE[] template = builder.build();

        // Encapsulate
        byte[] ciphertext = new byte[1088]; // ML-KEM-768 ciphertext size
        NativeLongByReference pulCiphertextLen = new NativeLongByReference(new NativeLong(1088));
        NativeLongByReference phSharedSecret1 = new NativeLongByReference();

        NativeLong rv = pkcs11.C_EncapsulateKey(
            hSession,
            mech,
            hPublicKey,
            template,
            new NativeLong(template.length),
            ciphertext,
            pulCiphertextLen,
            phSharedSecret1
        );

        assertEquals(CKR_OK, rv, "Encapsulation should succeed");
        assertEquals(1088, pulCiphertextLen.getValue().intValue(), "Ciphertext should be 1088 bytes");

        System.out.println("✓ Encapsulation successful");
        System.out.println("  Ciphertext size: " + pulCiphertextLen.getValue().intValue() + " bytes");

        // Decapsulate
        NativeLongByReference phSharedSecret2 = new NativeLongByReference();

        rv = pkcs11.C_DecapsulateKey(
            hSession,
            mech,
            hPrivateKey,
            template,
            new NativeLong(template.length),
            ciphertext,
            new NativeLong(1088),
            phSharedSecret2
        );

        assertEquals(CKR_OK, rv, "Decapsulation should succeed");

        System.out.println("✓ Decapsulation successful");

        // Extract both shared secrets and compare
        byte[] secret1 = extractSecretValue(phSharedSecret1.getValue());
        byte[] secret2 = extractSecretValue(phSharedSecret2.getValue());

        assertArrayEquals(secret1, secret2, "Shared secrets should match");
        assertEquals(32, secret1.length, "Shared secret should be 32 bytes");

        System.out.println("✓ Shared secrets match (" + secret1.length + " bytes)");

        // Cleanup
        pkcs11.C_DestroyObject(hSession, hPublicKey);
        pkcs11.C_DestroyObject(hSession, hPrivateKey);
        pkcs11.C_DestroyObject(hSession, phSharedSecret1.getValue());
        pkcs11.C_DestroyObject(hSession, phSharedSecret2.getValue());
    }

    @Test
    @Order(5)
    void testMLKEMWrongMechanismFails() throws Exception {
        System.out.println("\n=== Test Wrong Mechanism Validation ===");

        // Generate ML-KEM-512 key pair
        NativeLong[] keys = generateMLKEMKeyPair(
            pkcs11,
            hSession,
            PKCS11Mechanisms.CKM_MLKEM_512,
            512,
            "mlkem512-wrong-mech",
            false
        );

        NativeLong hPublicKey = keys[0];
        NativeLong hPrivateKey = keys[1];

        // Try to use CKM_MLKEM_768 with ML-KEM-512 key - should fail
        PKCS11Structures.CK_MECHANISM mech = new PKCS11Structures.CK_MECHANISM();
        mech.mechanism = PKCS11Mechanisms.CKM_MLKEM_768; // Wrong mechanism!
        mech.pParameter = null;
        mech.ulParameterLen = new NativeLong(0);

        // Template for shared secret - use CKAttributeBuilder for proper memory layout
        int templateSize = 3 * NativeLong.SIZE + 1; // 3 NativeLongs + 1 boolean
        CKAttributeBuilder builder =
            new CKAttributeBuilder(3, templateSize);
        builder.setNativeLong(0, CKA_CLASS, CKO_SECRET_KEY.longValue());
        builder.setNativeLong(1, CKA_KEY_TYPE, CKK_GENERIC_SECRET.longValue());
        builder.setBoolean(2, CKA_EXTRACTABLE, true);
        PKCS11Structures.CK_ATTRIBUTE[] template = builder.build();

        byte[] ciphertext = new byte[1088];
        NativeLongByReference pulCiphertextLen = new NativeLongByReference(new NativeLong(1088));
        NativeLongByReference phSharedSecret = new NativeLongByReference();

        NativeLong rv = pkcs11.C_EncapsulateKey(
            hSession,
            mech,
            hPublicKey,
            template,
            new NativeLong(template.length),
            ciphertext,
            pulCiphertextLen,
            phSharedSecret
        );

        assertNotEquals(CKR_OK, rv, "Should fail when mechanism doesn't match key size");
        System.out.println("✓ Correctly rejected mismatched mechanism (error: 0x" +
                          Long.toHexString(rv.longValue()) + ")");

        // Cleanup
        pkcs11.C_DestroyObject(hSession, hPublicKey);
        pkcs11.C_DestroyObject(hSession, hPrivateKey);
    }

    /**
     * Helper method to extract the CKA_VALUE from a secret key object.
     */
    private byte[] extractSecretValue(NativeLong hKey) {
        PKCS11Structures.CK_ATTRIBUTE[] template = new PKCS11Structures.CK_ATTRIBUTE[]{
            PKCS11Helper.createQueryAttribute(CKA_VALUE)
        };

        // Get size
        NativeLong rv = pkcs11.C_GetAttributeValue(hSession, hKey, template, new NativeLong(1));
        if (!rv.equals(CKR_OK)) {
            throw new RuntimeException("Failed to get attribute size: 0x" + Long.toHexString(rv.longValue()));
        }

        // Get value
        int size = template[0].ulValueLen.intValue();
        byte[] value = new byte[size];
        template = new PKCS11Structures.CK_ATTRIBUTE[]{
            PKCS11Helper.createByteArrayAttribute(CKA_VALUE, value)
        };
        template[0].pValue.write(0, value, 0, size);

        rv = pkcs11.C_GetAttributeValue(hSession, hKey, template, new NativeLong(1));
        if (!rv.equals(CKR_OK)) {
            throw new RuntimeException("Failed to get attribute value: 0x" + Long.toHexString(rv.longValue()));
        }

        template[0].pValue.read(0, value, 0, size);
        return value;
    }
}
