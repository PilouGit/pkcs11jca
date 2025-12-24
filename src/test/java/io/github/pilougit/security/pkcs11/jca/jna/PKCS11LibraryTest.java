package io.github.pilougit.security.pkcs11.jca.jna;

import com.sun.jna.NativeLong;
import com.sun.jna.ptr.NativeLongByReference;
import io.github.pilougit.security.pkcs11.jca.util.jna.*;
import org.junit.jupiter.api.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test class for PKCS11Library.
 *
 * These tests require a PKCS#11 library to be available (e.g., SoftHSMv2).
 * Set the system property pkcs11.library to the path of your PKCS#11 library:
 *
 * mvn test -Dpkcs11.library=/usr/lib/softhsm/libsofthsm2.so
 *
 * Before running tests, initialize a SoftHSM token:
 * softhsm2-util --init-token --slot 0 --label "Test Token" --so-pin 1234 --pin 1234
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class PKCS11LibraryTest {

    private static PKCS11Library pkcs11;
    private static String libraryPath;
    private static boolean skipTests = false;

    @BeforeAll
    public static void setup() {
        // Get library path from system property
        libraryPath = System.getProperty("pkcs11.library");

        if (libraryPath == null || libraryPath.isEmpty()) {
            System.out.println("WARNING: No PKCS#11 library specified. Tests will be skipped.");
            System.out.println("To run tests, set -Dpkcs11.library=/path/to/pkcs11.so");
            skipTests = true;
            return;
        }

        try {
            pkcs11 = PKCS11Library.getInstance(libraryPath);
            System.out.println("Loaded PKCS#11 library: " + libraryPath);
        } catch (Exception e) {
            System.err.println("Failed to load PKCS#11 library: " + e.getMessage());
            skipTests = true;
        }
    }

    @Test
    @Order(1)
    public void testInitialize() {
        if (skipTests) {
            System.out.println("Skipping test - no PKCS#11 library available");
            return;
        }

        NativeLong rv = pkcs11.C_Initialize(null);
        assertTrue(rv.equals(PKCS11Types.CKR_OK) || rv.equals(PKCS11Types.CKR_CRYPTOKI_ALREADY_INITIALIZED),
                "C_Initialize should succeed or already be initialized");
    }

    @Test
    @Order(2)
    public void testGetInfo() {
        if (skipTests) {
            System.out.println("Skipping test - no PKCS#11 library available");
            return;
        }

        PKCS11Structures.CK_INFO info = new PKCS11Structures.CK_INFO();
        NativeLong rv = pkcs11.C_GetInfo(info);

        assertEquals(PKCS11Types.CKR_OK, rv, "C_GetInfo should succeed");
        assertNotNull(info.cryptokiVersion, "Cryptoki version should not be null");

        System.out.println("Cryptoki Version: " + info.cryptokiVersion.major + "." + info.cryptokiVersion.minor);
        System.out.println("Manufacturer ID: " + new String(info.manufacturerID).trim());
        System.out.println("Library Description: " + new String(info.libraryDescription).trim());
        System.out.println("Library Version: " + info.libraryVersion.major + "." + info.libraryVersion.minor);
    }

    @Test
    @Order(3)
    public void testGetSlotList() {
        if (skipTests) {
            System.out.println("Skipping test - no PKCS#11 library available");
            return;
        }

        // Get slot count
        NativeLongByReference slotCount = new NativeLongByReference();
        NativeLong rv = pkcs11.C_GetSlotList(PKCS11Types.CK_FALSE, null, slotCount);

        assertEquals(PKCS11Types.CKR_OK, rv, "C_GetSlotList should succeed");
        assertTrue(slotCount.getValue().intValue() > 0, "Should have at least one slot");

        // Get slot list
        NativeLong[] slots = new NativeLong[slotCount.getValue().intValue()];
        rv = pkcs11.C_GetSlotList(PKCS11Types.CK_FALSE, slots, slotCount);

        assertEquals(PKCS11Types.CKR_OK, rv, "C_GetSlotList should succeed");
        System.out.println("Found " + slotCount.getValue().intValue() + " slot(s)");
    }

    @Test
    @Order(4)
    public void testGetSlotInfo() {
        if (skipTests) {
            System.out.println("Skipping test - no PKCS#11 library available");
            return;
        }

        // Get first slot
        NativeLongByReference slotCount = new NativeLongByReference();
        pkcs11.C_GetSlotList(PKCS11Types.CK_FALSE, null, slotCount);

        if (slotCount.getValue().intValue() == 0) {
            System.out.println("No slots available for testing");
            return;
        }

        NativeLong[] slots = new NativeLong[slotCount.getValue().intValue()];
        pkcs11.C_GetSlotList(PKCS11Types.CK_FALSE, slots, slotCount);

        // Get slot info
        PKCS11Structures.CK_SLOT_INFO slotInfo = new PKCS11Structures.CK_SLOT_INFO();
        NativeLong rv = pkcs11.C_GetSlotInfo(slots[0], slotInfo);

        assertEquals(PKCS11Types.CKR_OK, rv, "C_GetSlotInfo should succeed");
        System.out.println("Slot Description: " + new String(slotInfo.slotDescription).trim());
        System.out.println("Manufacturer ID: " + new String(slotInfo.manufacturerID).trim());
    }

    @Test
    @Order(5)
    public void testVendorDefines() {
        // Test vendor-specific constants
        assertNotNull(VendorDefines.CKM_VENDOR_MLKEM768_ECDH_P256);
        assertNotNull(VendorDefines.CKM_VENDOR_MLKEM1024_ECDH_P384);
        assertNotNull(VendorDefines.CKM_VENDOR_MLKEM768_X25519);
        assertNotNull(VendorDefines.CKM_VENDOR_MLDSA65_ECDSA_P256);
        assertNotNull(VendorDefines.CKM_VENDOR_MLDSA87_ECDSA_P384);

        // Test helper methods
        assertTrue(VendorDefines.isHybridKEMMechanism(VendorDefines.CKM_VENDOR_MLKEM768_ECDH_P256));
        assertTrue(VendorDefines.isHybridSignatureMechanism(VendorDefines.CKM_VENDOR_MLDSA65_ECDSA_P256));
        assertTrue(VendorDefines.isHybridMechanism(VendorDefines.CKM_VENDOR_MLKEM768_X25519));

        // Test mechanism names
        String kemName = VendorDefines.getHybridMechanismName(VendorDefines.CKM_VENDOR_MLKEM768_ECDH_P256);
        assertEquals("ML-KEM-768 + ECDH P-256", kemName);

        String sigName = VendorDefines.getHybridMechanismName(VendorDefines.CKM_VENDOR_MLDSA65_ECDSA_P256);
        assertEquals("ML-DSA-65 + ECDSA P-256", sigName);

        // Test combiner type names
        String combinerName = VendorDefines.getCombinerTypeName(VendorDefines.HYBRID_COMBINER_SHA256);
        assertEquals("SHA-256 KDF", combinerName);

        System.out.println("Vendor defines tests passed");
    }

    @Test
    @Order(6)
    public void testHybridMechanismInfo() {
        // Test CK_HYBRID_MECHANISM_INFO structure
        VendorDefines.CK_HYBRID_MECHANISM_INFO info = new VendorDefines.CK_HYBRID_MECHANISM_INFO(
            PKCS11Mechanisms.CKM_ML_KEM,
            PKCS11Mechanisms.CKM_ECDH1_DERIVE,
            VendorDefines.HYBRID_COMBINER_SHA256,
            new NativeLong(64)
        );

        assertEquals(PKCS11Mechanisms.CKM_ML_KEM, info.pqcMechanism);
        assertEquals(PKCS11Mechanisms.CKM_ECDH1_DERIVE, info.classicalMechanism);
        assertEquals(VendorDefines.HYBRID_COMBINER_SHA256, info.combinerType);
        assertEquals(64, info.outputLength.intValue());

        System.out.println("Hybrid mechanism info structure test passed");
    }

    @Test
    @Order(7)
    public void testPQCMechanisms() {
        // Test PQC mechanism constants
        assertNotNull(PKCS11Mechanisms.CKM_ML_KEM_512_KEY_PAIR_GEN);
        assertNotNull(PKCS11Mechanisms.CKM_ML_KEM_768_KEY_PAIR_GEN);
        assertNotNull(PKCS11Mechanisms.CKM_ML_KEM_1024_KEY_PAIR_GEN);
        assertNotNull(PKCS11Mechanisms.CKM_ML_KEM);

        assertNotNull(PKCS11Mechanisms.CKM_ML_DSA_44_KEY_PAIR_GEN);
        assertNotNull(PKCS11Mechanisms.CKM_ML_DSA_65_KEY_PAIR_GEN);
        assertNotNull(PKCS11Mechanisms.CKM_ML_DSA_87_KEY_PAIR_GEN);
        assertNotNull(PKCS11Mechanisms.CKM_ML_DSA);

        assertNotNull(PKCS11Mechanisms.CKM_SLH_DSA_SHA2_128S_KEY_PAIR_GEN);
        assertNotNull(PKCS11Mechanisms.CKM_SLH_DSA);

        System.out.println("PQC mechanism constants test passed");
    }

    @AfterAll
    public static void cleanup() {
        if (skipTests || pkcs11 == null) {
            return;
        }

        try {
            NativeLong rv = pkcs11.C_Finalize(null);
            if (rv.equals(PKCS11Types.CKR_OK)) {
                System.out.println("PKCS#11 library finalized successfully");
            }
        } catch (Exception e) {
            System.err.println("Error during cleanup: " + e.getMessage());
        }
    }
}
