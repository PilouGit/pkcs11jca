package io.github.pilougit.security.pkcs11.jca.jna;

import io.github.pilougit.security.pkcs11.jca.HsmOptions;
import io.github.pilougit.security.pkcs11.jca.Pkcs11Provider;
import io.github.pilougit.security.pkcs11.jca.mechanisms.Mechanism;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.security.NoSuchAlgorithmException;
import java.security.Provider.Service;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

public class Pkcs11ProviderTest {

    private static final String LIBRARY_PATH = "/home/pilou/myprojects/postquantum/softhsm2_distrib/lib/softhsm/libsofthsm2.so";
    private static final long SLOT_ID = 1969959532L;
    private static final String USER_PIN = "123456";

    private Pkcs11Provider provider;

    @BeforeEach
    public void setUp() {
        String conf = System.getenv("SOFTHSM2_CONF");
        if (conf == null) {
            throw new IllegalStateException("SOFTHSM2_CONF not defined");
        }
        HsmOptions options = new HsmOptions.Builder()
                .name("SoftHsm")
                .pkcs11Library(Path.of(LIBRARY_PATH))
                .slot(SLOT_ID)
                .userPin(USER_PIN.toCharArray())
                .build();

        provider = new Pkcs11Provider();
        provider.configure(options);
    }

    @Test
    public void initPkcs11Provider() {
        assertNotNull(provider);
        assertTrue(provider.isConfigured());
        System.err.println(provider.getPkcs11Info());
        Set<Mechanism> mechanism = provider.getMechanisms(SLOT_ID);
        Mechanism testmech = mechanism.iterator().next();

        System.err.println(mechanism);
        System.err.println(provider.getMechanismInfo(SLOT_ID,testmech));
    }

    @Test
    public void testSecureRandomServiceRegistered() {
        Service service = provider.getService("SecureRandom", "PKCS11");
        assertNotNull(service, "SecureRandom service should be registered");
        assertEquals("SecureRandom", service.getType());
        assertEquals("PKCS11", service.getAlgorithm());
    }

    @Test
    public void testGetSecureRandomInstance() throws NoSuchAlgorithmException {
        SecureRandom random = SecureRandom.getInstance("PKCS11", provider);
        assertNotNull(random, "SecureRandom instance should not be null");
        assertEquals("PKCS11", random.getAlgorithm());
    }

    @Test
    public void testGenerateRandomBytes() throws NoSuchAlgorithmException {
        SecureRandom random = SecureRandom.getInstance("PKCS11", provider);

        // Generate 32 random bytes
        byte[] randomBytes = new byte[32];
        random.nextBytes(randomBytes);

        // Verify that bytes were generated (not all zeros)
        boolean hasNonZero = false;
        for (byte b : randomBytes) {
            if (b != 0) {
                hasNonZero = true;
                break;
            }
        }
        assertTrue(hasNonZero, "Generated random bytes should not be all zeros");

        System.out.println("Generated 32 random bytes: " + bytesToHex(randomBytes));
    }

    @Test
    public void testGenerateRandomBytesMultipleSizes() throws NoSuchAlgorithmException {
        SecureRandom random = SecureRandom.getInstance("PKCS11", provider);

        // Test different sizes
        int[] sizes = {1, 16, 32, 64, 128, 256};
        for (int size : sizes) {
            byte[] randomBytes = new byte[size];
            random.nextBytes(randomBytes);
            assertEquals(size, randomBytes.length);

            // Verify randomness (at least one non-zero byte)
            boolean hasNonZero = false;
            for (byte b : randomBytes) {
                if (b != 0) {
                    hasNonZero = true;
                    break;
                }
            }
            assertTrue(hasNonZero, "Generated " + size + " random bytes should contain non-zero values");
        }
    }

    @Test
    public void testGenerateSeed() throws NoSuchAlgorithmException {
        SecureRandom random = SecureRandom.getInstance("PKCS11", provider);

        byte[] seed = random.generateSeed(32);
        assertNotNull(seed);
        assertEquals(32, seed.length);

        // Verify that seed was generated (not all zeros)
        boolean hasNonZero = false;
        for (byte b : seed) {
            if (b != 0) {
                hasNonZero = true;
                break;
            }
        }
        assertTrue(hasNonZero, "Generated seed should not be all zeros");

        System.out.println("Generated seed: " + bytesToHex(seed));
    }

    @Test
    public void testSetSeed() throws NoSuchAlgorithmException {
        SecureRandom random = SecureRandom.getInstance("PKCS11", provider);

        // Set a seed
        byte[] seed = "test-seed-data-for-rng".getBytes();
        assertDoesNotThrow(() -> random.setSeed(seed), "setSeed should not throw exception");

        // Should still be able to generate random bytes after seeding
        byte[] randomBytes = new byte[16];
        random.nextBytes(randomBytes);
        assertNotNull(randomBytes);
    }

    @Test
    public void testRandomnessQuality() throws NoSuchAlgorithmException {
        SecureRandom random = SecureRandom.getInstance("PKCS11", provider);

        // Generate two consecutive random values and ensure they're different
        byte[] random1 = new byte[32];
        byte[] random2 = new byte[32];

        random.nextBytes(random1);
        random.nextBytes(random2);

        assertFalse(Arrays.equals(random1, random2),
                "Two consecutive random generations should produce different values");

        System.out.println("Random 1: " + bytesToHex(random1));
        System.out.println("Random 2: " + bytesToHex(random2));
    }

    @Test
    public void testSecureRandomViaSecurityProvider() throws NoSuchAlgorithmException {
        // Add provider to Security
        Security.addProvider(provider);

        try {
            SecureRandom random = SecureRandom.getInstance("PKCS11");
            assertNotNull(random);
            assertEquals("PKCS11", random.getAlgorithm());

            byte[] randomBytes = new byte[16];
            random.nextBytes(randomBytes);
            assertNotNull(randomBytes);

            System.out.println("Random via Security.addProvider: " + bytesToHex(randomBytes));
        } finally {
            Security.removeProvider(provider.getName());
        }
    }

    // Helper method to convert bytes to hex string
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
