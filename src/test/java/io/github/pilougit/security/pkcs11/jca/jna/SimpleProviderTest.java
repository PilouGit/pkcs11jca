package io.github.pilougit.security.pkcs11.jca.jna;

import com.sun.jna.NativeLong;
import com.sun.jna.ptr.NativeLongByReference;
import io.github.pilougit.security.pkcs11.jca.HsmOptions;
import io.github.pilougit.security.pkcs11.jca.Pkcs11Provider;
import io.github.pilougit.security.pkcs11.jca.util.jna.PKCS11Library;
import io.github.pilougit.security.pkcs11.jca.util.jna.PKCS11Structures;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.security.SecureRandom;

public class SimpleProviderTest {

    @Test
    public void testDirectPKCS11() {
        String libraryPath = "/home/pilou/myprojects/postquantum/softhsm2_distrib/lib/softhsm/libsofthsm2.so";
        long slotId = 1969959532L;

        System.out.println("\n=== Direct PKCS#11 Test ===\n");

        // Load library
        System.out.println("1. Loading library...");
        PKCS11Library pkcs11 = PKCS11Library.getInstance(libraryPath);
        System.out.println("   ✓ Loaded\n");

        // Initialize
        System.out.println("2. Initializing...");
        PKCS11Structures.CK_C_INITIALIZE_ARGS initArgs = new PKCS11Structures.CK_C_INITIALIZE_ARGS();
        initArgs.flags = new NativeLong(0);
        initArgs.pReserved = null;
        NativeLong rv = pkcs11.C_Initialize(initArgs.getPointer());
        System.out.println("   C_Initialize returned: " + rv.longValue() + " (0x" + Long.toHexString(rv.longValue()) + ")");

        if (rv.longValue() == 0) {
            System.out.println("   ✓ Success\n");
        } else if (rv.longValue() == 0x00000191L) {
            System.out.println("   ℹ Already initialized\n");
        } else {
            System.out.println("   ✗ Failed: " + getErrorName(rv.longValue()) + "\n");
            return;
        }

        // Open session
        System.out.println("3. Opening session on slot " + slotId + "...");
        NativeLongByReference phSession = new NativeLongByReference();
        long flags = 0x00000004L | 0x00000002L; // CKF_SERIAL_SESSION | CKF_RW_SESSION
        rv = pkcs11.C_OpenSession(new NativeLong(slotId), new NativeLong(flags), null, null, phSession);
        System.out.println("   C_OpenSession returned: " + rv.longValue() + " (0x" + Long.toHexString(rv.longValue()) + ")");

        if (rv.longValue() != 0) {
            System.out.println("   ✗ Failed: " + getErrorName(rv.longValue()));
            return;
        }

        NativeLong hSession = phSession.getValue();
        System.out.println("   ✓ Session: " + hSession.longValue() + "\n");

        // Generate random
        System.out.println("4. Generating random bytes...");
        byte[] randomBytes = new byte[16];
        rv = pkcs11.C_GenerateRandom(hSession, randomBytes, new NativeLong(randomBytes.length));
        System.out.println("   C_GenerateRandom returned: " + rv.longValue());

        if (rv.longValue() == 0) {
            System.out.println("   ✓ Generated: " + bytesToHex(randomBytes));
        } else {
            System.out.println("   ✗ Failed: " + getErrorName(rv.longValue()));
        }

        System.out.println("\n=== Test Completed ===\n");
    }

    @Test
    public void testProviderConfiguration() {
        System.out.println("\n=== Provider Configuration Test ===\n");

        HsmOptions options = new HsmOptions.Builder()
                .name("SoftHsm")
                .pkcs11Library(Path.of("/home/pilou/myprojects/postquantum/softhsm2_distrib/lib/softhsm/libsofthsm2.so"))
                .slot(1969959532)
                .userPin("123456".toCharArray())
                .build();

        try {
            Pkcs11Provider provider = new Pkcs11Provider();
            System.out.println("Configuring provider...");
            provider.configure(options);
            System.out.println("✓ Provider configured successfully");
            System.out.println("✓ Slot: " + provider.getSlotID());
            System.out.println("✓ Session: " + provider.getSession());

            // Try to get SecureRandom
            System.out.println("\nTrying to get SecureRandom instance...");
            SecureRandom random = SecureRandom.getInstance("PKCS11", provider);
            System.out.println("✓ SecureRandom obtained");

            byte[] randomBytes = new byte[16];
            random.nextBytes(randomBytes);
            System.out.println("✓ Generated random: " + bytesToHex(randomBytes));

        } catch (Exception e) {
            System.out.println("✗ Error: " + e.getMessage());
            e.printStackTrace();
        }

        System.out.println("\n=== Test Completed ===\n");
    }

    private String getErrorName(long errorCode) {
        switch ((int) errorCode) {
            case 0x00000000: return "CKR_OK";
            case 0x00000005: return "CKR_GENERAL_ERROR";
            case 0x00000003: return "CKR_SLOT_ID_INVALID";
            case 0x000000E0: return "CKR_TOKEN_NOT_PRESENT";
            case 0x000000A0: return "CKR_PIN_INCORRECT";
            case 0x00000191: return "CKR_CRYPTOKI_ALREADY_INITIALIZED";
            case 0x00000100: return "CKR_USER_ALREADY_LOGGED_IN";
            default: return "UNKNOWN_ERROR_0x" + Long.toHexString(errorCode);
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
