package io.github.pilougit.security.pkcs11.jca.jna;

import com.sun.jna.NativeLong;
import com.sun.jna.ptr.NativeLongByReference;
import io.github.pilougit.security.pkcs11.jca.util.jna.PKCS11Library;
import io.github.pilougit.security.pkcs11.jca.util.jna.PKCS11Structures;

public class TestDebug {
    public static void main(String[] args) {
        String libraryPath = "/home/pilou/myprojects/postquantum/softhsm2_distrib/lib/softhsm/libsofthsm2.so";
        long slotId = 1969959532L;

        System.out.println("=== PKCS#11 Debug Test ===\n");

        // Load library
        System.out.println("1. Loading PKCS#11 library: " + libraryPath);
        PKCS11Library pkcs11 = PKCS11Library.getInstance(libraryPath);
        System.out.println("   ✓ Library loaded\n");

        // Initialize
        System.out.println("2. Calling C_Initialize...");
        PKCS11Structures.CK_C_INITIALIZE_ARGS initArgs = new PKCS11Structures.CK_C_INITIALIZE_ARGS();
        initArgs.flags = new NativeLong(0);
        initArgs.pReserved = null;

        NativeLong rv = pkcs11.C_Initialize(initArgs.getPointer());
        System.out.println("   Return value: " + rv.longValue() + " (0x" + Long.toHexString(rv.longValue()) + ")");

        if (rv.longValue() == 0) {
            System.out.println("   ✓ C_Initialize successful\n");
        } else if (rv.longValue() == 0x00000191L) {
            System.out.println("   ℹ C_Initialize returned CKR_CRYPTOKI_ALREADY_INITIALIZED (library already initialized)\n");
        } else {
            System.out.println("   ✗ C_Initialize failed with error: " + rv.longValue());
            System.exit(1);
        }

        // Get slot list
        System.out.println("3. Getting slot list...");
        NativeLongByReference pulCount = new NativeLongByReference();
        rv = pkcs11.C_GetSlotList((byte) 1, null, pulCount);
        System.out.println("   Return value: " + rv.longValue());
        System.out.println("   Number of slots: " + pulCount.getValue().longValue());

        if (rv.longValue() != 0) {
            System.out.println("   ✗ C_GetSlotList failed");
            System.exit(1);
        }

        NativeLong[] slotList = new NativeLong[(int) pulCount.getValue().longValue()];
        rv = pkcs11.C_GetSlotList((byte) 1, slotList, pulCount);
        System.out.println("   ✓ Got " + slotList.length + " slot(s)");
        for (int i = 0; i < slotList.length; i++) {
            System.out.println("     Slot " + i + ": " + slotList[i].longValue());
        }
        System.out.println();

        // Open session
        System.out.println("4. Opening session on slot " + slotId + "...");
        NativeLongByReference phSession = new NativeLongByReference();
        long flags = 0x00000004L | 0x00000002L; // CKF_SERIAL_SESSION | CKF_RW_SESSION
        System.out.println("   Session flags: 0x" + Long.toHexString(flags));

        rv = pkcs11.C_OpenSession(new NativeLong(slotId), new NativeLong(flags), null, null, phSession);
        System.out.println("   Return value: " + rv.longValue() + " (0x" + Long.toHexString(rv.longValue()) + ")");

        if (rv.longValue() != 0) {
            System.out.println("   ✗ C_OpenSession failed with error: " + rv.longValue());
            printPKCS11Error(rv.longValue());
            System.exit(1);
        }

        NativeLong hSession = phSession.getValue();
        System.out.println("   ✓ Session opened: " + hSession.longValue() + "\n");

        // Login
        System.out.println("5. Logging in with PIN...");
        byte[] pin = "123456".getBytes();
        rv = pkcs11.C_Login(hSession, new NativeLong(1), pin, new NativeLong(pin.length));
        System.out.println("   Return value: " + rv.longValue() + " (0x" + Long.toHexString(rv.longValue()) + ")");

        if (rv.longValue() == 0) {
            System.out.println("   ✓ Login successful\n");
        } else if (rv.longValue() == 0x00000100L) {
            System.out.println("   ℹ User already logged in\n");
        } else {
            System.out.println("   ✗ C_Login failed");
            printPKCS11Error(rv.longValue());
        }

        // Generate random
        System.out.println("6. Generating random bytes...");
        byte[] randomBytes = new byte[16];
        rv = pkcs11.C_GenerateRandom(hSession, randomBytes, new NativeLong(randomBytes.length));
        System.out.println("   Return value: " + rv.longValue());

        if (rv.longValue() == 0) {
            System.out.println("   ✓ Generated random bytes: " + bytesToHex(randomBytes));
        } else {
            System.out.println("   ✗ C_GenerateRandom failed");
            printPKCS11Error(rv.longValue());
        }

        System.out.println("\n=== Test completed ===");
    }

    private static void printPKCS11Error(long errorCode) {
        System.out.println("   PKCS#11 error code: 0x" + Long.toHexString(errorCode));
        switch ((int) errorCode) {
            case 0x00000005: System.out.println("   CKR_GENERAL_ERROR"); break;
            case 0x00000003: System.out.println("   CKR_SLOT_ID_INVALID"); break;
            case 0x000000E0: System.out.println("   CKR_TOKEN_NOT_PRESENT"); break;
            case 0x000000A0: System.out.println("   CKR_PIN_INCORRECT"); break;
            default: System.out.println("   Unknown error");
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
