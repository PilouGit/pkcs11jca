package io.github.pilougit.security.pkcs11.jca.jna;

import com.sun.jna.NativeLong;
import com.sun.jna.ptr.NativeLongByReference;
import io.github.pilougit.security.pkcs11.jca.util.jna.*;

import java.nio.file.Path;

public class DirectEncapsulateTest {
    public static void main(String[] args) {
        String libraryPath = "/home/pilou/myprojects/postquantum/softhsm2_distrib/lib/softhsm/libsofthsm2.so";
        long slotId = 1969959532L;
        String pin = "123456";

        System.out.println("\n=== Direct Encapsulation Test ===\n");

        // Load library
        System.out.println("1. Loading library...");
        PKCS11Library pkcs11 = PKCS11Library.getInstance(Path.of(libraryPath));
        System.out.println("   ✓ Loaded\n");

        // Initialize
        System.out.println("2. Initializing...");
        NativeLong rv = pkcs11.C_Initialize(null);
        if (!rv.equals(PKCS11Types.CKR_OK) && rv.longValue() != 0x00000191L) {
            System.err.println("   ✗ C_Initialize failed: 0x" + Long.toHexString(rv.longValue()));
            return;
        }
        System.out.println("   ✓ Initialized\n");

        // Open session
        System.out.println("3. Opening session...");
        NativeLongByReference phSession = new NativeLongByReference();
        long flags = PKCS11Types.CKF_SERIAL_SESSION.longValue() | PKCS11Types.CKF_RW_SESSION.longValue();
        rv = pkcs11.C_OpenSession(new NativeLong(slotId), new NativeLong(flags), null, null, phSession);
        if (!rv.equals(PKCS11Types.CKR_OK)) {
            System.err.println("   ✗ C_OpenSession failed: 0x" + Long.toHexString(rv.longValue()));
            return;
        }
        NativeLong hSession = phSession.getValue();
        System.out.println("   ✓ Session: " + hSession.longValue() + "\n");

        // Login
        System.out.println("4. Logging in...");
        byte[] pinBytes = pin.getBytes();
        rv = pkcs11.C_Login(hSession, PKCS11Types.CKU_USER, pinBytes, new NativeLong(pinBytes.length));
        if (!rv.equals(PKCS11Types.CKR_OK) && rv.longValue() != 0x00000100L) {
            System.err.println("   ✗ C_Login failed: 0x" + Long.toHexString(rv.longValue()));
        } else {
            System.out.println("   ✓ Logged in\n");
        }

        // Generate hybrid key pair
        System.out.println("5. Generating ML-KEM-768 + ECDH P-256 key pair...");
        PKCS11Structures.CK_MECHANISM mechanism = new PKCS11Structures.CK_MECHANISM();
        mechanism.mechanism = PKCS11Mechanisms.CKM_VENDOR_MLKEM768_ECDH_P256;
        mechanism.pParameter = null;
        mechanism.ulParameterLen = new NativeLong(0);

        System.out.println("   Mechanism value: 0x" + Long.toHexString(mechanism.mechanism.longValue()));

        CKAttributeBuilder publicBuilder = new CKAttributeBuilder(3, 3 * NativeLong.SIZE + 1);
        publicBuilder.setNativeLong(0, PKCS11Types.CKA_CLASS, PKCS11Types.CKO_PUBLIC_KEY.longValue());
        publicBuilder.setNativeLong(1, PKCS11Types.CKA_KEY_TYPE, 0x80000100L); // CKK_VENDOR_HYBRID_KEM
        publicBuilder.setBoolean(2, PKCS11Types.CKA_TOKEN, false);
        PKCS11Structures.CK_ATTRIBUTE[] publicTemplate = publicBuilder.build();

        CKAttributeBuilder privateBuilder = new CKAttributeBuilder(4, 3 * NativeLong.SIZE + 2);
        privateBuilder.setNativeLong(0, PKCS11Types.CKA_CLASS, PKCS11Types.CKO_PRIVATE_KEY.longValue());
        privateBuilder.setNativeLong(1, PKCS11Types.CKA_KEY_TYPE, 0x80000100L); // CKK_VENDOR_HYBRID_KEM
        privateBuilder.setBoolean(2, PKCS11Types.CKA_TOKEN, false);
        privateBuilder.setBoolean(3, PKCS11Types.CKA_PRIVATE, false);
        PKCS11Structures.CK_ATTRIBUTE[] privateTemplate = privateBuilder.build();

        NativeLongByReference phPublicKey = new NativeLongByReference();
        NativeLongByReference phPrivateKey = new NativeLongByReference();

        rv = pkcs11.C_GenerateKeyPair(
                hSession,
                mechanism,
                publicTemplate,
                new NativeLong(publicTemplate.length),
                privateTemplate,
                new NativeLong(privateTemplate.length),
                phPublicKey,
                phPrivateKey
        );

        if (!rv.equals(PKCS11Types.CKR_OK)) {
            System.err.println("   ✗ C_GenerateKeyPair failed: 0x" + Long.toHexString(rv.longValue()));
            pkcs11.C_Finalize(null);
            return;
        }

        NativeLong hPublicKey = phPublicKey.getValue();
        NativeLong hPrivateKey = phPrivateKey.getValue();
        System.out.println("   ✓ Keys generated");
        System.out.println("   Public key handle: " + hPublicKey.longValue());
        System.out.println("   Private key handle: " + hPrivateKey.longValue() + "\n");

        // Try to encapsulate
        System.out.println("6. Attempting encapsulation...");

        // Reset mechanism for encapsulation
        mechanism.mechanism = PKCS11Mechanisms.CKM_VENDOR_MLKEM768_ECDH_P256;
        mechanism.pParameter = null;
        mechanism.ulParameterLen = new NativeLong(0);

        System.out.println("   Encapsulation mechanism: 0x" + Long.toHexString(mechanism.mechanism.longValue()));

        // Template for shared secret
        CKAttributeBuilder secretBuilder = new CKAttributeBuilder(5, 3 * NativeLong.SIZE + 3);
        secretBuilder.setNativeLong(0, PKCS11Types.CKA_CLASS, PKCS11Types.CKO_SECRET_KEY.longValue());
        secretBuilder.setNativeLong(1, PKCS11Types.CKA_KEY_TYPE, PKCS11Types.CKK_GENERIC_SECRET.longValue());
        secretBuilder.setBoolean(2, PKCS11Types.CKA_TOKEN, false);
        secretBuilder.setBoolean(3, PKCS11Types.CKA_PRIVATE, false);
        secretBuilder.setBoolean(4, PKCS11Types.CKA_EXTRACTABLE, true);
        PKCS11Structures.CK_ATTRIBUTE[] secretTemplate = secretBuilder.build();

        byte[] ciphertext = new byte[65 + 1088]; // ECDH P-256 + ML-KEM-768
        NativeLongByReference pulCiphertextLen = new NativeLongByReference(new NativeLong(ciphertext.length));
        NativeLongByReference phSharedSecret = new NativeLongByReference();

        System.out.println("   Calling C_EncapsulateKey...");
        rv = pkcs11.C_EncapsulateKey(
                hSession,
                mechanism,
                hPublicKey,
                secretTemplate,
                new NativeLong(secretTemplate.length),
                ciphertext,
                pulCiphertextLen,
                phSharedSecret
        );

        System.out.println("   C_EncapsulateKey returned: 0x" + Long.toHexString(rv.longValue()));

        if (rv.equals(PKCS11Types.CKR_OK)) {
            System.out.println("   ✓ Encapsulation successful!");
            System.out.println("   Ciphertext length: " + pulCiphertextLen.getValue().longValue());
            System.out.println("   Shared secret handle: " + phSharedSecret.getValue().longValue());
        } else {
            System.err.println("   ✗ Encapsulation failed!");
            System.err.println("   Error code: 0x" + Long.toHexString(rv.longValue()));
            if (rv.longValue() == 0x150) {
                System.err.println("   Error: CKR_MECHANISM_INVALID");
            } else if (rv.longValue() == 0x70) {
                System.err.println("   Error: CKR_KEY_TYPE_INCONSISTENT");
            }
        }

        // Cleanup
        System.out.println("\n7. Cleaning up...");
        pkcs11.C_DestroyObject(hSession, hPublicKey);
        pkcs11.C_DestroyObject(hSession, hPrivateKey);
        pkcs11.C_Logout(hSession);
        pkcs11.C_CloseSession(hSession);
        pkcs11.C_Finalize(null);

        System.out.println("   ✓ Done\n");
    }
}
