package io.github.pilougit.security.pkcs11.jca.util.helpers;

import com.sun.jna.NativeLong;
import com.sun.jna.ptr.NativeLongByReference;
import io.github.pilougit.security.pkcs11.jca.util.jna.*;

import static io.github.pilougit.security.pkcs11.jca.util.jna.PKCS11Helper.*;

public class HybridKemHelper {
    /**
     * Example: Generate a hybrid KEM key pair.
     *
     * @param pkcs11 PKCS#11 library instance
     * @param session Session handle
     * @param mechanism Hybrid KEM mechanism
     * @param label Key label
     * @return Array with [publicKey, privateKey] handles
     * @throws PKCS11Helper.PKCS11Exception if operation fails
     */
    public static NativeLong[] generateHybridKEMKeyPair(
            PKCS11Library pkcs11,
            NativeLong session,
            NativeLong mechanism,
            String label) throws PKCS11Helper.PKCS11Exception {

        // Create mechanism
        PKCS11Structures.CK_MECHANISM mech = new PKCS11Structures.CK_MECHANISM(mechanism);

        // Public key template - match C++ implementation
        byte[] pubLabel = (label + "-pub").getBytes();
        int totalPubBytes = 2 * NativeLong.SIZE + 4 + pubLabel.length; // 2 NativeLongs + 4 booleans + label
        CKAttributeBuilder pubBuilder = new CKAttributeBuilder(7, totalPubBytes);
        pubBuilder.setNativeLong(0, PKCS11Types.CKA_CLASS, PKCS11Types.CKO_PUBLIC_KEY.longValue());
        pubBuilder.setNativeLong(1, PKCS11Types.CKA_KEY_TYPE, PKCS11Types.CKK_VENDOR_HYBRID_KEM.longValue());
        pubBuilder.setBoolean(2, PKCS11Types.CKA_TOKEN, true);
        pubBuilder.setBoolean(3, PKCS11Types.CKA_PRIVATE, false);
        pubBuilder.setBoolean(4, PKCS11Types.CKA_ENCRYPT, true);
        pubBuilder.setBoolean(5, PKCS11Types.CKA_VERIFY, false);
        pubBuilder.setBoolean(6, PKCS11Types.CKA_WRAP, false);
        PKCS11Structures.CK_ATTRIBUTE[] publicTemplate = pubBuilder.build();

        // Private key template - match C++ implementation
        byte[] privLabel = (label + "-priv").getBytes();
        int totalPrivBytes = 2 * NativeLong.SIZE + 5 + privLabel.length; // 2 NativeLongs + 5 booleans + label
        CKAttributeBuilder privBuilder = new CKAttributeBuilder(9, totalPrivBytes);
        privBuilder.setNativeLong(0, PKCS11Types.CKA_CLASS, PKCS11Types.CKO_PRIVATE_KEY.longValue());
        privBuilder.setNativeLong(1, PKCS11Types.CKA_KEY_TYPE, PKCS11Types.CKK_VENDOR_HYBRID_KEM.longValue());
        privBuilder.setBoolean(2, PKCS11Types.CKA_TOKEN, true);
        privBuilder.setBoolean(3, PKCS11Types.CKA_PRIVATE, false);
        privBuilder.setBoolean(4, PKCS11Types.CKA_SENSITIVE, true);
        privBuilder.setBoolean(5, PKCS11Types.CKA_DECRYPT, true);
        privBuilder.setBoolean(6, PKCS11Types.CKA_SIGN, false);
        privBuilder.setBoolean(7, PKCS11Types.CKA_UNWRAP, false);
        privBuilder.setBoolean(8, PKCS11Types.CKA_EXTRACTABLE, false);
        PKCS11Structures.CK_ATTRIBUTE[] privateTemplate = privBuilder.build();

        NativeLongByReference publicKey = new NativeLongByReference();
        NativeLongByReference privateKey = new NativeLongByReference();

        NativeLong rv = pkcs11.C_GenerateKeyPair(
                session,
                mech,
                publicTemplate, new NativeLong(publicTemplate.length),
                privateTemplate, new NativeLong(privateTemplate.length),
                publicKey,
                privateKey
        );

        checkResult(rv, "Generate hybrid KEM key pair");

        return new NativeLong[]{publicKey.getValue(), privateKey.getValue()};
    }

    /**
     * Example: Generate a hybrid signature key pair.
     *
     * @param pkcs11 PKCS#11 library instance
     * @param session Session handle
     * @param mechanism Hybrid signature mechanism
     * @param label Key label
     * @return Array with [publicKey, privateKey] handles
     * @throws PKCS11Helper.PKCS11Exception if operation fails
     */
    public static NativeLong[] generateHybridSignatureKeyPair(
            PKCS11Library pkcs11,
            NativeLong session,
            NativeLong mechanism,
            String label) throws PKCS11Helper.PKCS11Exception {

        // Create mechanism
        PKCS11Structures.CK_MECHANISM mech = new PKCS11Structures.CK_MECHANISM(mechanism);

        // Public key template - use CKAttributeBuilder for proper memory layout
        byte[] pubLabel = (label + "-pub").getBytes();
        int totalPubBytes = 1 + 1 + pubLabel.length; // 2 booleans + label
        CKAttributeBuilder pubBuilder = new CKAttributeBuilder(3, totalPubBytes);
        pubBuilder.setBoolean(0, PKCS11Types.CKA_TOKEN, true);
        pubBuilder.setBoolean(1, PKCS11Types.CKA_VERIFY, true);
        pubBuilder.setByteArray(2, PKCS11Types.CKA_LABEL, pubLabel);
        PKCS11Structures.CK_ATTRIBUTE[] publicTemplate = pubBuilder.build();

        // Private key template - use CKAttributeBuilder for proper memory layout
        byte[] privLabel = (label + "-priv").getBytes();
        int totalPrivBytes = 1 + 1 + 1 + 1 + privLabel.length; // 4 booleans + label
        CKAttributeBuilder privBuilder = new CKAttributeBuilder(5, totalPrivBytes);
        privBuilder.setBoolean(0, PKCS11Types.CKA_TOKEN, true);
        privBuilder.setBoolean(1, PKCS11Types.CKA_SIGN, true);
        privBuilder.setBoolean(2, PKCS11Types.CKA_SENSITIVE, true);
        privBuilder.setBoolean(3, PKCS11Types.CKA_EXTRACTABLE, false);
        privBuilder.setByteArray(4, PKCS11Types.CKA_LABEL, privLabel);
        PKCS11Structures.CK_ATTRIBUTE[] privateTemplate = privBuilder.build();

        NativeLongByReference publicKey = new NativeLongByReference();
        NativeLongByReference privateKey = new NativeLongByReference();

        NativeLong rv = pkcs11.C_GenerateKeyPair(
                session,
                mech,
                publicTemplate, new NativeLong(publicTemplate.length),
                privateTemplate, new NativeLong(privateTemplate.length),
                publicKey,
                privateKey
        );

        checkResult(rv, "Generate hybrid signature key pair");

        return new NativeLong[]{publicKey.getValue(), privateKey.getValue()};
    }

    /**
     * Generate an ML-KEM key pair using variant-specific mechanisms.
     *
     * IMPORTANT: Both public and private key templates must include CKA_VALUE_LEN
     * to specify the ML-KEM parameter set (512, 768, or 1024).
     *
     * @param pkcs11 PKCS#11 library instance
     * @param session Session handle
     * @param mechanism ML-KEM mechanism (CKM_MLKEM_512, CKM_MLKEM_768, or CKM_MLKEM_1024)
     * @param parameterSet Parameter set value (512, 768, or 1024)
     * @param label Key label
     * @param onToken Whether to store keys on token
     * @return Array with [publicKey, privateKey] handles
     * @throws PKCS11Helper.PKCS11Exception if operation fails
     */
    public static NativeLong[] generateMLKEMKeyPair(
            PKCS11Library pkcs11,
            NativeLong session,
            NativeLong mechanism,
            long parameterSet,
            String label,
            boolean onToken) throws PKCS11Helper.PKCS11Exception {

        // Create mechanism - use CKM_ML_KEM_KEY_PAIR_GEN for key generation
        PKCS11Structures.CK_MECHANISM mech = new PKCS11Structures.CK_MECHANISM(
                PKCS11Mechanisms.CKM_ML_KEM_KEY_PAIR_GEN
        );

        int pubLen = 4;
        byte[] pubLabel = (label + "-pub").getBytes();
        int totalPubBytes = 1 + 1 + pubLabel.length + NativeLong.SIZE;

        CKAttributeBuilder pubBuilder = new CKAttributeBuilder(pubLen, totalPubBytes);
        pubBuilder.setBoolean(0, PKCS11Types.CKA_TOKEN, onToken);
        pubBuilder.setBoolean(1, PKCS11Types.CKA_ENCRYPT, true);
        pubBuilder.setByteArray(2, PKCS11Types.CKA_LABEL, pubLabel);
        pubBuilder.setNativeLong(3, PKCS11Types.CKA_VALUE_LEN, parameterSet);
        PKCS11Structures.CK_ATTRIBUTE[] publicTemplate = pubBuilder.build();

// Private key template
        int privLen = 6;
        byte[] privLabel = (label + "-priv").getBytes();
        int totalPrivBytes = 1 + 1 + 1 + 1 + privLabel.length + NativeLong.SIZE;

        CKAttributeBuilder privBuilder = new CKAttributeBuilder(privLen, totalPrivBytes);
        privBuilder.setBoolean(0, PKCS11Types.CKA_TOKEN, onToken);
        privBuilder.setBoolean(1, PKCS11Types.CKA_DECRYPT, true);
        privBuilder.setBoolean(2, PKCS11Types.CKA_SENSITIVE, true);
        privBuilder.setBoolean(3, PKCS11Types.CKA_EXTRACTABLE, false);
        privBuilder.setByteArray(4, PKCS11Types.CKA_LABEL, privLabel);
        privBuilder.setNativeLong(5, PKCS11Types.CKA_VALUE_LEN, parameterSet);
        PKCS11Structures.CK_ATTRIBUTE[] privateTemplate = privBuilder.build();
        NativeLongByReference publicKey = new NativeLongByReference();
        NativeLongByReference privateKey = new NativeLongByReference();

        NativeLong rv = pkcs11.C_GenerateKeyPair(
                session,
                mech,
                publicTemplate, new NativeLong(publicTemplate.length),
                privateTemplate, new NativeLong(privateTemplate.length),
                publicKey,
                privateKey
        );

        checkResult(rv, "Generate ML-KEM key pair");

        return new NativeLong[]{publicKey.getValue(), privateKey.getValue()};
    }
}
