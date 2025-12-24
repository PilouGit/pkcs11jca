package io.github.pilougit.security.pkcs11.jca.util.helpers;

import com.sun.jna.NativeLong;
import com.sun.jna.ptr.NativeLongByReference;
import io.github.pilougit.security.pkcs11.jca.util.jna.*;

import static io.github.pilougit.security.pkcs11.jca.util.jna.PKCS11Helper.*;

/**
 * Helper class for Elliptic Curve Cryptography (ECC) operations using PKCS#11.
 * Provides utility methods for generating EC key pairs with standard curves.
 */
public class ECCHelper {

    /**
     * Standard NIST P-256 curve OID in DER encoding.
     * OID: 1.2.840.10045.3.1.7
     */
    public static final byte[] P256_OID_DER = new byte[]{
            0x06, 0x08, 0x2A, (byte) 0x86, 0x48, (byte) 0xCE, 0x3D, 0x03, 0x01, 0x07
    };

    /**
     * Standard NIST P-384 curve OID in DER encoding.
     * OID: 1.3.132.0.34
     */
    public static final byte[] P384_OID_DER = new byte[]{
            0x06, 0x05, 0x2B, (byte) 0x81, 0x04, 0x00, 0x22
    };

    /**
     * Standard NIST P-521 curve OID in DER encoding.
     * OID: 1.3.132.0.35
     */
    public static final byte[] P521_OID_DER = new byte[]{
            0x06, 0x05, 0x2B, (byte) 0x81, 0x04, 0x00, 0x23
    };

    /**
     * Generate an EC key pair using PKCS#11.
     *
     * @param pkcs11     PKCS#11 library instance
     * @param session    Session handle
     * @param ecParams   EC parameters in DER-encoded OID format (e.g., P256_OID_DER)
     * @param canVerify  Whether the public key can be used for verification
     * @param canSign    Whether the private key can be used for signing
     * @param isPrivate  Whether the private key should be marked as private
     * @return Array with [publicKey, privateKey] handles
     * @throws PKCS11Helper.PKCS11Exception if operation fails
     */
    public static NativeLong[] generateECKeyPair(
            PKCS11Library pkcs11,
            NativeLong session,
            byte[] ecParams,
            boolean canVerify,
            boolean canSign,
            boolean isPrivate) throws PKCS11Helper.PKCS11Exception {

        // Create mechanism for EC key pair generation
        PKCS11Structures.CK_MECHANISM mechanism = new PKCS11Structures.CK_MECHANISM();
        mechanism.mechanism = PKCS11Mechanisms.CKM_EC_KEY_PAIR_GEN;
        mechanism.pParameter = null;
        mechanism.ulParameterLen = new NativeLong(0);
        mechanism.write();

        // Public key template
        PKCS11Structures.CK_ATTRIBUTE[] publicTemplate = new PKCS11Structures.CK_ATTRIBUTE[]{
                createNativeLongAttribute(PKCS11Types.CKA_KEY_TYPE, PKCS11Types.CKK_EC),
                createByteArrayAttribute(PKCS11Types.CKA_EC_PARAMS, ecParams),
                createBooleanAttribute(PKCS11Types.CKA_VERIFY, canVerify)
        };

        // Private key template
        PKCS11Structures.CK_ATTRIBUTE[] privateTemplate = new PKCS11Structures.CK_ATTRIBUTE[]{
                createBooleanAttribute(PKCS11Types.CKA_PRIVATE, isPrivate),
                createBooleanAttribute(PKCS11Types.CKA_SIGN, canSign)
        };

        NativeLongByReference hPublicKey = new NativeLongByReference();
        NativeLongByReference hPrivateKey = new NativeLongByReference();

        NativeLong rv = pkcs11.C_GenerateKeyPair(
                session,
                mechanism,
                publicTemplate, new NativeLong(publicTemplate.length),
                privateTemplate, new NativeLong(privateTemplate.length),
                hPublicKey,
                hPrivateKey
        );

        checkResult(rv, "Generate EC key pair");

        return new NativeLong[]{hPublicKey.getValue(), hPrivateKey.getValue()};
    }

    /**
     * Generate an EC key pair with default settings (verify enabled, sign enabled, private).
     *
     * @param pkcs11   PKCS#11 library instance
     * @param session  Session handle
     * @param ecParams EC parameters in DER-encoded OID format
     * @return Array with [publicKey, privateKey] handles
     * @throws PKCS11Helper.PKCS11Exception if operation fails
     */
    public static NativeLong[] generateECKeyPair(
            PKCS11Library pkcs11,
            NativeLong session,
            byte[] ecParams) throws PKCS11Helper.PKCS11Exception {

        return generateECKeyPair(pkcs11, session, ecParams, true, true, true);
    }

    /**
     * Get EC parameters (DER-encoded OID) for a given curve name.
     *
     * @param curveName Standard curve name (e.g., "secp256r1", "secp384r1", "secp521r1")
     * @return DER-encoded OID bytes
     * @throws IllegalArgumentException if curve name is not supported
     */
    public static byte[] getCurveParams(String curveName) {
        return switch (curveName) {
            case "secp256r1", "P-256", "prime256v1" -> P256_OID_DER;
            case "secp384r1", "P-384" -> P384_OID_DER;
            case "secp521r1", "P-521" -> P521_OID_DER;
            default -> throw new IllegalArgumentException("Unsupported curve: " + curveName);
        };
    }

    /**
     * Get EC parameters (DER-encoded OID) for a given key size.
     *
     * @param keySize Key size in bits (256, 384, or 521)
     * @return DER-encoded OID bytes
     * @throws IllegalArgumentException if key size is not supported
     */
    public static byte[] getCurveParamsBySize(int keySize) {
        return switch (keySize) {
            case 256 -> P256_OID_DER;
            case 384 -> P384_OID_DER;
            case 521 -> P521_OID_DER;
            default -> throw new IllegalArgumentException("Unsupported EC size: " + keySize);
        };
    }
}
