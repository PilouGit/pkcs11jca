package io.github.pilougit.security.pkcs11.jca.kem;

import com.sun.jna.Memory;
import com.sun.jna.NativeLong;
import com.sun.jna.ptr.NativeLongByReference;
import io.github.pilougit.security.pkcs11.jca.util.jna.CKAttributeBuilder;
import io.github.pilougit.security.pkcs11.jca.util.jna.PKCS11Library;
import io.github.pilougit.security.pkcs11.jca.util.jna.PKCS11Mechanisms;
import io.github.pilougit.security.pkcs11.jca.util.jna.PKCS11Structures;
import io.github.pilougit.security.pkcs11.jca.keygen.Pkcs11HybridKEMPrivateKey;
import io.github.pilougit.security.pkcs11.jca.keygen.Pkcs11HybridKEMPublicKey;

import javax.crypto.DecapsulateException;
import javax.crypto.KEM;
import javax.crypto.KEMSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import static io.github.pilougit.security.pkcs11.jca.util.jna.PKCS11Types.*;

/**
 * Hybrid KEM implementation using SoftHSMv2 vendor-specific mechanisms.
 *
 * This implementation uses native PKCS#11 hybrid KEM mechanisms that combine
 * classical and post-quantum algorithms directly in the HSM:
 * - CKM_VENDOR_MLKEM768_ECDH_P256: ML-KEM-768 + ECDH P-256
 * - CKM_VENDOR_MLKEM1024_ECDH_P384: ML-KEM-1024 + ECDH P-384
 * - CKM_VENDOR_MLKEM768_X25519: ML-KEM-768 + X25519
 *
 * The HSM handles key combination using SHA-256 internally, providing
 * defense-in-depth security.
 *
 * Supported algorithms:
 * - X25519-ML-KEM-768 (recommended for general use)
 * - ECDH-P256-ML-KEM-768
 * - ECDH-P384-ML-KEM-1024
 */
public class Pkcs11HybridKEMSpi implements KEMSpi {

    private final PKCS11Library pkcs11;
    private final NativeLong hSession;
    private final String algorithm;

    public Pkcs11HybridKEMSpi(PKCS11Library pkcs11, NativeLong hSession, String algorithm) {
        this.pkcs11 = pkcs11;
        this.hSession = hSession;
        this.algorithm = algorithm;
    }

    @Override
    public KEMSpi.EncapsulatorSpi engineNewEncapsulator(
            PublicKey publicKey,
            AlgorithmParameterSpec spec,
            SecureRandom secureRandom)
            throws InvalidAlgorithmParameterException, InvalidKeyException {

        if (!(publicKey instanceof Pkcs11HybridKEMPublicKey)) {
            throw new InvalidKeyException("Public key must be a Pkcs11HybridKEMPublicKey");
        }

        Pkcs11HybridKEMPublicKey pkcs11PublicKey = (Pkcs11HybridKEMPublicKey) publicKey;
        return new HybridEncapsulator(pkcs11PublicKey);
    }

    @Override
    public KEMSpi.DecapsulatorSpi engineNewDecapsulator(
            PrivateKey privateKey,
            AlgorithmParameterSpec spec)
            throws InvalidAlgorithmParameterException, InvalidKeyException {

        if (!(privateKey instanceof Pkcs11HybridKEMPrivateKey)) {
            throw new InvalidKeyException("Private key must be a Pkcs11HybridKEMPrivateKey");
        }

        Pkcs11HybridKEMPrivateKey pkcs11PrivateKey = (Pkcs11HybridKEMPrivateKey) privateKey;
        return new HybridDecapsulator(pkcs11PrivateKey);
    }

    /**
     * Hybrid encapsulator using vendor-specific mechanisms.
     */
    private class HybridEncapsulator implements KEMSpi.EncapsulatorSpi {
        private final Pkcs11HybridKEMPublicKey publicKey;
        private final NativeLong mechanismType;

        HybridEncapsulator(Pkcs11HybridKEMPublicKey publicKey) {
            this.publicKey = publicKey;
            this.mechanismType = getMechanismType(algorithm);
        }

        @Override
        public int engineSecretSize() {
            return getSharedSecretSize(algorithm);
        }

        @Override
        public int engineEncapsulationSize() {
            return getEncapsulationSize(algorithm);
        }

        @Override
        public KEM.Encapsulated engineEncapsulate(int from, int to, String algorithm) {
            try {
                // Prepare mechanism
                PKCS11Structures.CK_MECHANISM mechanism = new PKCS11Structures.CK_MECHANISM(mechanismType);

                // Template for the generated shared secret key - match C++ implementation
                int templateSize = 3 * NativeLong.SIZE + 2; // 3 NativeLongs + 2 booleans
                CKAttributeBuilder builder = new CKAttributeBuilder(5, templateSize);
                builder.setNativeLong(0, CKA_CLASS, CKO_SECRET_KEY.longValue());
                builder.setNativeLong(1, CKA_KEY_TYPE, CKK_GENERIC_SECRET.longValue());
                builder.setBoolean(2, CKA_TOKEN, false);
                builder.setBoolean(3, CKA_PRIVATE, false);
                builder.setBoolean(4, CKA_EXTRACTABLE, true);
                PKCS11Structures.CK_ATTRIBUTE[] template = builder.build();

                // Prepare output buffers
                int ciphertextLen = engineEncapsulationSize();
                byte[] ciphertext = new byte[ciphertextLen];
                NativeLongByReference pulCiphertextLen = new NativeLongByReference(new NativeLong(ciphertextLen));
                NativeLongByReference phSharedSecret = new NativeLongByReference();

                // Call C_EncapsulateKey with vendor hybrid mechanism
                NativeLong rv = pkcs11.C_EncapsulateKey(
                        hSession,
                        mechanism,
                        publicKey.getHandle(),
                        template,
                        new NativeLong(template.length),
                        ciphertext,
                        pulCiphertextLen,
                        phSharedSecret
                );

                if (!rv.equals(CKR_OK)) {
                    throw new RuntimeException("C_EncapsulateKey failed: 0x" + Long.toHexString(rv.longValue()));
                }

                // Extract the shared secret
                NativeLong hSharedSecret = phSharedSecret.getValue();
                byte[] sharedSecretBytes = extractSecretKey(hSharedSecret);

                // Cleanup: destroy the temporary key object
                pkcs11.C_DestroyObject(hSession, hSharedSecret);

                // Extract requested range
                byte[] extractedSecret = extractRange(sharedSecretBytes, from, to);
                String keyAlgorithm = (algorithm != null && !algorithm.isEmpty()) ? algorithm : "Generic";
                SecretKey finalSecret = new SecretKeySpec(extractedSecret, keyAlgorithm);

                // Trim ciphertext to actual size
                int actualCiphertextLen = pulCiphertextLen.getValue().intValue();
                byte[] actualCiphertext = new byte[actualCiphertextLen];
                System.arraycopy(ciphertext, 0, actualCiphertext, 0, actualCiphertextLen);

                return new KEM.Encapsulated(finalSecret, actualCiphertext, null);

            } catch (Exception e) {
                throw new RuntimeException("Hybrid encapsulation failed", e);
            }
        }
    }

    /**
     * Hybrid decapsulator using vendor-specific mechanisms.
     */
    private class HybridDecapsulator implements KEMSpi.DecapsulatorSpi {
        private final Pkcs11HybridKEMPrivateKey privateKey;
        private final NativeLong mechanismType;

        HybridDecapsulator(Pkcs11HybridKEMPrivateKey privateKey) {
            this.privateKey = privateKey;
            this.mechanismType = getMechanismType(algorithm);
        }

        @Override
        public int engineSecretSize() {
            return getSharedSecretSize(algorithm);
        }

        @Override
        public int engineEncapsulationSize() {
            return getEncapsulationSize(algorithm);
        }

        @Override
        public SecretKey engineDecapsulate(byte[] encapsulation, int from, int to, String algorithm)
                throws DecapsulateException {
            try {
                // Prepare mechanism
                PKCS11Structures.CK_MECHANISM mechanism = new PKCS11Structures.CK_MECHANISM(mechanismType);

                // Template for the recovered shared secret key - match C++ implementation
                int templateSize = 3 * NativeLong.SIZE + 2; // 3 NativeLongs + 2 booleans
                CKAttributeBuilder builder = new CKAttributeBuilder(5, templateSize);
                builder.setNativeLong(0, CKA_CLASS, CKO_SECRET_KEY.longValue());
                builder.setNativeLong(1, CKA_KEY_TYPE, CKK_GENERIC_SECRET.longValue());
                builder.setBoolean(2, CKA_TOKEN, false);
                builder.setBoolean(3, CKA_PRIVATE, false);
                builder.setBoolean(4, CKA_EXTRACTABLE, true);
                PKCS11Structures.CK_ATTRIBUTE[] template = builder.build();

                NativeLongByReference phSharedSecret = new NativeLongByReference();

                // Call C_DecapsulateKey with vendor hybrid mechanism
                NativeLong rv = pkcs11.C_DecapsulateKey(
                        hSession,
                        mechanism,
                        privateKey.getHandle(),
                        template,
                        new NativeLong(template.length),
                        encapsulation,
                        new NativeLong(encapsulation.length),
                        phSharedSecret
                );

                if (!rv.equals(CKR_OK)) {
                    throw new DecapsulateException("C_DecapsulateKey failed: 0x" + Long.toHexString(rv.longValue()));
                }

                // Extract the shared secret
                NativeLong hSharedSecret = phSharedSecret.getValue();
                byte[] sharedSecretBytes = extractSecretKey(hSharedSecret);

                // Cleanup: destroy the temporary key object
                pkcs11.C_DestroyObject(hSession, hSharedSecret);

                // Extract requested range
                byte[] extractedSecret = extractRange(sharedSecretBytes, from, to);
                String keyAlgorithm = (algorithm != null && !algorithm.isEmpty()) ? algorithm : "Generic";

                return new SecretKeySpec(extractedSecret, keyAlgorithm);

            } catch (DecapsulateException e) {
                throw e;
            } catch (Exception e) {
                throw new DecapsulateException("Hybrid decapsulation failed", e);
            }
        }
    }

    /**
     * Extract the secret key value from a PKCS#11 key object.
     */
    private byte[] extractSecretKey(NativeLong hKey) {
        // Get the key value
        PKCS11Structures.CK_ATTRIBUTE[] template = new PKCS11Structures.CK_ATTRIBUTE[1];
        template[0] = new PKCS11Structures.CK_ATTRIBUTE();
        template[0].type = CKA_VALUE;
        template[0].pValue = null;
        template[0].ulValueLen = new NativeLong(0);

        // First call to get the size
        NativeLong rv = pkcs11.C_GetAttributeValue(hSession, hKey, template, new NativeLong(1));
        if (!rv.equals(CKR_OK)) {
            throw new RuntimeException("Failed to get key size: 0x" + Long.toHexString(rv.longValue()));
        }

        // Allocate buffer and get the value
        int valueLen = template[0].ulValueLen.intValue();
        Memory valueMemory = new Memory(valueLen);
        template[0].pValue = valueMemory;

        rv = pkcs11.C_GetAttributeValue(hSession, hKey, template, new NativeLong(1));
        if (!rv.equals(CKR_OK)) {
            throw new RuntimeException("Failed to get key value: 0x" + Long.toHexString(rv.longValue()));
        }

        return valueMemory.getByteArray(0, valueLen);
    }

    /**
     * Extract a range from a byte array.
     */
    private byte[] extractRange(byte[] data, int from, int to) {
        if (from == 0 && to == data.length) {
            return data;
        }
        int length = to - from;
        byte[] result = new byte[length];
        System.arraycopy(data, from, result, 0, length);
        return result;
    }

    /**
     * Get the PKCS#11 vendor mechanism type for the hybrid algorithm.
     */
    private NativeLong getMechanismType(String algorithm) {
        if (algorithm == null) {
            throw new IllegalArgumentException("Algorithm cannot be null");
        }

        return switch (algorithm.toUpperCase()) {
            case "X25519-ML-KEM-768", "X25519-MLKEM-768" ->
                PKCS11Mechanisms.CKM_VENDOR_MLKEM768_X25519;
            case "ECDH-P256-ML-KEM-768", "ECDH-P256-MLKEM-768" ->
                PKCS11Mechanisms.CKM_VENDOR_MLKEM768_ECDH_P256;
            case "ECDH-P384-ML-KEM-1024", "ECDH-P384-MLKEM-1024" ->
                PKCS11Mechanisms.CKM_VENDOR_MLKEM1024_ECDH_P384;
            default -> throw new IllegalArgumentException("Unsupported hybrid KEM algorithm: " + algorithm);
        };
    }

    /**
     * Get the shared secret size for the hybrid algorithm.
     * All vendor hybrid KEMs use SHA-256 for combining, resulting in 32-byte secrets.
     */
    private int getSharedSecretSize(String algorithm) {
        return switch (algorithm.toUpperCase()) {
            case "X25519-ML-KEM-768", "X25519-MLKEM-768",
                 "ECDH-P256-ML-KEM-768", "ECDH-P256-MLKEM-768",
                 "ECDH-P384-ML-KEM-1024", "ECDH-P384-MLKEM-1024" -> 32; // SHA-256 output
            default -> throw new IllegalArgumentException("Unknown hybrid algorithm: " + algorithm);
        };
    }

    /**
     * Get the encapsulation (combined ciphertext) size for the hybrid algorithm.
     * This is the sum of classical and PQ ciphertext sizes in raw format.
     * Classical keys use uncompressed point format (0x04 + X + Y) for ECDH
     * and raw 32-byte format for X25519.
     */
    private int getEncapsulationSize(String algorithm) {
        return switch (algorithm.toUpperCase()) {
            case "X25519-ML-KEM-768", "X25519-MLKEM-768" ->
                32 + 1088;  // X25519 raw (32) + ML-KEM-768 (1088) = 1120
            case "ECDH-P256-ML-KEM-768", "ECDH-P256-MLKEM-768" ->
                65 + 1088;  // ECDH P-256 uncompressed (65) + ML-KEM-768 (1088) = 1153
            case "ECDH-P384-ML-KEM-1024", "ECDH-P384-MLKEM-1024" ->
                97 + 1568;  // ECDH P-384 uncompressed (97) + ML-KEM-1024 (1568) = 1665
            default -> throw new IllegalArgumentException("Unknown hybrid algorithm: " + algorithm);
        };
    }
}
