package io.github.pilougit.security.pkcs11.jca.kem;

import com.sun.jna.Memory;
import com.sun.jna.NativeLong;
import com.sun.jna.ptr.NativeLongByReference;
import io.github.pilougit.security.pkcs11.jca.PKCS11Key;
import io.github.pilougit.security.pkcs11.jca.util.jna.PKCS11Library;
import io.github.pilougit.security.pkcs11.jca.util.jna.PKCS11Mechanisms;
import io.github.pilougit.security.pkcs11.jca.util.jna.PKCS11Structures;

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
 * PKCS#11 implementation of KEMSpi (Key Encapsulation Mechanism).
 * Uses C_EncapsulateKey and C_DecapsulateKey PKCS#11 v3.2 functions.
 *
 * Supports post-quantum KEM algorithms like ML-KEM (Kyber).
 */
public class PKCS11KEMSpi implements KEMSpi {

    private final PKCS11Library pkcs11;
    private final NativeLong hSession;
    private final String algorithm;

    public PKCS11KEMSpi(PKCS11Library pkcs11, NativeLong hSession, String algorithm) {
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

        if (!(publicKey instanceof PKCS11Key)) {
            throw new InvalidKeyException("Public key must be a PKCS11Key");
        }

        PKCS11Key pkcs11PublicKey = (PKCS11Key) publicKey;
        return new PKCS11Encapsulator(pkcs11PublicKey);
    }

    @Override
    public KEMSpi.DecapsulatorSpi engineNewDecapsulator(
            PrivateKey privateKey,
            AlgorithmParameterSpec spec)
            throws InvalidAlgorithmParameterException, InvalidKeyException {

        if (!(privateKey instanceof PKCS11Key)) {
            throw new InvalidKeyException("Private key must be a PKCS11Key");
        }

        PKCS11Key pkcs11PrivateKey = (PKCS11Key) privateKey;
        return new PKCS11Decapsulator(pkcs11PrivateKey);
    }

    /**
     * Encapsulator implementation using C_EncapsulateKey.
     */
    private class PKCS11Encapsulator implements KEMSpi.EncapsulatorSpi {
        private final PKCS11Key publicKey;
        private final NativeLong mechanismType;

        PKCS11Encapsulator(PKCS11Key publicKey) {
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
                PKCS11Structures.CK_MECHANISM mechanism = new PKCS11Structures.CK_MECHANISM();
                mechanism.mechanism = mechanismType;
                mechanism.pParameter = null;
                mechanism.ulParameterLen = new NativeLong(0);

                // Template for the generated shared secret key
                PKCS11Structures.CK_ATTRIBUTE[] template = new PKCS11Structures.CK_ATTRIBUTE[3];

                // CKA_CLASS = CKO_SECRET_KEY
                template[0] = new PKCS11Structures.CK_ATTRIBUTE();
                template[0].type = CKA_CLASS;
                Memory classMemory = new Memory(NativeLong.SIZE);
                classMemory.setLong(0, CKO_SECRET_KEY.longValue());
                template[0].pValue = classMemory;
                template[0].ulValueLen = new NativeLong(NativeLong.SIZE);

                // CKA_KEY_TYPE = CKK_GENERIC_SECRET
                template[1] = new PKCS11Structures.CK_ATTRIBUTE();
                template[1].type = CKA_KEY_TYPE;
                Memory keyTypeMemory = new Memory(NativeLong.SIZE);
                keyTypeMemory.setLong(0, CKK_GENERIC_SECRET.longValue());
                template[1].pValue = keyTypeMemory;
                template[1].ulValueLen = new NativeLong(NativeLong.SIZE);

                // CKA_EXTRACTABLE = TRUE
                template[2] = new PKCS11Structures.CK_ATTRIBUTE();
                template[2].type = CKA_EXTRACTABLE;
                Memory extractableMemory = new Memory(1);
                extractableMemory.setByte(0, CK_TRUE);
                template[2].pValue = extractableMemory;
                template[2].ulValueLen = new NativeLong(1);

                // Prepare output buffers
                int ciphertextLen = engineEncapsulationSize();
                byte[] ciphertext = new byte[ciphertextLen];
                NativeLongByReference pulCiphertextLen = new NativeLongByReference(new NativeLong(ciphertextLen));
                NativeLongByReference phSharedSecret = new NativeLongByReference();

                // Call C_EncapsulateKey
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
                throw new RuntimeException("Encapsulation failed", e);
            }
        }
    }

    /**
     * Decapsulator implementation using C_DecapsulateKey.
     */
    private class PKCS11Decapsulator implements KEMSpi.DecapsulatorSpi {
        private final PKCS11Key privateKey;
        private final NativeLong mechanismType;

        PKCS11Decapsulator(PKCS11Key privateKey) {
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
                PKCS11Structures.CK_MECHANISM mechanism = new PKCS11Structures.CK_MECHANISM();
                mechanism.mechanism = mechanismType;
                mechanism.pParameter = null;
                mechanism.ulParameterLen = new NativeLong(0);

                // Template for the recovered shared secret key
                PKCS11Structures.CK_ATTRIBUTE[] template = new PKCS11Structures.CK_ATTRIBUTE[3];

                // CKA_CLASS = CKO_SECRET_KEY
                template[0] = new PKCS11Structures.CK_ATTRIBUTE();
                template[0].type = CKA_CLASS;
                Memory classMemory = new Memory(NativeLong.SIZE);
                classMemory.setLong(0, CKO_SECRET_KEY.longValue());
                template[0].pValue = classMemory;
                template[0].ulValueLen = new NativeLong(NativeLong.SIZE);

                // CKA_KEY_TYPE = CKK_GENERIC_SECRET
                template[1] = new PKCS11Structures.CK_ATTRIBUTE();
                template[1].type = CKA_KEY_TYPE;
                Memory keyTypeMemory = new Memory(NativeLong.SIZE);
                keyTypeMemory.setLong(0, CKK_GENERIC_SECRET.longValue());
                template[1].pValue = keyTypeMemory;
                template[1].ulValueLen = new NativeLong(NativeLong.SIZE);

                // CKA_EXTRACTABLE = TRUE
                template[2] = new PKCS11Structures.CK_ATTRIBUTE();
                template[2].type = CKA_EXTRACTABLE;
                Memory extractableMemory = new Memory(1);
                extractableMemory.setByte(0, CK_TRUE);
                template[2].pValue = extractableMemory;
                template[2].ulValueLen = new NativeLong(1);

                NativeLongByReference phSharedSecret = new NativeLongByReference();

                // Call C_DecapsulateKey
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
                throw new DecapsulateException("Decapsulation failed", e);
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
     * Get the PKCS#11 mechanism type for the algorithm.
     */
    private NativeLong getMechanismType(String algorithm) {
        if (algorithm == null) {
            throw new IllegalArgumentException("Algorithm cannot be null");
        }

        return switch (algorithm.toUpperCase()) {
            case "ML-KEM-512", "KYBER512" -> PKCS11Mechanisms.CKM_MLKEM_512;
            case "ML-KEM-768", "KYBER768" -> PKCS11Mechanisms.CKM_MLKEM_768;
            case "ML-KEM-1024", "KYBER1024" -> PKCS11Mechanisms.CKM_MLKEM_1024;
            default -> throw new IllegalArgumentException("Unsupported KEM algorithm: " + algorithm);
        };
    }

    /**
     * Get the shared secret size for the algorithm.
     */
    private int getSharedSecretSize(String algorithm) {
        // All ML-KEM variants use 32-byte shared secrets
        return switch (algorithm.toUpperCase()) {
            case "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",
                 "KYBER512", "KYBER768", "KYBER1024" -> 32;
            default -> throw new IllegalArgumentException("Unknown algorithm: " + algorithm);
        };
    }

    /**
     * Get the encapsulation (ciphertext) size for the algorithm.
     */
    private int getEncapsulationSize(String algorithm) {
        return switch (algorithm.toUpperCase()) {
            case "ML-KEM-512", "KYBER512" -> 768;   // ML-KEM-512 ciphertext
            case "ML-KEM-768", "KYBER768" -> 1088;  // ML-KEM-768 ciphertext
            case "ML-KEM-1024", "KYBER1024" -> 1568; // ML-KEM-1024 ciphertext
            default -> throw new IllegalArgumentException("Unknown algorithm: " + algorithm);
        };
    }
}
