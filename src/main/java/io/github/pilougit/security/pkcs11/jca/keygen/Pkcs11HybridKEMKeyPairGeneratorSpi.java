package io.github.pilougit.security.pkcs11.jca.keygen;

import com.sun.jna.NativeLong;
import io.github.pilougit.security.pkcs11.jca.util.helpers.HybridKemHelper;
import io.github.pilougit.security.pkcs11.jca.util.jna.PKCS11Helper;
import io.github.pilougit.security.pkcs11.jca.util.jna.PKCS11Library;
import io.github.pilougit.security.pkcs11.jca.util.jna.PKCS11Mechanisms;

import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

/**
 * KeyPairGenerator SPI implementation for Hybrid KEM algorithms.
 *
 * Supported hybrid KEM algorithms:
 * - MLKEM768-ECDH-P256: ML-KEM-768 + ECDH P-256
 * - MLKEM1024-ECDH-P384: ML-KEM-1024 + ECDH P-384
 * - MLKEM768-X25519: ML-KEM-768 + X25519
 *
 * These are vendor-specific mechanisms that combine post-quantum and classical
 * cryptography for enhanced security during the transition to post-quantum cryptography.
 */
public class Pkcs11HybridKEMKeyPairGeneratorSpi extends KeyPairGeneratorSpi {

    private final PKCS11Library pkcs11;
    private final NativeLong hSession;

    // Default to ML-KEM-768 + ECDH P-256
    private NativeLong mechanism = PKCS11Mechanisms.CKM_VENDOR_MLKEM768_ECDH_P256;
    private String algorithmName = "MLKEM768-ECDH-P256";

    /**
     * Algorithm name to mechanism mapping.
     */
    private static class AlgorithmInfo {
        final NativeLong mechanism;
        final String name;

        AlgorithmInfo(NativeLong mechanism, String name) {
            this.mechanism = mechanism;
            this.name = name;
        }
    }

    // Supported hybrid KEM algorithms
    private static final AlgorithmInfo ALG_MLKEM768_ECDH_P256 =
            new AlgorithmInfo(PKCS11Mechanisms.CKM_VENDOR_MLKEM768_ECDH_P256, "MLKEM768-ECDH-P256");

    private static final AlgorithmInfo ALG_MLKEM1024_ECDH_P384 =
            new AlgorithmInfo(PKCS11Mechanisms.CKM_VENDOR_MLKEM1024_ECDH_P384, "MLKEM1024-ECDH-P384");

    private static final AlgorithmInfo ALG_MLKEM768_X25519 =
            new AlgorithmInfo(PKCS11Mechanisms.CKM_VENDOR_MLKEM768_X25519, "MLKEM768-X25519");

    public Pkcs11HybridKEMKeyPairGeneratorSpi(PKCS11Library pkcs11, NativeLong hSession) {
        this.pkcs11 = pkcs11;
        this.hSession = hSession;
    }

    @Override
    public void initialize(int keysize, SecureRandom random) {
        // Map key sizes to hybrid algorithms
        // Using combined security level as key size hint
        switch (keysize) {
            case 768 -> {
                // ML-KEM-768 + P-256 (192-bit classical security)
                mechanism = ALG_MLKEM768_ECDH_P256.mechanism;
                algorithmName = ALG_MLKEM768_ECDH_P256.name;
            }
            case 1024 -> {
                // ML-KEM-1024 + P-384 (256-bit classical security)
                mechanism = ALG_MLKEM1024_ECDH_P384.mechanism;
                algorithmName = ALG_MLKEM1024_ECDH_P384.name;
            }
            case 256 -> {
                // ML-KEM-768 + X25519 (128-bit classical security)
                mechanism = ALG_MLKEM768_X25519.mechanism;
                algorithmName = ALG_MLKEM768_X25519.name;
            }
            default -> throw new InvalidParameterException(
                    "Unsupported key size: " + keysize +
                    ". Supported sizes: 256 (X25519), 768 (P-256), 1024 (P-384)");
        }
    }

    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException {

        if (params instanceof HybridKEMParameterSpec hybridParams) {
            String algName = hybridParams.getAlgorithmName().toUpperCase();

            AlgorithmInfo selectedAlg = switch (algName) {
                case "MLKEM768-ECDH-P256", "MLKEM768-P256" -> ALG_MLKEM768_ECDH_P256;
                case "MLKEM1024-ECDH-P384", "MLKEM1024-P384" -> ALG_MLKEM1024_ECDH_P384;
                case "MLKEM768-X25519" -> ALG_MLKEM768_X25519;
                default -> throw new InvalidAlgorithmParameterException(
                        "Unsupported hybrid KEM algorithm: " + algName);
            };

            mechanism = selectedAlg.mechanism;
            algorithmName = selectedAlg.name;
        } else {
            throw new InvalidAlgorithmParameterException(
                    "Expected HybridKEMParameterSpec, got: " +
                    (params != null ? params.getClass().getName() : "null"));
        }
    }

    @Override
    public KeyPair generateKeyPair() {
        try {
            // Generate hybrid KEM key pair using HybridKemHelper
            NativeLong[] keys = HybridKemHelper.generateHybridKEMKeyPair(
                    pkcs11,
                    hSession,
                    mechanism,
                    "hybrid-kem"  // Default label
            );

            NativeLong hPublicKey = keys[0];
            NativeLong hPrivateKey = keys[1];

            // Create key objects
            PublicKey pub = new Pkcs11HybridKEMPublicKey(pkcs11, hSession, hPublicKey, algorithmName);
            PrivateKey priv = new Pkcs11HybridKEMPrivateKey(pkcs11, hSession, hPrivateKey, algorithmName);

            return new KeyPair(pub, priv);

        } catch (PKCS11Helper.PKCS11Exception e) {
            throw new ProviderException(
                    "Hybrid KEM key pair generation failed for " + algorithmName + ": " + e.getMessage(), e);
        }
    }

    /**
     * Parameter specification for Hybrid KEM key pair generation.
     */
    public static class HybridKEMParameterSpec implements AlgorithmParameterSpec {
        private final String algorithmName;

        /**
         * Create a new parameter spec for hybrid KEM key generation.
         *
         * @param algorithmName Algorithm name (e.g., "MLKEM768-ECDH-P256")
         */
        public HybridKEMParameterSpec(String algorithmName) {
            this.algorithmName = algorithmName;
        }

        public String getAlgorithmName() {
            return algorithmName;
        }
    }
}
