package io.github.pilougit.security.pkcs11.jca.util.jna;

import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import java.util.Arrays;
import java.util.List;

/**
 * SoftHSM vendor-specific definitions for PKCS#11.
 * This includes extensions for Post-Quantum Cryptography (PQC) hybrid schemes.
 *
 * Based on SoftHSMv2 vendor_defines.h
 */
public class VendorDefines {

    // ========================================================================
    // Vendor-specific mechanism types for PQC Hybrid schemes
    // ========================================================================

    /**
     * Hybrid KEM mechanisms (0x80000001 - 0x800000FF)
     */

    /** ML-KEM-768 + ECDH P-256 hybrid KEM */
    public static final NativeLong CKM_VENDOR_MLKEM768_ECDH_P256 = new NativeLong(0x80000001L);

    /** ML-KEM-1024 + ECDH P-384 hybrid KEM */
    public static final NativeLong CKM_VENDOR_MLKEM1024_ECDH_P384 = new NativeLong(0x80000002L);

    /** ML-KEM-768 + X25519 hybrid KEM */
    public static final NativeLong CKM_VENDOR_MLKEM768_X25519 = new NativeLong(0x80000003L);

    /**
     * Hybrid Signature mechanisms (0x80000010 - 0x8000001F)
     */

    /** ML-DSA-65 + ECDSA P-256 hybrid signature */
    public static final NativeLong CKM_VENDOR_MLDSA65_ECDSA_P256 = new NativeLong(0x80000010L);

    /** ML-DSA-87 + ECDSA P-384 hybrid signature */
    public static final NativeLong CKM_VENDOR_MLDSA87_ECDSA_P384 = new NativeLong(0x80000011L);

    // ========================================================================
    // Vendor-specific key types for PQC Hybrid schemes
    // ========================================================================

    /** Hybrid KEM key type */
    public static final NativeLong CKK_VENDOR_HYBRID_KEM = new NativeLong(0x80000100L);

    /** Hybrid Signature key type */
    public static final NativeLong CKK_VENDOR_HYBRID_SIGNATURE = new NativeLong(0x80000101L);

    // ========================================================================
    // Vendor-specific attributes for Hybrid keys
    // ========================================================================

    /** PQC public key component attribute */
    public static final NativeLong CKA_VENDOR_PQC_PUBLIC_KEY = new NativeLong(0x80000200L);

    /** PQC private key component attribute */
    public static final NativeLong CKA_VENDOR_PQC_PRIVATE_KEY = new NativeLong(0x80000201L);

    /** Classical public key component attribute */
    public static final NativeLong CKA_VENDOR_CLASSICAL_PUBLIC_KEY = new NativeLong(0x80000202L);

    /** Classical private key component attribute */
    public static final NativeLong CKA_VENDOR_CLASSICAL_PRIVATE_KEY = new NativeLong(0x80000203L);

    /** Hybrid mechanism identifier attribute */
    public static final NativeLong CKA_VENDOR_HYBRID_MECHANISM = new NativeLong(0x80000204L);

    // ========================================================================
    // Hybrid KEM combiner function identifiers
    // ========================================================================

    /**
     * Hybrid combiner types for KEM key derivation.
     */
    public static final int HYBRID_COMBINER_CONCAT = 0;   /* Simple concatenation */
    public static final int HYBRID_COMBINER_SHA256 = 1;   /* SHA-256 based KDF */
    public static final int HYBRID_COMBINER_SHA512 = 2;   /* SHA-512 based KDF */
    public static final int HYBRID_COMBINER_KMAC128 = 3;  /* KMAC128 based KDF */
    public static final int HYBRID_COMBINER_KMAC256 = 4;  /* KMAC256 based KDF */

    // ========================================================================
    // Hybrid mechanism info structure
    // ========================================================================

    /**
     * CK_HYBRID_MECHANISM_INFO structure
     * Contains information about a hybrid mechanism's PQC and classical components.
     */
    public static class CK_HYBRID_MECHANISM_INFO extends Structure {
        /** PQC mechanism (e.g., CKM_ML_KEM) */
        public NativeLong pqcMechanism;

        /** Classical mechanism (e.g., CKM_ECDH) */
        public NativeLong classicalMechanism;

        /** KDF combiner function type */
        public int combinerType;

        /** Combined secret length in bytes */
        public NativeLong outputLength;

        public CK_HYBRID_MECHANISM_INFO() {
            super();
        }

        public CK_HYBRID_MECHANISM_INFO(NativeLong pqcMechanism, NativeLong classicalMechanism,
                                        int combinerType, NativeLong outputLength) {
            this.pqcMechanism = pqcMechanism;
            this.classicalMechanism = classicalMechanism;
            this.combinerType = combinerType;
            this.outputLength = outputLength;
        }

        @Override
        protected List<String> getFieldOrder() {
            return Arrays.asList("pqcMechanism", "classicalMechanism", "combinerType", "outputLength");
        }
    }

    // ========================================================================
    // Helper methods for hybrid mechanisms
    // ========================================================================

    /**
     * Check if a mechanism is a hybrid KEM mechanism.
     *
     * @param mechanism The mechanism to check
     * @return true if the mechanism is a hybrid KEM mechanism
     */
    public static boolean isHybridKEMMechanism(NativeLong mechanism) {
        long mech = mechanism.longValue();
        return mech == CKM_VENDOR_MLKEM768_ECDH_P256.longValue() ||
               mech == CKM_VENDOR_MLKEM1024_ECDH_P384.longValue() ||
               mech == CKM_VENDOR_MLKEM768_X25519.longValue();
    }

    /**
     * Check if a mechanism is a hybrid signature mechanism.
     *
     * @param mechanism The mechanism to check
     * @return true if the mechanism is a hybrid signature mechanism
     */
    public static boolean isHybridSignatureMechanism(NativeLong mechanism) {
        long mech = mechanism.longValue();
        return mech == CKM_VENDOR_MLDSA65_ECDSA_P256.longValue() ||
               mech == CKM_VENDOR_MLDSA87_ECDSA_P384.longValue();
    }

    /**
     * Check if a mechanism is any hybrid mechanism (KEM or signature).
     *
     * @param mechanism The mechanism to check
     * @return true if the mechanism is a hybrid mechanism
     */
    public static boolean isHybridMechanism(NativeLong mechanism) {
        return isHybridKEMMechanism(mechanism) || isHybridSignatureMechanism(mechanism);
    }

    /**
     * Get a human-readable name for a hybrid mechanism.
     *
     * @param mechanism The mechanism
     * @return The mechanism name
     */
    public static String getHybridMechanismName(NativeLong mechanism) {
        long mech = mechanism.longValue();

        // Hybrid KEM mechanisms
        if (mech == CKM_VENDOR_MLKEM768_ECDH_P256.longValue()) {
            return "ML-KEM-768 + ECDH P-256";
        } else if (mech == CKM_VENDOR_MLKEM1024_ECDH_P384.longValue()) {
            return "ML-KEM-1024 + ECDH P-384";
        } else if (mech == CKM_VENDOR_MLKEM768_X25519.longValue()) {
            return "ML-KEM-768 + X25519";
        }

        // Hybrid Signature mechanisms
        else if (mech == CKM_VENDOR_MLDSA65_ECDSA_P256.longValue()) {
            return "ML-DSA-65 + ECDSA P-256";
        } else if (mech == CKM_VENDOR_MLDSA87_ECDSA_P384.longValue()) {
            return "ML-DSA-87 + ECDSA P-384";
        }

        return "Unknown hybrid mechanism (0x" + Long.toHexString(mech) + ")";
    }

    /**
     * Get a human-readable name for a combiner type.
     *
     * @param combinerType The combiner type
     * @return The combiner name
     */
    public static String getCombinerTypeName(int combinerType) {
        switch (combinerType) {
            case HYBRID_COMBINER_CONCAT:
                return "Concatenation";
            case HYBRID_COMBINER_SHA256:
                return "SHA-256 KDF";
            case HYBRID_COMBINER_SHA512:
                return "SHA-512 KDF";
            case HYBRID_COMBINER_KMAC128:
                return "KMAC128 KDF";
            case HYBRID_COMBINER_KMAC256:
                return "KMAC256 KDF";
            default:
                return "Unknown combiner type (" + combinerType + ")";
        }
    }
}
