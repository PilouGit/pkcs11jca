package io.github.pilougit.security.pkcs11.jca.util.jna;

import com.sun.jna.NativeLong;

/**
 * PKCS#11 mechanism types (CK_MECHANISM_TYPE).
 * Based on PKCS#11 v3.2 specification.
 */
public interface PKCS11Mechanisms {

    // ========================================================================
    // Encryption/Decryption mechanisms
    // ========================================================================

    NativeLong CKM_RSA_PKCS = new NativeLong(0x00000001L);
    NativeLong CKM_RSA_PKCS_KEY_PAIR_GEN = new NativeLong(0x00000000L);
    NativeLong CKM_RSA_9796 = new NativeLong(0x00000002L);
    NativeLong CKM_RSA_X_509 = new NativeLong(0x00000003L);
    NativeLong CKM_RSA_PKCS_OAEP = new NativeLong(0x00000009L);
    NativeLong CKM_RSA_PKCS_PSS = new NativeLong(0x0000000DL);
    NativeLong CKM_SHA1_RSA_PKCS_PSS = new NativeLong(0x0000000EL);
    NativeLong CKM_SHA256_RSA_PKCS_PSS = new NativeLong(0x00000040L);
    NativeLong CKM_SHA384_RSA_PKCS_PSS = new NativeLong(0x00000041L);
    NativeLong CKM_SHA512_RSA_PKCS_PSS = new NativeLong(0x00000042L);

    // ========================================================================
    // DSA mechanisms
    // ========================================================================

    NativeLong CKM_DSA_KEY_PAIR_GEN = new NativeLong(0x00000010L);
    NativeLong CKM_DSA = new NativeLong(0x00000011L);
    NativeLong CKM_DSA_SHA1 = new NativeLong(0x00000012L);
    NativeLong CKM_DSA_SHA224 = new NativeLong(0x00000013L);
    NativeLong CKM_DSA_SHA256 = new NativeLong(0x00000014L);
    NativeLong CKM_DSA_SHA384 = new NativeLong(0x00000015L);
    NativeLong CKM_DSA_SHA512 = new NativeLong(0x00000016L);

    // ========================================================================
    // DH mechanisms
    // ========================================================================

    NativeLong CKM_DH_PKCS_KEY_PAIR_GEN = new NativeLong(0x00000020L);
    NativeLong CKM_DH_PKCS_DERIVE = new NativeLong(0x00000021L);

    // ========================================================================
    // EC mechanisms
    // ========================================================================

    NativeLong CKM_EC_KEY_PAIR_GEN = new NativeLong(0x00001040L);
    NativeLong CKM_ECDSA = new NativeLong(0x00001041L);
    NativeLong CKM_ECDSA_SHA1 = new NativeLong(0x00001042L);
    NativeLong CKM_ECDSA_SHA224 = new NativeLong(0x00001043L);
    NativeLong CKM_ECDSA_SHA256 = new NativeLong(0x00001044L);
    NativeLong CKM_ECDSA_SHA384 = new NativeLong(0x00001045L);
    NativeLong CKM_ECDSA_SHA512 = new NativeLong(0x00001046L);
    NativeLong CKM_ECDH1_DERIVE = new NativeLong(0x00001050L);
    NativeLong CKM_ECDH1_COFACTOR_DERIVE = new NativeLong(0x00001051L);

    // ========================================================================
    // EdDSA mechanisms
    // ========================================================================

    NativeLong CKM_EC_EDWARDS_KEY_PAIR_GEN = new NativeLong(0x00001055L);
    NativeLong CKM_EC_MONTGOMERY_KEY_PAIR_GEN = new NativeLong(0x00001056L);
    NativeLong CKM_EDDSA = new NativeLong(0x00001057L);

    // ========================================================================
    // AES mechanisms
    // ========================================================================

    NativeLong CKM_AES_KEY_GEN = new NativeLong(0x00001080L);
    NativeLong CKM_AES_ECB = new NativeLong(0x00001081L);
    NativeLong CKM_AES_CBC = new NativeLong(0x00001082L);
    NativeLong CKM_AES_CBC_PAD = new NativeLong(0x00001083L);
    NativeLong CKM_AES_CTR = new NativeLong(0x00001086L);
    NativeLong CKM_AES_GCM = new NativeLong(0x00001087L);
    NativeLong CKM_AES_CCM = new NativeLong(0x00001088L);
    NativeLong CKM_AES_CTS = new NativeLong(0x00001089L);
    NativeLong CKM_AES_CMAC = new NativeLong(0x0000108AL);

    // ========================================================================
    // DES mechanisms
    // ========================================================================

    NativeLong CKM_DES_KEY_GEN = new NativeLong(0x00000120L);
    NativeLong CKM_DES_ECB = new NativeLong(0x00000121L);
    NativeLong CKM_DES_CBC = new NativeLong(0x00000122L);
    NativeLong CKM_DES_CBC_PAD = new NativeLong(0x00000125L);
    NativeLong CKM_DES3_KEY_GEN = new NativeLong(0x00000131L);
    NativeLong CKM_DES3_ECB = new NativeLong(0x00000132L);
    NativeLong CKM_DES3_CBC = new NativeLong(0x00000133L);
    NativeLong CKM_DES3_CBC_PAD = new NativeLong(0x00000136L);

    // ========================================================================
    // Hash mechanisms
    // ========================================================================

    NativeLong CKM_MD5 = new NativeLong(0x00000210L);
    NativeLong CKM_SHA_1 = new NativeLong(0x00000220L);
    NativeLong CKM_SHA224 = new NativeLong(0x00000255L);
    NativeLong CKM_SHA256 = new NativeLong(0x00000250L);
    NativeLong CKM_SHA384 = new NativeLong(0x00000260L);
    NativeLong CKM_SHA512 = new NativeLong(0x00000270L);
    NativeLong CKM_SHA512_224 = new NativeLong(0x00000048L);
    NativeLong CKM_SHA512_256 = new NativeLong(0x0000004CL);
    NativeLong CKM_SHA3_224 = new NativeLong(0x000002B0L);
    NativeLong CKM_SHA3_256 = new NativeLong(0x000002B1L);
    NativeLong CKM_SHA3_384 = new NativeLong(0x000002B2L);
    NativeLong CKM_SHA3_512 = new NativeLong(0x000002B3L);

    // ========================================================================
    // HMAC mechanisms
    // ========================================================================

    NativeLong CKM_MD5_HMAC = new NativeLong(0x00000211L);
    NativeLong CKM_SHA_1_HMAC = new NativeLong(0x00000221L);
    NativeLong CKM_SHA224_HMAC = new NativeLong(0x00000256L);
    NativeLong CKM_SHA256_HMAC = new NativeLong(0x00000251L);
    NativeLong CKM_SHA384_HMAC = new NativeLong(0x00000261L);
    NativeLong CKM_SHA512_HMAC = new NativeLong(0x00000271L);
    NativeLong CKM_SHA512_224_HMAC = new NativeLong(0x00000049L);
    NativeLong CKM_SHA512_256_HMAC = new NativeLong(0x0000004DL);
    NativeLong CKM_SHA3_224_HMAC = new NativeLong(0x000002B4L);
    NativeLong CKM_SHA3_256_HMAC = new NativeLong(0x000002B5L);
    NativeLong CKM_SHA3_384_HMAC = new NativeLong(0x000002B6L);
    NativeLong CKM_SHA3_512_HMAC = new NativeLong(0x000002B7L);

    // ========================================================================
    // Generic secret key mechanisms
    // ========================================================================

    NativeLong CKM_GENERIC_SECRET_KEY_GEN = new NativeLong(0x00000350L);

    // ========================================================================
    // Post-Quantum Cryptography mechanisms (PKCS#11 v3.2)
    // ========================================================================

    /** ML-KEM generic key pair generation (use with CKA_VALUE_LEN) */
    NativeLong CKM_ML_KEM_KEY_PAIR_GEN = new NativeLong(0x0000000FL);

    /** ML-KEM-512 key pair generation */
    NativeLong CKM_ML_KEM_512_KEY_PAIR_GEN = new NativeLong(0x00000500L);

    /** ML-KEM-768 key pair generation */
    NativeLong CKM_ML_KEM_768_KEY_PAIR_GEN = new NativeLong(0x00000501L);

    /** ML-KEM-1024 key pair generation */
    NativeLong CKM_ML_KEM_1024_KEY_PAIR_GEN = new NativeLong(0x00000502L);

    /** ML-KEM encapsulation/decapsulation */
    NativeLong CKM_ML_KEM = new NativeLong(0x00000503L);

    /** ML-KEM-512 encapsulation/decapsulation */
    NativeLong CKM_MLKEM_512 = new NativeLong(0x00000504L);

    /** ML-KEM-768 encapsulation/decapsulation */
    NativeLong CKM_MLKEM_768 = new NativeLong(0x00000505L);

    /** ML-KEM-1024 encapsulation/decapsulation */
    NativeLong CKM_MLKEM_1024 = new NativeLong(0x00000506L);

    /** ML-DSA-44 key pair generation */
    NativeLong CKM_ML_DSA_44_KEY_PAIR_GEN = new NativeLong(0x00000510L);

    /** ML-DSA-65 key pair generation */
    NativeLong CKM_ML_DSA_65_KEY_PAIR_GEN = new NativeLong(0x00000511L);

    /** ML-DSA-87 key pair generation */
    NativeLong CKM_ML_DSA_87_KEY_PAIR_GEN = new NativeLong(0x00000512L);

    /** ML-DSA signature */
    NativeLong CKM_ML_DSA = new NativeLong(0x00000513L);

    /** SLH-DSA-SHA2-128s key pair generation */
    NativeLong CKM_SLH_DSA_SHA2_128S_KEY_PAIR_GEN = new NativeLong(0x00000520L);

    /** SLH-DSA-SHA2-128f key pair generation */
    NativeLong CKM_SLH_DSA_SHA2_128F_KEY_PAIR_GEN = new NativeLong(0x00000521L);

    /** SLH-DSA-SHA2-192s key pair generation */
    NativeLong CKM_SLH_DSA_SHA2_192S_KEY_PAIR_GEN = new NativeLong(0x00000522L);

    /** SLH-DSA-SHA2-192f key pair generation */
    NativeLong CKM_SLH_DSA_SHA2_192F_KEY_PAIR_GEN = new NativeLong(0x00000523L);

    /** SLH-DSA-SHA2-256s key pair generation */
    NativeLong CKM_SLH_DSA_SHA2_256S_KEY_PAIR_GEN = new NativeLong(0x00000524L);

    /** SLH-DSA-SHA2-256f key pair generation */
    NativeLong CKM_SLH_DSA_SHA2_256F_KEY_PAIR_GEN = new NativeLong(0x00000525L);

    /** SLH-DSA signature */
    NativeLong CKM_SLH_DSA = new NativeLong(0x00000526L);

    // ========================================================================
    // KDF mechanisms
    // ========================================================================

    NativeLong CKM_HKDF_DERIVE = new NativeLong(0x00000411L);
    NativeLong CKM_HKDF_DATA = new NativeLong(0x00000412L);
    NativeLong CKM_HKDF_KEY_GEN = new NativeLong(0x00000413L);

    // ========================================================================
    // Vendor defined mechanisms start
    // ========================================================================

    NativeLong CKM_VENDOR_DEFINED = new NativeLong(0x80000000L);

    // ========================================================================
    // SoftHSMv2 Vendor-Specific Hybrid KEM Mechanisms
    // ========================================================================

    /** ML-KEM-768 + ECDH P-256 hybrid KEM */
    NativeLong CKM_VENDOR_MLKEM768_ECDH_P256 = new NativeLong(0x80000001L);

    /** ML-KEM-1024 + ECDH P-384 hybrid KEM */
    NativeLong CKM_VENDOR_MLKEM1024_ECDH_P384 = new NativeLong(0x80000002L);

    /** ML-KEM-768 + X25519 hybrid KEM */
    NativeLong CKM_VENDOR_MLKEM768_X25519 = new NativeLong(0x80000003L);

    /** ML-DSA-65 + ECDSA P-256 hybrid signature */
    NativeLong CKM_VENDOR_MLDSA65_ECDSA_P256 = new NativeLong(0x80000010L);

    /** ML-DSA-87 + ECDSA P-384 hybrid signature */
    NativeLong CKM_VENDOR_MLDSA87_ECDSA_P384 = new NativeLong(0x80000011L);
}
