package io.github.pilougit.security.pkcs11.jca.mechanisms;

import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public enum Mechanism {
    // ========================================================================
    // Encryption/Decryption mechanisms
    // ========================================================================


    CKM_RSA_PKCS(0x00000001L),
    CKM_RSA_PKCS_KEY_PAIR_GEN(0x00000000L),
    CKM_RSA_9796(0x00000002L),
    CKM_RSA_X_509(0x00000003L),
    CKM_RSA_PKCS_OAEP(0x00000009L),
    CKM_RSA_PKCS_PSS(0x0000000DL),
    CKM_SHA1_RSA_PKCS_PSS(0x0000000EL),
    CKM_SHA256_RSA_PKCS_PSS(0x00000040L),
    CKM_SHA384_RSA_PKCS_PSS(0x00000041L),
    CKM_SHA512_RSA_PKCS_PSS(0x00000042L),

    // ========================================================================
    // DSA mechanisms
    // ========================================================================

    CKM_DSA_KEY_PAIR_GEN(0x00000010L),
    CKM_DSA(0x00000011L),
    CKM_DSA_SHA1(0x00000012L),
    CKM_DSA_SHA224(0x00000013L),
    CKM_DSA_SHA256(0x00000014L),
    CKM_DSA_SHA384(0x00000015L),
    CKM_DSA_SHA512(0x00000016L),

    // ========================================================================
    // DH mechanisms
    // ========================================================================

    CKM_DH_PKCS_KEY_PAIR_GEN(0x00000020L),
    CKM_DH_PKCS_DERIVE(0x00000021L),

    // ========================================================================
    // EC mechanisms
    // ========================================================================

    CKM_EC_KEY_PAIR_GEN(0x00001040L),
    CKM_ECDSA(0x00001041L),
    CKM_ECDSA_SHA1(0x00001042L),
    CKM_ECDSA_SHA224(0x00001043L),
    CKM_ECDSA_SHA256(0x00001044L),
    CKM_ECDSA_SHA384(0x00001045L),
    CKM_ECDSA_SHA512(0x00001046L),
    CKM_ECDH1_DERIVE(0x00001050L),
    CKM_ECDH1_COFACTOR_DERIVE(0x00001051L),

    // ========================================================================
    // EdDSA mechanisms
    // ========================================================================

    CKM_EC_EDWARDS_KEY_PAIR_GEN(0x00001055L),
    CKM_EC_MONTGOMERY_KEY_PAIR_GEN(0x00001056L),
    CKM_EDDSA(0x00001057L),

    // ========================================================================
    // AES mechanisms
    // ========================================================================

    CKM_AES_KEY_GEN(0x00001080L),
    CKM_AES_ECB(0x00001081L),
    CKM_AES_CBC(0x00001082L),
    CKM_AES_CBC_PAD(0x00001083L),
    CKM_AES_CTR(0x00001086L),
    CKM_AES_GCM(0x00001087L),
    CKM_AES_CCM(0x00001088L),
    CKM_AES_CTS(0x00001089L),
    CKM_AES_CMAC(0x0000108AL),

    // ========================================================================
    // DES mechanisms
    // ========================================================================

    CKM_DES_KEY_GEN(0x00000120L),
    CKM_DES_ECB(0x00000121L),
    CKM_DES_CBC(0x00000122L),
    CKM_DES_CBC_PAD(0x00000125L),
    CKM_DES3_KEY_GEN(0x00000131L),
    CKM_DES3_ECB(0x00000132L),
    CKM_DES3_CBC(0x00000133L),
    CKM_DES3_CBC_PAD(0x00000136L),

    // ========================================================================
    // Hash mechanisms
    // ========================================================================

    CKM_MD5(0x00000210L),
    CKM_SHA_1(0x00000220L),
    CKM_SHA224(0x00000255L),
    CKM_SHA256(0x00000250L),
    CKM_SHA384(0x00000260L),
    CKM_SHA512(0x00000270L),
    CKM_SHA512_224(0x00000048L),
    CKM_SHA512_256(0x0000004CL),
    CKM_SHA3_224(0x000002B0L),
    CKM_SHA3_256(0x000002B1L),
    CKM_SHA3_384(0x000002B2L),
    CKM_SHA3_512(0x000002B3L),

    // ========================================================================
    // HMAC mechanisms
    // ========================================================================

    CKM_MD5_HMAC(0x00000211L),
    CKM_SHA_1_HMAC(0x00000221L),
    CKM_SHA224_HMAC(0x00000256L),
    CKM_SHA256_HMAC(0x00000251L),
    CKM_SHA384_HMAC(0x00000261L),
    CKM_SHA512_HMAC(0x00000271L),
    CKM_SHA512_224_HMAC(0x00000049L),
    CKM_SHA512_256_HMAC(0x0000004DL),
    CKM_SHA3_224_HMAC(0x000002B4L),
    CKM_SHA3_256_HMAC(0x000002B5L),
    CKM_SHA3_384_HMAC(0x000002B6L),
    CKM_SHA3_512_HMAC(0x000002B7L),

    // ========================================================================
    // Generic secret key mechanisms
    // ========================================================================

    CKM_GENERIC_SECRET_KEY_GEN(0x00000350L),

    // ========================================================================
    // Post-Quantum Cryptography mechanisms (PKCS#11 v3.2)
    // ========================================================================

    /** ML-KEM generic key pair generation (use with CKA_VALUE_LEN) */
    CKM_ML_KEM_KEY_PAIR_GEN(0x0000000FL),

    /** ML-KEM-512 key pair generation */
    CKM_ML_KEM_512_KEY_PAIR_GEN(0x00000500L),

    /** ML-KEM-768 key pair generation */
    CKM_ML_KEM_768_KEY_PAIR_GEN(0x00000501L),

    /** ML-KEM-1024 key pair generation */
    CKM_ML_KEM_1024_KEY_PAIR_GEN(0x00000502L),

    /** ML-KEM encapsulation/decapsulation */
    CKM_ML_KEM(0x00000503L),

    /** ML-KEM-512 encapsulation/decapsulation */
    CKM_MLKEM_512(0x00000504L),

    /** ML-KEM-768 encapsulation/decapsulation */
    CKM_MLKEM_768(0x00000505L),

    /** ML-KEM-1024 encapsulation/decapsulation */
    CKM_MLKEM_1024(0x00000506L),

    /** ML-DSA-44 key pair generation */
    CKM_ML_DSA_44_KEY_PAIR_GEN(0x00000510L),

    /** ML-DSA-65 key pair generation */
    CKM_ML_DSA_65_KEY_PAIR_GEN(0x00000511L),

    /** ML-DSA-87 key pair generation */
    CKM_ML_DSA_87_KEY_PAIR_GEN(0x00000512L),

    /** ML-DSA signature */
    CKM_ML_DSA(0x00000513L),

    /** SLH-DSA-SHA2-128s key pair generation */
    CKM_SLH_DSA_SHA2_128S_KEY_PAIR_GEN(0x00000520L),

    /** SLH-DSA-SHA2-128f key pair generation */
    CKM_SLH_DSA_SHA2_128F_KEY_PAIR_GEN(0x00000521L),

    /** SLH-DSA-SHA2-192s key pair generation */
    CKM_SLH_DSA_SHA2_192S_KEY_PAIR_GEN(0x00000522L),

    /** SLH-DSA-SHA2-192f key pair generation */
    CKM_SLH_DSA_SHA2_192F_KEY_PAIR_GEN(0x00000523L),

    /** SLH-DSA-SHA2-256s key pair generation */
    CKM_SLH_DSA_SHA2_256S_KEY_PAIR_GEN(0x00000524L),

    /** SLH-DSA-SHA2-256f key pair generation */
    CKM_SLH_DSA_SHA2_256F_KEY_PAIR_GEN(0x00000525L),

    /** SLH-DSA signature */
    CKM_SLH_DSA(0x00000526L),

    // ========================================================================
    // KDF mechanisms
    // ========================================================================

    CKM_HKDF_DERIVE(0x00000411L),
    CKM_HKDF_DATA(0x00000412L),
    CKM_HKDF_KEY_GEN(0x00000413L),

    // ========================================================================
    // Vendor defined mechanisms start
    // ========================================================================

    CKM_VENDOR_DEFINED(0x80000000L),

    // ========================================================================
    // SoftHSMv2 Vendor-Specific Hybrid KEM Mechanisms
    // ========================================================================

    /** ML-KEM-768 + ECDH P-256 hybrid KEM */
    CKM_VENDOR_MLKEM768_ECDH_P256(0x80000001L),

    /** ML-KEM-1024 + ECDH P-384 hybrid KEM */
    CKM_VENDOR_MLKEM1024_ECDH_P384(0x80000002L),

    /** ML-KEM-768 + X25519 hybrid KEM */
    CKM_VENDOR_MLKEM768_X25519(0x80000003L),

    /** ML-DSA-65 + ECDSA P-256 hybrid signature */
    CKM_VENDOR_MLDSA65_ECDSA_P256(0x80000010L),

    /** ML-DSA-87 + ECDSA P-384 hybrid signature */
    CKM_VENDOR_MLDSA87_ECDSA_P384(0x80000011L),
    UNKNOWN(0x8888888L);
    private final long value;

    Mechanism(long value) {
        this.value = value;
    }

    public long value() {
        return value;
    }

    private static final Map<Long, Mechanism> LOOKUP =
            Stream.of(values())
                    .collect(Collectors.toMap(
                            Mechanism::value,
                            m -> m,
                            (a, b) -> a
                    ));

    public static Mechanism from(long value) {
        return LOOKUP.getOrDefault(value, UNKNOWN);
    }
}
