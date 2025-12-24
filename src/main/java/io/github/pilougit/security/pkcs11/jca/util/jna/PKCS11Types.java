package io.github.pilougit.security.pkcs11.jca.util.jna;

import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;

/**
 * PKCS#11 base types and constants.
 * Based on PKCS#11 v3.2 specification.
 */
public interface PKCS11Types {

    // Basic types (mapped to Java types)
    // CK_ULONG -> NativeLong
    // CK_BYTE -> byte
    // CK_CHAR -> byte
    // CK_UTF8CHAR -> byte
    // CK_VOID_PTR -> Pointer
    // CK_BYTE_PTR -> Pointer

    // Cryptoki version
    int CRYPTOKI_VERSION_MAJOR = 3;
    int CRYPTOKI_VERSION_MINOR = 2;
    int CRYPTOKI_VERSION_REVISION = 0;

    // Boolean values
    byte CK_FALSE = 0;
    byte CK_TRUE = 1;

    // Return values (CK_RV)
    NativeLong CKR_OK = new NativeLong(0x00000000L);
    NativeLong CKR_CANCEL = new NativeLong(0x00000001L);
    NativeLong CKR_HOST_MEMORY = new NativeLong(0x00000002L);
    NativeLong CKR_SLOT_ID_INVALID = new NativeLong(0x00000003L);
    NativeLong CKR_GENERAL_ERROR = new NativeLong(0x00000005L);
    NativeLong CKR_FUNCTION_FAILED = new NativeLong(0x00000006L);
    NativeLong CKR_ARGUMENTS_BAD = new NativeLong(0x00000007L);
    NativeLong CKR_NO_EVENT = new NativeLong(0x00000008L);
    NativeLong CKR_NEED_TO_CREATE_THREADS = new NativeLong(0x00000009L);
    NativeLong CKR_CANT_LOCK = new NativeLong(0x0000000AL);
    NativeLong CKR_ATTRIBUTE_READ_ONLY = new NativeLong(0x00000010L);
    NativeLong CKR_ATTRIBUTE_SENSITIVE = new NativeLong(0x00000011L);
    NativeLong CKR_ATTRIBUTE_TYPE_INVALID = new NativeLong(0x00000012L);
    NativeLong CKR_ATTRIBUTE_VALUE_INVALID = new NativeLong(0x00000013L);
    NativeLong CKR_DATA_INVALID = new NativeLong(0x00000020L);
    NativeLong CKR_DATA_LEN_RANGE = new NativeLong(0x00000021L);
    NativeLong CKR_DEVICE_ERROR = new NativeLong(0x00000030L);
    NativeLong CKR_DEVICE_MEMORY = new NativeLong(0x00000031L);
    NativeLong CKR_DEVICE_REMOVED = new NativeLong(0x00000032L);
    NativeLong CKR_ENCRYPTED_DATA_INVALID = new NativeLong(0x00000040L);
    NativeLong CKR_ENCRYPTED_DATA_LEN_RANGE = new NativeLong(0x00000041L);
    NativeLong CKR_FUNCTION_CANCELED = new NativeLong(0x00000050L);
    NativeLong CKR_FUNCTION_NOT_PARALLEL = new NativeLong(0x00000051L);
    NativeLong CKR_FUNCTION_NOT_SUPPORTED = new NativeLong(0x00000054L);
    NativeLong CKR_KEY_HANDLE_INVALID = new NativeLong(0x00000060L);
    NativeLong CKR_KEY_SIZE_RANGE = new NativeLong(0x00000062L);
    NativeLong CKR_KEY_TYPE_INCONSISTENT = new NativeLong(0x00000063L);
    NativeLong CKR_KEY_NOT_NEEDED = new NativeLong(0x00000064L);
    NativeLong CKR_KEY_CHANGED = new NativeLong(0x00000065L);
    NativeLong CKR_KEY_NEEDED = new NativeLong(0x00000066L);
    NativeLong CKR_KEY_INDIGESTIBLE = new NativeLong(0x00000067L);
    NativeLong CKR_KEY_FUNCTION_NOT_PERMITTED = new NativeLong(0x00000068L);
    NativeLong CKR_KEY_NOT_WRAPPABLE = new NativeLong(0x00000069L);
    NativeLong CKR_KEY_UNEXTRACTABLE = new NativeLong(0x0000006AL);
    NativeLong CKR_MECHANISM_INVALID = new NativeLong(0x00000070L);
    NativeLong CKR_MECHANISM_PARAM_INVALID = new NativeLong(0x00000071L);
    NativeLong CKR_OBJECT_HANDLE_INVALID = new NativeLong(0x00000082L);
    NativeLong CKR_OPERATION_ACTIVE = new NativeLong(0x00000090L);
    NativeLong CKR_OPERATION_NOT_INITIALIZED = new NativeLong(0x00000091L);
    NativeLong CKR_PIN_INCORRECT = new NativeLong(0x000000A0L);
    NativeLong CKR_PIN_INVALID = new NativeLong(0x000000A1L);
    NativeLong CKR_PIN_LEN_RANGE = new NativeLong(0x000000A2L);
    NativeLong CKR_PIN_EXPIRED = new NativeLong(0x000000A3L);
    NativeLong CKR_PIN_LOCKED = new NativeLong(0x000000A4L);
    NativeLong CKR_SESSION_CLOSED = new NativeLong(0x000000B0L);
    NativeLong CKR_SESSION_COUNT = new NativeLong(0x000000B1L);
    NativeLong CKR_SESSION_HANDLE_INVALID = new NativeLong(0x000000B3L);
    NativeLong CKR_SESSION_PARALLEL_NOT_SUPPORTED = new NativeLong(0x000000B4L);
    NativeLong CKR_SESSION_READ_ONLY = new NativeLong(0x000000B5L);
    NativeLong CKR_SESSION_EXISTS = new NativeLong(0x000000B6L);
    NativeLong CKR_SESSION_READ_ONLY_EXISTS = new NativeLong(0x000000B7L);
    NativeLong CKR_SESSION_READ_WRITE_SO_EXISTS = new NativeLong(0x000000B8L);
    NativeLong CKR_SIGNATURE_INVALID = new NativeLong(0x000000C0L);
    NativeLong CKR_SIGNATURE_LEN_RANGE = new NativeLong(0x000000C1L);
    NativeLong CKR_TEMPLATE_INCOMPLETE = new NativeLong(0x000000D0L);
    NativeLong CKR_TEMPLATE_INCONSISTENT = new NativeLong(0x000000D1L);
    NativeLong CKR_TOKEN_NOT_PRESENT = new NativeLong(0x000000E0L);
    NativeLong CKR_TOKEN_NOT_RECOGNIZED = new NativeLong(0x000000E1L);
    NativeLong CKR_TOKEN_WRITE_PROTECTED = new NativeLong(0x000000E2L);
    NativeLong CKR_UNWRAPPING_KEY_HANDLE_INVALID = new NativeLong(0x000000F0L);
    NativeLong CKR_UNWRAPPING_KEY_SIZE_RANGE = new NativeLong(0x000000F1L);
    NativeLong CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT = new NativeLong(0x000000F2L);
    NativeLong CKR_USER_ALREADY_LOGGED_IN = new NativeLong(0x00000100L);
    NativeLong CKR_USER_NOT_LOGGED_IN = new NativeLong(0x00000101L);
    NativeLong CKR_USER_PIN_NOT_INITIALIZED = new NativeLong(0x00000102L);
    NativeLong CKR_USER_TYPE_INVALID = new NativeLong(0x00000103L);
    NativeLong CKR_USER_ANOTHER_ALREADY_LOGGED_IN = new NativeLong(0x00000104L);
    NativeLong CKR_USER_TOO_MANY_TYPES = new NativeLong(0x00000105L);
    NativeLong CKR_WRAPPED_KEY_INVALID = new NativeLong(0x00000110L);
    NativeLong CKR_WRAPPED_KEY_LEN_RANGE = new NativeLong(0x00000112L);
    NativeLong CKR_WRAPPING_KEY_HANDLE_INVALID = new NativeLong(0x00000113L);
    NativeLong CKR_WRAPPING_KEY_SIZE_RANGE = new NativeLong(0x00000114L);
    NativeLong CKR_WRAPPING_KEY_TYPE_INCONSISTENT = new NativeLong(0x00000115L);
    NativeLong CKR_RANDOM_SEED_NOT_SUPPORTED = new NativeLong(0x00000120L);
    NativeLong CKR_RANDOM_NO_RNG = new NativeLong(0x00000121L);
    NativeLong CKR_DOMAIN_PARAMS_INVALID = new NativeLong(0x00000130L);
    NativeLong CKR_BUFFER_TOO_SMALL = new NativeLong(0x00000150L);
    NativeLong CKR_SAVED_STATE_INVALID = new NativeLong(0x00000160L);
    NativeLong CKR_INFORMATION_SENSITIVE = new NativeLong(0x00000170L);
    NativeLong CKR_STATE_UNSAVEABLE = new NativeLong(0x00000180L);
    NativeLong CKR_CRYPTOKI_NOT_INITIALIZED = new NativeLong(0x00000190L);
    NativeLong CKR_CRYPTOKI_ALREADY_INITIALIZED = new NativeLong(0x00000191L);
    NativeLong CKR_MUTEX_BAD = new NativeLong(0x000001A0L);
    NativeLong CKR_MUTEX_NOT_LOCKED = new NativeLong(0x000001A1L);
    NativeLong CKR_VENDOR_DEFINED = new NativeLong(0x80000000L);

    // Object classes (CK_OBJECT_CLASS)
    NativeLong CKO_DATA = new NativeLong(0x00000000L);
    NativeLong CKO_CERTIFICATE = new NativeLong(0x00000001L);
    NativeLong CKO_PUBLIC_KEY = new NativeLong(0x00000002L);
    NativeLong CKO_PRIVATE_KEY = new NativeLong(0x00000003L);
    NativeLong CKO_SECRET_KEY = new NativeLong(0x00000004L);
    NativeLong CKO_HW_FEATURE = new NativeLong(0x00000005L);
    NativeLong CKO_DOMAIN_PARAMETERS = new NativeLong(0x00000006L);
    NativeLong CKO_MECHANISM = new NativeLong(0x00000007L);
    NativeLong CKO_OTP_KEY = new NativeLong(0x00000008L);
    NativeLong CKO_PROFILE = new NativeLong(0x00000009L);
    NativeLong CKO_VENDOR_DEFINED = new NativeLong(0x80000000L);

    // Key types (CK_KEY_TYPE)
    NativeLong CKK_RSA = new NativeLong(0x00000000L);
    NativeLong CKK_DSA = new NativeLong(0x00000001L);
    NativeLong CKK_DH = new NativeLong(0x00000002L);
    NativeLong CKK_ECDSA = new NativeLong(0x00000003L);
    NativeLong CKK_EC = new NativeLong(0x00000003L);
    NativeLong CKK_X9_42_DH = new NativeLong(0x00000004L);
    NativeLong CKK_KEA = new NativeLong(0x00000005L);
    NativeLong CKK_GENERIC_SECRET = new NativeLong(0x00000010L);
    NativeLong CKK_RC2 = new NativeLong(0x00000011L);
    NativeLong CKK_RC4 = new NativeLong(0x00000012L);
    NativeLong CKK_DES = new NativeLong(0x00000013L);
    NativeLong CKK_DES2 = new NativeLong(0x00000014L);
    NativeLong CKK_DES3 = new NativeLong(0x00000015L);
    NativeLong CKK_CAST = new NativeLong(0x00000016L);
    NativeLong CKK_CAST3 = new NativeLong(0x00000017L);
    NativeLong CKK_CAST128 = new NativeLong(0x00000018L);
    NativeLong CKK_RC5 = new NativeLong(0x00000019L);
    NativeLong CKK_IDEA = new NativeLong(0x0000001AL);
    NativeLong CKK_SKIPJACK = new NativeLong(0x0000001BL);
    NativeLong CKK_BATON = new NativeLong(0x0000001CL);
    NativeLong CKK_JUNIPER = new NativeLong(0x0000001DL);
    NativeLong CKK_CDMF = new NativeLong(0x0000001EL);
    NativeLong CKK_AES = new NativeLong(0x0000001FL);
    NativeLong CKK_BLOWFISH = new NativeLong(0x00000020L);
    NativeLong CKK_TWOFISH = new NativeLong(0x00000021L);
    NativeLong CKK_SECURID = new NativeLong(0x00000022L);
    NativeLong CKK_HOTP = new NativeLong(0x00000023L);
    NativeLong CKK_ACTI = new NativeLong(0x00000024L);
    NativeLong CKK_CAMELLIA = new NativeLong(0x00000025L);
    NativeLong CKK_ARIA = new NativeLong(0x00000026L);
    NativeLong CKK_MD5_HMAC = new NativeLong(0x00000027L);
    NativeLong CKK_SHA_1_HMAC = new NativeLong(0x00000028L);
    NativeLong CKK_RIPEMD128_HMAC = new NativeLong(0x00000029L);
    NativeLong CKK_RIPEMD160_HMAC = new NativeLong(0x0000002AL);
    NativeLong CKK_SHA256_HMAC = new NativeLong(0x0000002BL);
    NativeLong CKK_SHA384_HMAC = new NativeLong(0x0000002CL);
    NativeLong CKK_SHA512_HMAC = new NativeLong(0x0000002DL);
    NativeLong CKK_SHA224_HMAC = new NativeLong(0x0000002EL);
    NativeLong CKK_SEED = new NativeLong(0x0000002FL);
    NativeLong CKK_GOSTR3410 = new NativeLong(0x00000030L);
    NativeLong CKK_GOSTR3411 = new NativeLong(0x00000031L);
    NativeLong CKK_GOST28147 = new NativeLong(0x00000032L);
    NativeLong CKK_CHACHA20 = new NativeLong(0x00000033L);
    NativeLong CKK_POLY1305 = new NativeLong(0x00000034L);
    NativeLong CKK_AES_XTS = new NativeLong(0x00000035L);
    NativeLong CKK_SHA3_224_HMAC = new NativeLong(0x00000036L);
    NativeLong CKK_SHA3_256_HMAC = new NativeLong(0x00000037L);
    NativeLong CKK_SHA3_384_HMAC = new NativeLong(0x00000038L);
    NativeLong CKK_SHA3_512_HMAC = new NativeLong(0x00000039L);
    NativeLong CKK_BLAKE2B_160_HMAC = new NativeLong(0x0000003AL);
    NativeLong CKK_BLAKE2B_256_HMAC = new NativeLong(0x0000003BL);
    NativeLong CKK_BLAKE2B_384_HMAC = new NativeLong(0x0000003CL);
    NativeLong CKK_BLAKE2B_512_HMAC = new NativeLong(0x0000003DL);
    NativeLong CKK_SALSA20 = new NativeLong(0x0000003EL);
    NativeLong CKK_X2RATCHET = new NativeLong(0x0000003FL);
    NativeLong CKK_EC_EDWARDS = new NativeLong(0x00000040L);
    NativeLong CKK_EC_MONTGOMERY = new NativeLong(0x00000041L);
    NativeLong CKK_HKDF = new NativeLong(0x00000042L);
    NativeLong CKK_SHA512_224_HMAC = new NativeLong(0x00000043L);
    NativeLong CKK_SHA512_256_HMAC = new NativeLong(0x00000044L);
    NativeLong CKK_SHA512_T_HMAC = new NativeLong(0x00000045L);
    NativeLong CKK_HSS = new NativeLong(0x00000046L);
    NativeLong CKK_VENDOR_DEFINED = new NativeLong(0x80000000L);

    // SoftHSMv2 vendor-specific key types for PQC hybrid schemes
    NativeLong CKK_VENDOR_HYBRID_KEM = new NativeLong(0x80000100L);
    NativeLong CKK_VENDOR_HYBRID_SIGNATURE = new NativeLong(0x80000101L);

    // Attribute types (CK_ATTRIBUTE_TYPE) - Most common ones
    NativeLong CKA_CLASS = new NativeLong(0x00000000L);
    NativeLong CKA_TOKEN = new NativeLong(0x00000001L);
    NativeLong CKA_PRIVATE = new NativeLong(0x00000002L);
    NativeLong CKA_LABEL = new NativeLong(0x00000003L);
    NativeLong CKA_APPLICATION = new NativeLong(0x00000010L);
    NativeLong CKA_VALUE = new NativeLong(0x00000011L);
    NativeLong CKA_OBJECT_ID = new NativeLong(0x00000012L);
    NativeLong CKA_CERTIFICATE_TYPE = new NativeLong(0x00000080L);
    NativeLong CKA_ISSUER = new NativeLong(0x00000081L);
    NativeLong CKA_SERIAL_NUMBER = new NativeLong(0x00000082L);
    NativeLong CKA_AC_ISSUER = new NativeLong(0x00000083L);
    NativeLong CKA_OWNER = new NativeLong(0x00000084L);
    NativeLong CKA_ATTR_TYPES = new NativeLong(0x00000085L);
    NativeLong CKA_TRUSTED = new NativeLong(0x00000086L);
    NativeLong CKA_KEY_TYPE = new NativeLong(0x00000100L);
    NativeLong CKA_SUBJECT = new NativeLong(0x00000101L);
    NativeLong CKA_ID = new NativeLong(0x00000102L);
    NativeLong CKA_SENSITIVE = new NativeLong(0x00000103L);
    NativeLong CKA_ENCRYPT = new NativeLong(0x00000104L);
    NativeLong CKA_DECRYPT = new NativeLong(0x00000105L);
    NativeLong CKA_WRAP = new NativeLong(0x00000106L);
    NativeLong CKA_UNWRAP = new NativeLong(0x00000107L);
    NativeLong CKA_SIGN = new NativeLong(0x00000108L);
    NativeLong CKA_SIGN_RECOVER = new NativeLong(0x00000109L);
    NativeLong CKA_VERIFY = new NativeLong(0x0000010AL);
    NativeLong CKA_VERIFY_RECOVER = new NativeLong(0x0000010BL);
    NativeLong CKA_DERIVE = new NativeLong(0x0000010CL);
    NativeLong CKA_START_DATE = new NativeLong(0x00000110L);
    NativeLong CKA_END_DATE = new NativeLong(0x00000111L);
    NativeLong CKA_MODULUS = new NativeLong(0x00000120L);
    NativeLong CKA_MODULUS_BITS = new NativeLong(0x00000121L);
    NativeLong CKA_PUBLIC_EXPONENT = new NativeLong(0x00000122L);
    NativeLong CKA_PRIVATE_EXPONENT = new NativeLong(0x00000123L);
    NativeLong CKA_PRIME_1 = new NativeLong(0x00000124L);
    NativeLong CKA_PRIME_2 = new NativeLong(0x00000125L);
    NativeLong CKA_EXPONENT_1 = new NativeLong(0x00000126L);
    NativeLong CKA_EXPONENT_2 = new NativeLong(0x00000127L);
    NativeLong CKA_COEFFICIENT = new NativeLong(0x00000128L);
    NativeLong CKA_PUBLIC_KEY_INFO = new NativeLong(0x00000129L);
    NativeLong CKA_PRIME = new NativeLong(0x00000130L);
    NativeLong CKA_SUBPRIME = new NativeLong(0x00000131L);
    NativeLong CKA_BASE = new NativeLong(0x00000132L);
    NativeLong CKA_VALUE_BITS = new NativeLong(0x00000160L);
    NativeLong CKA_VALUE_LEN = new NativeLong(0x00000161L);
    NativeLong CKA_EXTRACTABLE = new NativeLong(0x00000162L);
    NativeLong CKA_LOCAL = new NativeLong(0x00000163L);
    NativeLong CKA_NEVER_EXTRACTABLE = new NativeLong(0x00000164L);
    NativeLong CKA_ALWAYS_SENSITIVE = new NativeLong(0x00000165L);
    NativeLong CKA_KEY_GEN_MECHANISM = new NativeLong(0x00000166L);
    NativeLong CKA_MODIFIABLE = new NativeLong(0x00000170L);
    NativeLong CKA_COPYABLE = new NativeLong(0x00000171L);
    NativeLong CKA_DESTROYABLE = new NativeLong(0x00000172L);
    NativeLong CKA_EC_PARAMS = new NativeLong(0x00000180L);
    NativeLong CKA_EC_POINT = new NativeLong(0x00000181L);
    NativeLong CKA_VENDOR_DEFINED = new NativeLong(0x80000000L);

    // SoftHSMv2 vendor-specific attributes for PQC hybrid keys
    NativeLong CKA_VENDOR_PQC_PUBLIC_KEY = new NativeLong(0x80000200L);
    NativeLong CKA_VENDOR_PQC_PRIVATE_KEY = new NativeLong(0x80000201L);
    NativeLong CKA_VENDOR_CLASSICAL_PUBLIC_KEY = new NativeLong(0x80000202L);
    NativeLong CKA_VENDOR_CLASSICAL_PRIVATE_KEY = new NativeLong(0x80000203L);
    NativeLong CKA_VENDOR_HYBRID_MECHANISM = new NativeLong(0x80000204L);

    // User types (CK_USER_TYPE)
    NativeLong CKU_SO = new NativeLong(0x00000000L);
    NativeLong CKU_USER = new NativeLong(0x00000001L);
    NativeLong CKU_CONTEXT_SPECIFIC = new NativeLong(0x00000002L);

    // Session states (CK_STATE)
    NativeLong CKS_RO_PUBLIC_SESSION = new NativeLong(0x00000000L);
    NativeLong CKS_RO_USER_FUNCTIONS = new NativeLong(0x00000001L);
    NativeLong CKS_RW_PUBLIC_SESSION = new NativeLong(0x00000002L);
    NativeLong CKS_RW_USER_FUNCTIONS = new NativeLong(0x00000003L);
    NativeLong CKS_RW_SO_FUNCTIONS = new NativeLong(0x00000004L);

    // Flags
    NativeLong CKF_TOKEN_PRESENT = new NativeLong(0x00000001L);
    NativeLong CKF_REMOVABLE_DEVICE = new NativeLong(0x00000002L);
    NativeLong CKF_HW_SLOT = new NativeLong(0x00000004L);
    NativeLong CKF_RNG = new NativeLong(0x00000001L);
    NativeLong CKF_WRITE_PROTECTED = new NativeLong(0x00000002L);
    NativeLong CKF_LOGIN_REQUIRED = new NativeLong(0x00000004L);
    NativeLong CKF_USER_PIN_INITIALIZED = new NativeLong(0x00000008L);
    NativeLong CKF_RESTORE_KEY_NOT_NEEDED = new NativeLong(0x00000020L);
    NativeLong CKF_CLOCK_ON_TOKEN = new NativeLong(0x00000040L);
    NativeLong CKF_PROTECTED_AUTHENTICATION_PATH = new NativeLong(0x00000100L);
    NativeLong CKF_DUAL_CRYPTO_OPERATIONS = new NativeLong(0x00000200L);
    NativeLong CKF_TOKEN_INITIALIZED = new NativeLong(0x00000400L);
    NativeLong CKF_SECONDARY_AUTHENTICATION = new NativeLong(0x00000800L);
    NativeLong CKF_USER_PIN_COUNT_LOW = new NativeLong(0x00010000L);
    NativeLong CKF_USER_PIN_FINAL_TRY = new NativeLong(0x00020000L);
    NativeLong CKF_USER_PIN_LOCKED = new NativeLong(0x00040000L);
    NativeLong CKF_USER_PIN_TO_BE_CHANGED = new NativeLong(0x00080000L);
    NativeLong CKF_SO_PIN_COUNT_LOW = new NativeLong(0x00100000L);
    NativeLong CKF_SO_PIN_FINAL_TRY = new NativeLong(0x00200000L);
    NativeLong CKF_SO_PIN_LOCKED = new NativeLong(0x00400000L);
    NativeLong CKF_SO_PIN_TO_BE_CHANGED = new NativeLong(0x00800000L);
    NativeLong CKF_ERROR_STATE = new NativeLong(0x01000000L);
    NativeLong CKF_RW_SESSION = new NativeLong(0x00000002L);
    NativeLong CKF_SERIAL_SESSION = new NativeLong(0x00000004L);

    // Special values
    NativeLong CK_UNAVAILABLE_INFORMATION = new NativeLong(~0L);
    NativeLong CK_EFFECTIVELY_INFINITE = new NativeLong(0x00000000L);
    NativeLong CK_INVALID_HANDLE = new NativeLong(0x00000000L);
}
