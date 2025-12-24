package io.github.pilougit.security.pkcs11.jca.util.jna;

public interface CKF  {// ======================================================================
// Slot flags (CK_SLOT_INFO.flags)
// ======================================================================

long CKF_TOKEN_PRESENT        = (1L << 0);
long CKF_REMOVABLE_DEVICE     = (1L << 1);
long CKF_HW_SLOT              = (1L << 2);
long CKF_ARRAY_ATTRIBUTE      = (1L << 30);

// ======================================================================
// Library flags (CK_INFO.flags)
// ======================================================================

long CKF_LIBRARY_CANT_CREATE_OS_THREADS = (1L << 0);
long CKF_OS_LOCKING_OK                  = (1L << 1);

// ======================================================================
// HKDF flags (CK_HKDF_PARAMS.flags)
// ======================================================================

long CKF_HKDF_SALT_NULL  = (1L << 0);
long CKF_HKDF_SALT_DATA  = (1L << 1);
long CKF_HKDF_SALT_KEY   = (1L << 2);

// ======================================================================
// Interface flags (CK_INTERFACE.flags)
// ======================================================================

long CKF_INTERFACE_FORK_SAFE = (1L << 0);

// ======================================================================
// EC mechanism flags (CK_MECHANISM_INFO.flags)
// ======================================================================

long CKF_EC_F_P           = (1L << 20);
long CKF_EC_F_2M          = (1L << 21);
long CKF_EC_ECPARAMETERS  = (1L << 22);

/**
 * EC curve specified by OID.
 * NOTE: CKF_EC_OID == CKF_EC_NAMEDCURVE (same bit)
 */
long CKF_EC_OID           = (1L << 23);
long CKF_EC_NAMEDCURVE    = (1L << 23);

long CKF_EC_UNCOMPRESS    = (1L << 24);
long CKF_EC_COMPRESS      = (1L << 25);
long CKF_EC_CURVENAME     = (1L << 26);

long CKF_ENCAPSULATE      = (1L << 28);
long CKF_DECAPSULATE      = (1L << 29);

// ======================================================================
// Mechanism capabilities (CK_MECHANISM_INFO.flags)
// ======================================================================

long CKF_HW               = (1L << 0);

long CKF_MESSAGE_ENCRYPT  = (1L << 1);
long CKF_MESSAGE_DECRYPT  = (1L << 2);
long CKF_MESSAGE_SIGN     = (1L << 3);
long CKF_MESSAGE_VERIFY   = (1L << 4);
long CKF_MULTI_MESSAGE    = (1L << 5);
long CKF_FIND_OBJECTS     = (1L << 6);

long CKF_ENCRYPT          = (1L << 8);
long CKF_DECRYPT          = (1L << 9);
long CKF_DIGEST           = (1L << 10);
long CKF_SIGN             = (1L << 11);
long CKF_SIGN_RECOVER     = (1L << 12);
long CKF_VERIFY           = (1L << 13);
long CKF_VERIFY_RECOVER   = (1L << 14);
long CKF_GENERATE         = (1L << 15);
long CKF_GENERATE_KEY_PAIR= (1L << 16);
long CKF_WRAP             = (1L << 17);
long CKF_UNWRAP           = (1L << 18);
long CKF_DERIVE           = (1L << 19);

long CKF_EXTENSION        = (1L << 31);
}