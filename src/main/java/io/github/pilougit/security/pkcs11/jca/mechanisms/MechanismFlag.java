package io.github.pilougit.security.pkcs11.jca.mechanisms;

public enum MechanismFlag {

    HW,
    ENCRYPT,
    DECRYPT,
    DIGEST,
    SIGN,
    VERIFY,
    GENERATE,
    GENERATE_KEY_PAIR,
    WRAP,
    UNWRAP,
    DERIVE,
    EC_NAMEDCURVE,
    EC_UNCOMPRESS,
    EC_COMPRESS
}