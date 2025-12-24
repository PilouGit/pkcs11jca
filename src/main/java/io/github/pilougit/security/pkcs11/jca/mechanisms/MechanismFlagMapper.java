package io.github.pilougit.security.pkcs11.jca.mechanisms;

import io.github.pilougit.security.pkcs11.jca.util.jna.CKF;

import java.util.EnumSet;

public class MechanismFlagMapper {
    public static EnumSet<MechanismFlag> from(long flags) {

        EnumSet<MechanismFlag> set = EnumSet.noneOf(MechanismFlag.class);

        if ((flags & CKF.CKF_HW) != 0) set.add(MechanismFlag.HW);
        if ((flags & CKF.CKF_ENCRYPT) != 0) set.add(MechanismFlag.ENCRYPT);
        if ((flags & CKF.CKF_DECRYPT) != 0) set.add(MechanismFlag.DECRYPT);
        if ((flags & CKF.CKF_DIGEST) != 0) set.add(MechanismFlag.DIGEST);
        if ((flags & CKF.CKF_SIGN) != 0) set.add(MechanismFlag.SIGN);
        if ((flags & CKF.CKF_VERIFY) != 0) set.add(MechanismFlag.VERIFY);
        if ((flags & CKF.CKF_GENERATE) != 0) set.add(MechanismFlag.GENERATE);
        if ((flags & CKF.CKF_GENERATE_KEY_PAIR) != 0)
            set.add(MechanismFlag.GENERATE_KEY_PAIR);
        if ((flags & CKF.CKF_WRAP) != 0) set.add(MechanismFlag.WRAP);
        if ((flags & CKF.CKF_UNWRAP) != 0) set.add(MechanismFlag.UNWRAP);
        if ((flags & CKF.CKF_DERIVE) != 0) set.add(MechanismFlag.DERIVE);
        if ((flags & CKF.CKF_EC_NAMEDCURVE) != 0)
            set.add(MechanismFlag.EC_NAMEDCURVE);

        return set;
    }
}
