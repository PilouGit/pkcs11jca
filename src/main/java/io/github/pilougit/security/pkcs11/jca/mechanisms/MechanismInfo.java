package io.github.pilougit.security.pkcs11.jca.mechanisms;

import java.util.EnumSet;

public final class MechanismInfo {

    private final int minKeySize;
    private final int maxKeySize;
    private final EnumSet<MechanismFlag> flags;

    public MechanismInfo(
            int minKeySize,
            int maxKeySize,
            EnumSet<MechanismFlag> flags
    ) {
        this.minKeySize = minKeySize;
        this.maxKeySize = maxKeySize;
        this.flags = flags.clone();
    }

    public int minKeySize() {
        return minKeySize;
    }

    public int maxKeySize() {
        return maxKeySize;
    }

    public boolean supports(MechanismFlag flag) {
        return flags.contains(flag);
    }

    public boolean canEncrypt() {
        return flags.contains(MechanismFlag.ENCRYPT);
    }

    public boolean canDecrypt() {
        return flags.contains(MechanismFlag.DECRYPT);
    }

    public boolean canDerive() {
        return flags.contains(MechanismFlag.DERIVE);
    }

    public boolean canGenerateKeyPair() {
        return flags.contains(MechanismFlag.GENERATE_KEY_PAIR);
    }

    @Override
    public String toString() {
        return "MechanismInfo{" +
                "minKeySize=" + minKeySize +
                ", maxKeySize=" + maxKeySize +
                ", flags=" + flags +
                '}';
    }
}