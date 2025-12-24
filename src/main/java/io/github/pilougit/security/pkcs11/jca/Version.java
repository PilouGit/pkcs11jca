package io.github.pilougit.security.pkcs11.jca;

import io.github.pilougit.security.pkcs11.jca.util.jna.PKCS11Structures;

import java.util.Objects;

public class Version {

    public  int major;
    public int minor;

    public Version(int major,int minor) {
        this.major = major;
        this.minor=minor;
    }

    public static Version from(PKCS11Structures.CK_VERSION v) {
        Objects.requireNonNull(v);
        return new Version(
                Byte.toUnsignedInt(v.major),
                Byte.toUnsignedInt(v.minor)
        );
    }

    @Override
    public String toString() {
        return major + "." + minor;
    }
}