package io.github.pilougit.security.pkcs11.jca;

import io.github.pilougit.security.pkcs11.jca.util.jna.PKCS11Structures;

import java.nio.charset.StandardCharsets;
import java.util.Objects;

public final class Pkcs11Info {

    private final Version cryptokiVersion;
    private final String manufacturerId;
    private final long flags;
    private final String libraryDescription;
    private final Version libraryVersion;

    private Pkcs11Info(
            Version cryptokiVersion,
            String manufacturerId,
            long flags,
            String libraryDescription,
            Version libraryVersion) {

        this.cryptokiVersion = cryptokiVersion;
        this.manufacturerId = manufacturerId;
        this.flags = flags;
        this.libraryDescription = libraryDescription;
        this.libraryVersion = libraryVersion;
    }

    /* ========= Factory ========= */

    public static Pkcs11Info from(PKCS11Structures.CK_INFO info) {
        Objects.requireNonNull(info, "CK_INFO");

        return new Pkcs11Info(
                Version.from(info.cryptokiVersion),
                decodePkcs11String(info.manufacturerID),
                info.flags.longValue(),
                decodePkcs11String(info.libraryDescription),
                Version.from(info.libraryVersion)
        );
    }

    /* ========= Getters ========= */

    public Version cryptokiVersion() {
        return cryptokiVersion;
    }

    public String manufacturerId() {
        return manufacturerId;
    }

    public long flags() {
        return flags;
    }

    public String libraryDescription() {
        return libraryDescription;
    }

    public Version libraryVersion() {
        return libraryVersion;
    }

    /* ========= Helpers ========= */

    private static String decodePkcs11String(byte[] bytes) {
        // PKCS#11: ASCII padded with spaces
        int len = bytes.length;
        while (len > 0 && bytes[len - 1] == ' ') {
            len--;
        }
        return new String(bytes, 0, len, StandardCharsets.US_ASCII);
    }

    @Override
    public String toString() {
        return "Pkcs11Info{" +
                "cryptokiVersion=" + cryptokiVersion +
                ", manufacturerId='" + manufacturerId + '\'' +
                ", flags=0x" + Long.toHexString(flags) +
                ", libraryDescription='" + libraryDescription + '\'' +
                ", libraryVersion=" + libraryVersion +
                '}';
    }
}