package io.github.pilougit.security.pkcs11.jca.random;

import com.sun.jna.NativeLong;
import io.github.pilougit.security.pkcs11.jca.util.jna.PKCS11Library;

import java.security.SecureRandomSpi;

public class PKCS11SecureRandomSpi extends SecureRandomSpi {

    private final PKCS11Library pkcs11;
    private final NativeLong hSession;

    public PKCS11SecureRandomSpi(PKCS11Library pkcs11, NativeLong hSession) {
        this.pkcs11 = pkcs11;
        this.hSession = hSession;
    }

    @Override
    protected void engineSetSeed(byte[] seed) {
        if (seed == null || seed.length == 0) return;

        NativeLong rc = pkcs11.C_SeedRandom(
                hSession,
                seed,
                new NativeLong(seed.length)
        );

        if (!rc.equals(new NativeLong(0))) { // CKR_OK = 0
            throw new RuntimeException("C_SeedRandom failed: " + rc);
        }
    }

    @Override
    protected void engineNextBytes(byte[] bytes) {
        NativeLong rc = pkcs11.C_GenerateRandom(
                hSession,
                bytes,
                new NativeLong(bytes.length)
        );

        if (!rc.equals(new NativeLong(0))) {
            throw new RuntimeException("C_GenerateRandom failed: " + rc);
        }
    }

    @Override
    protected byte[] engineGenerateSeed(int numBytes) {
        byte[] seed = new byte[numBytes];
        engineNextBytes(seed);
        return seed;
    }
}