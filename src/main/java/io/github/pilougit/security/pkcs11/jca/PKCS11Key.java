package io.github.pilougit.security.pkcs11.jca;

import com.sun.jna.NativeLong;

import java.security.Key;

/**
 * Represents a PKCS#11 key stored in a cryptographic token.
 * This class holds a reference to a PKCS#11 key object via its handle.
 */
public class PKCS11Key implements Key {

    private final NativeLong hKey;
    private final String algorithm;
    private final String format;

    public PKCS11Key(NativeLong hKey, String algorithm) {
        this.hKey = hKey;
        this.algorithm = algorithm;
        this.format = null; // PKCS#11 keys are not extractable by default
    }

    /**
     * Returns the PKCS#11 object handle for this key.
     *
     * @return the key handle
     */
    public NativeLong getHandle() {
        return hKey;
    }

    @Override
    public String getAlgorithm() {
        return algorithm;
    }

    @Override
    public String getFormat() {
        return format;
    }

    @Override
    public byte[] getEncoded() {
        // PKCS#11 keys are typically non-extractable
        return null;
    }

    @Override
    public String toString() {
        return "PKCS11Key[algorithm=" + algorithm + ", handle=" + hKey.longValue() + "]";
    }

    /**
     * PKCS#11 Public Key.
     */
    public static class PublicKey extends PKCS11Key implements java.security.PublicKey {
        public PublicKey(NativeLong hKey, String algorithm) {
            super(hKey, algorithm);
        }
    }

    /**
     * PKCS#11 Private Key.
     */
    public static class PrivateKey extends PKCS11Key implements java.security.PrivateKey {
        public PrivateKey(NativeLong hKey, String algorithm) {
            super(hKey, algorithm);
        }
    }
}
