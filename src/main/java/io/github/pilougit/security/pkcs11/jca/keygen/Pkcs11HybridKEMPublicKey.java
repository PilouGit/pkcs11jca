package io.github.pilougit.security.pkcs11.jca.keygen;

import com.sun.jna.NativeLong;
import io.github.pilougit.security.pkcs11.jca.util.jna.PKCS11Library;

import java.security.PublicKey;

/**
 * PKCS#11-backed Hybrid KEM Public Key.
 * Represents a hybrid post-quantum KEM public key stored in a PKCS#11 token.
 *
 * Supported hybrid algorithms:
 * - ML-KEM-768 + ECDH P-256
 * - ML-KEM-1024 + ECDH P-384
 * - ML-KEM-768 + X25519
 */
public class Pkcs11HybridKEMPublicKey implements PublicKey {

    private static final long serialVersionUID = 1L;

    private final PKCS11Library pkcs11;
    private final NativeLong session;
    private final NativeLong handle;
    private final String algorithm;

    /**
     * Creates a new Hybrid KEM public key.
     *
     * @param pkcs11    PKCS#11 library instance
     * @param session   Session handle
     * @param handle    Object handle for the public key
     * @param algorithm Algorithm name (e.g., "MLKEM768-ECDH-P256")
     */
    public Pkcs11HybridKEMPublicKey(PKCS11Library pkcs11, NativeLong session, NativeLong handle, String algorithm) {
        this.pkcs11 = pkcs11;
        this.session = session;
        this.handle = handle;
        this.algorithm = algorithm;
    }

    @Override
    public String getAlgorithm() {
        return algorithm;
    }

    @Override
    public String getFormat() {
        return null; // PKCS#11 keys don't have a standard encoding format
    }

    @Override
    public byte[] getEncoded() {
        return null; // PKCS#11 keys are not directly exportable
    }

    /**
     * Get the PKCS#11 object handle for this public key.
     *
     * @return Object handle
     */
    public NativeLong getHandle() {
        return handle;
    }

    /**
     * Get the PKCS#11 session handle.
     *
     * @return Session handle
     */
    public NativeLong getSession() {
        return session;
    }

    /**
     * Get the PKCS#11 library instance.
     *
     * @return PKCS#11 library
     */
    public PKCS11Library getPkcs11() {
        return pkcs11;
    }

    @Override
    public String toString() {
        return "Pkcs11HybridKEMPublicKey{" +
                "algorithm='" + algorithm + '\'' +
                ", handle=" + handle.longValue() +
                '}';
    }
}
