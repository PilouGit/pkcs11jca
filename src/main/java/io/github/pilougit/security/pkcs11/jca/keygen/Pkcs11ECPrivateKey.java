package io.github.pilougit.security.pkcs11.jca.keygen;

import com.sun.jna.NativeLong;
import io.github.pilougit.security.pkcs11.jca.util.jna.PKCS11Library;
import io.github.pilougit.security.pkcs11.jca.util.jna.PKCS11Structures;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECParameterSpec;

import static io.github.pilougit.security.pkcs11.jca.util.jna.PKCS11Types.CKA_VALUE;
import static io.github.pilougit.security.pkcs11.jca.util.jna.PKCS11Types.CKR_OK;

public class Pkcs11ECPrivateKey implements ECPrivateKey, PrivateKey {

    private final NativeLong keyHandle;
    private final ECParameterSpec params;
    private final PKCS11Library pkcs11;
    private final NativeLong hSession;

    private BigInteger s; // lazy-loaded

    public Pkcs11ECPrivateKey(PKCS11Library pkcs11, NativeLong hSession,NativeLong keyHandle, ECParameterSpec params) {
        this.keyHandle = keyHandle;
        this.params = params;
        this.pkcs11=pkcs11;
        this.hSession=hSession;
    }

    @Override
    public BigInteger getS() {
        if (s == null) {
            PKCS11Structures.CK_ATTRIBUTE[] attrs = new PKCS11Structures.CK_ATTRIBUTE[]{
                    PKCS11Structures.CK_ATTRIBUTE.createByteArrayAttr(CKA_VALUE, new byte[0])
            };
            NativeLong rv = pkcs11.C_GetAttributeValue(
                    hSession,
                    keyHandle,
                    attrs,
                    new NativeLong(attrs.length)
            );
            if (rv != CKR_OK) {
                throw new RuntimeException("C_GetAttributeValue failed: 0x" + Long.toHexString(rv.longValue()));
            }
            byte[] sBytes = attrs[0].pValue.getByteArray(0, (int) attrs[0].ulValueLen.longValue());
            s = new BigInteger(1, sBytes);
        }
        return s;
    }

    @Override
    public ECParameterSpec getParams() {
        return params;
    }

    @Override
    public String getAlgorithm() {
        return "EC";
    }

    @Override
    public String getFormat() {
        return "PKCS11";
    }

    @Override
    public byte[] getEncoded() {
        return null;
    }
}