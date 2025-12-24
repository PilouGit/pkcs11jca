package io.github.pilougit.security.pkcs11.jca.keygen;

import com.sun.jna.NativeLong;
import io.github.pilougit.security.pkcs11.jca.util.jna.PKCS11Library;
import io.github.pilougit.security.pkcs11.jca.util.jna.PKCS11Structures;

import java.math.BigInteger;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.util.Arrays;

import static io.github.pilougit.security.pkcs11.jca.util.jna.PKCS11Types.CKA_EC_POINT;
import static io.github.pilougit.security.pkcs11.jca.util.jna.PKCS11Types.CKR_OK;

public class Pkcs11ECPublicKey implements ECPublicKey {

    private final NativeLong keyHandle;
    private final ECParameterSpec params;
    private ECPoint w; // lazy-loaded
    private final PKCS11Library pkcs11;
    private final NativeLong hSession;

    public Pkcs11ECPublicKey(PKCS11Library pkcs11,NativeLong hSession,NativeLong keyHandle, ECParameterSpec params) {
        this.keyHandle = keyHandle;
        this.params = params;
        this.pkcs11=pkcs11;
        this.hSession=hSession;
    }

    @Override
    public ECPoint getW() {
        if (w == null) {
            // Lire CKA_EC_POINT
            PKCS11Structures.CK_ATTRIBUTE[] attrs = new PKCS11Structures.CK_ATTRIBUTE[]{
                    PKCS11Structures.CK_ATTRIBUTE.createByteArrayAttr(CKA_EC_POINT, new byte[0])
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

            byte[] ecPointDer = attrs[0].pValue.getByteArray(0, (int) attrs[0].ulValueLen.longValue());
            byte[] octets = decodeEcPointOctetString(ecPointDer);

            int len = (octets.length - 1) / 2;
            byte[] xBytes = Arrays.copyOfRange(octets, 1, 1 + len);
            byte[] yBytes = Arrays.copyOfRange(octets, 1 + len, octets.length);

            BigInteger x = new BigInteger(1, xBytes);
            BigInteger y = new BigInteger(1, yBytes);
            w = new ECPoint(x, y);
        }
        return w;
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
        return "X.509";
    }

    @Override
    public byte[] getEncoded() {
        // Optional: encoder en SubjectPublicKeyInfo si besoin
        return null;
    }

    private byte[] decodeEcPointOctetString(byte[] der) {
        if (der[0] != 0x04) throw new IllegalArgumentException("Unexpected DER encoding");
        int offset = 2; // strip OCTET STRING wrapper
        int len = der.length - offset;
        byte[] result = new byte[len];
        System.arraycopy(der, offset, result, 0, len);
        return result;
    }
}