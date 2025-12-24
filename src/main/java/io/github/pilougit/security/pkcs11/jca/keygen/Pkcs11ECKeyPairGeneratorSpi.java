package io.github.pilougit.security.pkcs11.jca.keygen;

import com.sun.jna.NativeLong;
import io.github.pilougit.security.pkcs11.jca.util.helpers.ECCHelper;
import io.github.pilougit.security.pkcs11.jca.util.jna.PKCS11Helper;
import io.github.pilougit.security.pkcs11.jca.util.jna.PKCS11Library;

import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;

public class Pkcs11ECKeyPairGeneratorSpi extends KeyPairGeneratorSpi {

    private final PKCS11Library pkcs11;
    private final NativeLong hSession;
    private byte[] ecParams = ECCHelper.P256_OID_DER;
    private String ecName;

    public Pkcs11ECKeyPairGeneratorSpi(PKCS11Library pkcs11, NativeLong hSession) {
        this.pkcs11 = pkcs11;
        this.hSession = hSession;
    }

    @Override
    public void initialize(int keysize, SecureRandom random) {
        try {
            ecParams = ECCHelper.getCurveParamsBySize(keysize);
        } catch (IllegalArgumentException e) {
            throw new InvalidParameterException(e.getMessage());
        }
    }

    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException {

        if (!(params instanceof ECGenParameterSpec ec)) {
            throw new InvalidAlgorithmParameterException("Expected ECGenParameterSpec");
        }

        try {
            ecParams = ECCHelper.getCurveParams(ec.getName());
            ecName = ec.getName();
        } catch (IllegalArgumentException e) {
            throw new InvalidAlgorithmParameterException(e.getMessage());
        }
    }
    private ECParameterSpec curveNameToSpec(String curveName) {
        try {
            ECGenParameterSpec ecSpec = new ECGenParameterSpec(curveName);
            AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
            params.init(ecSpec);
            return params.getParameterSpec(ECParameterSpec.class);
        } catch (Exception e) {
            throw new IllegalArgumentException("Unsupported curve: " + curveName, e);
        }}
    @Override
    public KeyPair generateKeyPair() {
        try {
            // Generate EC key pair using ECCHelper
            NativeLong[] keys = ECCHelper.generateECKeyPair(
                    pkcs11,
                    hSession,
                    ecParams,
                    true,  // canVerify
                    true,  // canSign
                    true   // isPrivate
            );

            NativeLong hPublicKey = keys[0];
            NativeLong hPrivateKey = keys[1];

            // Convert curve name to ECParameterSpec
            ECParameterSpec ecSpec = curveNameToSpec(ecName);

            // Create key objects
            PublicKey pub = new Pkcs11ECPublicKey(pkcs11, hSession, hPublicKey, ecSpec);
            PrivateKey priv = new Pkcs11ECPrivateKey(pkcs11, hSession, hPrivateKey, ecSpec);

            return new KeyPair(pub, priv);

        } catch (PKCS11Helper.PKCS11Exception e) {
            throw new ProviderException("EC key pair generation failed: " + e.getMessage(), e);
        }
    }
}