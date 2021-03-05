package com.jin.util.secure;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

public class SM2KeyHelperTest {

    @Test
    public void buildKey(){
        AsymmetricCipherKeyPair keyPair = SM2KeyHelper.generateKeyPair();
        String publicKey = SM2KeyHelper.getHexPublicKey(keyPair);
        String privateKey = SM2KeyHelper.getHexPrivateKey(keyPair);
        System.out.println("hex publicKey: " + publicKey);
        System.out.println("hex privateKey: " + privateKey);

        System.out.println("------------------------------");
        System.out.println("revert key and rebuild");
        ECPublicKeyParameters ecPublicKeyParameters = SM2KeyHelper.publicKeyPair(publicKey);
        System.out.println("hex publicKey: " + Hex.toHexString(ecPublicKeyParameters.getQ().getEncoded(false)));

        ECPrivateKeyParameters ecPrivateKeyParameters = SM2KeyHelper.privateKeyPair(privateKey);
        System.out.println("hex privateKey: " + ecPrivateKeyParameters.getD().toString(16));

    }
}
