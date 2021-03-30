package com.jin.util.secure;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.junit.Test;

import javax.crypto.SecretKey;

public class SMKeyHelperTest {

    @Test
    public void buildKey() {


        AsymmetricCipherKeyPair keyPair = SMKeyHelper.generateKeyPair();
        String publicKey = SMKeyHelper.getHexPublicKey(keyPair);
        String privateKey = SMKeyHelper.getHexPrivateKey(keyPair);
        System.out.println("hex publicKey: " + publicKey);
        System.out.println("hex privateKey: " + privateKey);
        System.out.println("base64 publicKey: " + SMKeyHelper.getBase64PublicKey(keyPair));
        System.out.println("base64 privateKey: " + SMKeyHelper.getBase64PrivateKey(keyPair));


        System.out.println("------------------------------");
        System.out.println("revert key and rebuild");
//        cn.hutool.crypto.asymmetric.SM2 sm2 = SmUtil.sm2(privateKey, publicKey);

        ECPublicKeyParameters ecPublicKeyParameters = SMKeyHelper.publicKeyPair(publicKey);
        System.out.println("hex publicKey: " + Hex.toHexString(ecPublicKeyParameters.getQ().getEncoded(false)));

        ECPrivateKeyParameters ecPrivateKeyParameters = SMKeyHelper.privateKeyPair(privateKey);
        System.out.println("hex privateKey: " + ecPrivateKeyParameters.getD().toString(16));

    }


    @Test
    public void testGenerateKey() {
//        SecureRandom random = new SecureRandom("stq123".getBytes());
//        f5082c08b8f2545171862e4293c79474
        SecretKey secretKey = SMKeyHelper.generateKey();
        String key = Hex.toHexString(secretKey.getEncoded());
        System.out.println(key);
        Assert.assertEquals(key.length(), 32);

    }
}
