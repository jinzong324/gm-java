package com.jin.util.secure;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Before;
import org.junit.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Provider;
import java.security.SecureRandom;

public class SM4Test {

    String hexKey = null;

    @Before
    public void before() {
        hexKey = "f5082c08b8f2545171862e4293c79474";
    }

    @Test
    public void testGenKey() throws Exception {
        final Provider provider = new BouncyCastleProvider();
        KeyGenerator keyGenerator = KeyGenerator.getInstance("SM4", provider);
        SecureRandom random = new SecureRandom("stq123".getBytes());
        keyGenerator.init(256, random);
        SecretKey secretKey = keyGenerator.generateKey();
        String key = Hex.toHexString(secretKey.getEncoded());
        System.out.println(key);
        //
//        String BKey = Base64.toBase64String(secretKey.getEncoded());
//        System.out.println(BKey);
        byte[] sm3 = SM3.digest(secretKey.getEncoded());
        SecretKey secretKey1 = new SecretKeySpec(sm3, "SM4");
        System.out.println(Hex.toHexString(sm3));

    }


    @Test
    public void testEncrypt() {
        String str = "my password";

        byte[] bytes = SM4.encrypt(str.getBytes(StandardCharsets.UTF_8), Hex.decodeStrict(hexKey));
        String sm4HexStr = Hex.toHexString(bytes);
        String sm4Base64Str = Base64.toBase64String(bytes);
        System.out.println("hex: " + sm4HexStr);
        System.out.println("base64: " + sm4Base64Str);
    }

    @Test
    public void testEncrypt2() {
        String str = "my password";
        String sm3HexKey = SM3.digest(hexKey);

        byte[] bytes = SM4.encrypt(str.getBytes(StandardCharsets.UTF_8), Hex.decodeStrict(sm3HexKey));
        String sm4HexStr = Hex.toHexString(bytes);
        String sm4Base64Str = Base64.toBase64String(bytes);
        System.out.println("hex: " + sm4HexStr);
        System.out.println("base64: " + sm4Base64Str);
    }

    @Test
    public void testDecrypt() {
        String sm4HexStr = "2fb124bd3a91bf3fe96371a0b28e95c8";
        byte[] bytes = SM4.decrypt(Hex.decodeStrict(sm4HexStr), Hex.decodeStrict(hexKey));
        String sourceStr = new String(bytes, StandardCharsets.UTF_8);
        System.out.println("decrypt hex str: " + sourceStr);

        String sm4Base64Str = "L7EkvTqRvz/pY3Ggso6VyA==";
        byte[] bytes2 = SM4.decrypt(Base64.decode(sm4Base64Str), Hex.decodeStrict(hexKey));
        String sourceStr2 = new String(bytes2, StandardCharsets.UTF_8);
        System.out.println("decrypt base64 str: " + sourceStr2);


    }
}
