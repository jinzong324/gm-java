package com.jin.util.secure;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Provider;
import java.security.Security;

public class SM4 {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }


    public static String encryptHex(String data, String key) {
        return Hex.toHexString(encrypt(data.getBytes(StandardCharsets.UTF_8), Hex.decodeStrict(key)));
    }

    /**
     * 加密
     *
     * @param data 被加密的数据
     * @param key  密钥
     * @return 加密后的bytes
     */
    public static byte[] encrypt(byte[] data, byte[] key) {
        SecretKeySpec secretKey = new SecretKeySpec(key, SMKeyHelper.ALGORITHM_SM4);
        return encrypt(data, secretKey);
    }


    /**
     * 加密
     *
     * @param data      被加密的数据
     * @param secretKey 密钥
     * @return 加密后的bytes
     */
    public static byte[] encrypt(byte[] data, SecretKey secretKey) {
        final Provider provider = new BouncyCastleProvider();
        try {
            Cipher cipher = Cipher.getInstance(SMKeyHelper.ALGORITHM_SM4, provider);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            return cipher.doFinal(data);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static String decryptHex(String secretStr, String key) {
        return new String(decrypt(Hex.decodeStrict(secretStr), Hex.decodeStrict(key)), StandardCharsets.UTF_8);
    }

    /**
     * 解密
     *
     * @param data 要解密的数据
     * @param key  密钥
     * @return 解密后的bytes
     */
    public static byte[] decrypt(byte[] data, byte[] key) {
        SecretKeySpec secretKey = new SecretKeySpec(key, SMKeyHelper.ALGORITHM_SM4);
        return decrypt(data, secretKey);
    }

    /**
     * 解密
     *
     * @param data      要解密的数据
     * @param secretKey 密钥
     * @return 解密后的bytes
     */
    public static byte[] decrypt(byte[] data, SecretKey secretKey) {
        final Provider provider = new BouncyCastleProvider();
        try {
            Cipher cipher = Cipher.getInstance(SMKeyHelper.ALGORITHM_SM4, provider);
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            return cipher.doFinal(data);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

}
