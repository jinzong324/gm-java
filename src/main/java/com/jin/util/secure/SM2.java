package com.jin.util.secure;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithID;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.Security;

public class SM2 {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    static final String USER_ID = "4153938967598525";

    /**
     * 加密
     *
     * @param input
     * @param publicKey
     * @return 加密后的Hex
     */
    public static String encrypt(String input, String publicKey) {
        if (input == null || "".equals(input)) {
            return null;
        }
        if (publicKey == null || "".equals(publicKey)) {
            return input;
        }

        ECPublicKeyParameters ecPublicKeyParameters = SMKeyHelper.publicKeyPair(publicKey);
        byte[] bytes = input.getBytes(StandardCharsets.UTF_8);
        byte[] rb = encrypt(bytes, ecPublicKeyParameters);
        return Hex.toHexString(rb);
    }

    public static byte[] encrypt(byte[] bytes, CipherParameters publicKeyParams) {
        SM2Engine sm2Engine = new SM2Engine(SM2Engine.Mode.C1C3C2);
        try {
            ParametersWithRandom param = new ParametersWithRandom(publicKeyParams, new SecureRandom());
            sm2Engine.init(true, param);
            return sm2Engine.processBlock(bytes, 0, bytes.length);
        } catch (InvalidCipherTextException e) {
            throw new RuntimeException(e);
        }
    }


    /**
     * 解密
     *
     * @param secret
     * @param privateKey
     * @return 解密后的字符串
     */
    public static String decrypt(String secret, String privateKey) {
        if (secret == null || "".equals(secret)) {
            return null;
        }
        if (privateKey == null || "".equals(privateKey)) {
            return secret;
        }

        ECPrivateKeyParameters ecPrivateKeyParameters = SMKeyHelper.privateKeyPair(privateKey);
        byte[] data = Hex.decode(secret);
        byte[] arrayOfBytes = decrypt(data, ecPrivateKeyParameters);
        return new String(arrayOfBytes, StandardCharsets.UTF_8);
    }

    public static byte[] decrypt(byte[] data, CipherParameters privateKeyParams) {
        SM2Engine sm2Engine = new SM2Engine(SM2Engine.Mode.C1C3C2);
        try {
            sm2Engine.init(false, privateKeyParams);
            return sm2Engine.processBlock(data, 0, data.length);
        } catch (InvalidCipherTextException e) {
            throw new RuntimeException(e);
        }
    }

    public static String sign(String input, String privateKey) {
        if (null == input) {
            return null;
        }
        ECPrivateKeyParameters ecPrivateKeyParameters = SMKeyHelper.privateKeyPair(privateKey);
        byte[] bytes = sign(input.getBytes(StandardCharsets.UTF_8), ecPrivateKeyParameters);
        return Hex.toHexString(bytes);
    }

    public static byte[] sign(byte[] data, CipherParameters privateKeyParams) {
        SM2Signer signer = new SM2Signer();
        try {
            CipherParameters param = new ParametersWithID(privateKeyParams, USER_ID.getBytes(StandardCharsets.UTF_8));
            signer.init(true, param);
            signer.update(data, 0, data.length);
            return signer.generateSignature();
        } catch (CryptoException e) {
            throw new RuntimeException(e);
        }
    }

    public static boolean verify(String input, String sign, String publicKey) {
        ECPublicKeyParameters ecPublicKeyParameters = SMKeyHelper.publicKeyPair(publicKey);
        return verify(input.getBytes(StandardCharsets.UTF_8), Hex.decodeStrict(sign), ecPublicKeyParameters);
    }

    public static boolean verify(byte[] data, byte[] sign, CipherParameters publicKeyParams) {
        final SM2Signer signer = new SM2Signer();
        CipherParameters param = new ParametersWithID(publicKeyParams, USER_ID.getBytes(StandardCharsets.UTF_8));

        signer.init(false, param);
        signer.update(data, 0, data.length);
        return signer.verifySignature(sign);
    }
}
