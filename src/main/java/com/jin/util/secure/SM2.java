package com.jin.util.secure;

import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import java.security.SecureRandom;
import java.security.Security;

import static org.bouncycastle.crypto.engines.SM2Engine.Mode.C1C3C2;

public class SM2 {
    static{
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * 加密
     * @param input
     * @param publicKey
     * @return 加密后的Hex
     * @throws Exception
     */
    public static String encrypt(String input, String publicKey) throws Exception {
        if(input == null || "".equals(input)){
            return null;
        }
        if(publicKey == null || "".equals(publicKey)){
            return input;
        }

        SM2Engine sm2Engine = new SM2Engine(C1C3C2);
        ECPublicKeyParameters ecPublicKeyParameters = SM2KeyHelper.publicKeyPair(publicKey);
        ParametersWithRandom parametersWithRandom = new ParametersWithRandom(ecPublicKeyParameters, new SecureRandom());
        sm2Engine.init(true, parametersWithRandom);
        byte[] bytes = input.getBytes("UTF-8");
        byte[] rb = sm2Engine.processBlock(bytes, 0, bytes.length);
        return Hex.toHexString(rb);
    }

    /**
     * 解密
     * @param secret
     * @param privateKey
     * @return 解密后的字符串
     * @throws Exception
     */
    public static String decrypt(String secret, String privateKey) throws Exception {
        if(secret == null || "".equals(secret)){
            return null;
        }
        if(privateKey == null || "".equals(privateKey)){
            return secret;
        }

        SM2Engine sm2Engine = new SM2Engine(C1C3C2);
        ECPrivateKeyParameters ecPrivateKeyParameters = SM2KeyHelper.privateKeyPair(privateKey);
        sm2Engine.init(false, ecPrivateKeyParameters);
        byte[] b = Hex.decode(secret);
        byte[] arrayOfBytes = sm2Engine.processBlock(b, 0, b.length);
        return new String(arrayOfBytes, "UTF-8");
    }

}
