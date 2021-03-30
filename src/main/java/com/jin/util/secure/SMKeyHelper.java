package com.jin.util.secure;

import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;


public class SMKeyHelper {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final X9ECParameters ecParameters = GMNamedCurves.getByName("sm2p256v1");
    private static final ECDomainParameters DOMAIN_PARAMS = new ECDomainParameters(ecParameters.getCurve(), ecParameters.getG(), ecParameters.getN());


    public static final String ALGORITHM_SM4 = "SM4";

    public static final int KEY_SIZE_DEFAULT = 128;


    /**
     * 生成公私钥
     *
     * @return AsymmetricCipherKeyPair
     */
    public static AsymmetricCipherKeyPair generateKeyPair() {
        SecureRandom random = new SecureRandom();
        ECKeyGenerationParameters keyGenerationParams = new ECKeyGenerationParameters(DOMAIN_PARAMS, random);
        ECKeyPairGenerator keyGen = new ECKeyPairGenerator();
        keyGen.init(keyGenerationParams);

        AsymmetricCipherKeyPair keyPair = keyGen.generateKeyPair();
        return keyPair;


//        ECPublicKeyParameters ecPublicKeyParameters = (ECPublicKeyParameters) keyPair.getPublic();
//        ECPrivateKeyParameters ecPrivateKeyParameters = (ECPrivateKeyParameters) keyPair.getPrivate();
//
//        return new SM2KeyPair(ecPublicKeyParameters.getQ().getAffineXCoord().getEncoded(), ecPublicKeyParameters.getQ().getAffineYCoord().getEncoded(), ecPrivateKeyParameters.getD().toByteArray());
    }

    /**
     * 获取公钥Hex
     *
     * @param keyPair 公私钥对
     * @return String
     */
    public static String getHexPublicKey(AsymmetricCipherKeyPair keyPair) {
        ECPoint ecPoint = ((ECPublicKeyParameters) keyPair.getPublic()).getQ();
        String hexPublicKey = Hex.toHexString(ecPoint.getEncoded(false));
        return hexPublicKey;
//        return buildECPublicKeyParameters(sm2KeyPair.getPublicKeyX(), sm2KeyPair.getPublicKeyY());
//        return buildECPublicKeyParameters(sm2KeyPair.getPublicKeyX(), sm2KeyPair.getPublicKeyY());
    }

    public static String getBase64PublicKey(AsymmetricCipherKeyPair keyPair) {
        ECPoint ecPoint = ((ECPublicKeyParameters) keyPair.getPublic()).getQ();
        String publicKey = new String(Base64.encode(ecPoint.getEncoded(false)));
        return publicKey;
    }

//    /**
//     * 构建公钥参数
//     * @param publicKeyX
//     * @param publicKeyY
//     * @return
//     */
//    public static ECPublicKeyParameters buildECPublicKeyParameters(byte[] publicKeyX, byte[] publicKeyY){
//        ECPoint pointQ = SM2Constants.CURVE.createPoint(new BigInteger(1, publicKeyX), new BigInteger(1, publicKeyY));
//        return new ECPublicKeyParameters(pointQ, SM2Constants.DOMAIN_PARAMS);
//    }

//    /**
//     * 构建私钥参数
//     * @param privateKey
//     * @return
//     */
//    public static ECPrivateKeyParameters buildECPrivateKeyParameters(byte[] privateKey){
//        BigInteger d = new BigInteger(1, privateKey);
//        return new ECPrivateKeyParameters(d, SM2Constants.DOMAIN_PARAMS);
//    }

    /**
     * 获取私钥Hex
     *
     * @param keyPair 公私钥对
     * @return String
     */
    public static String getHexPrivateKey(AsymmetricCipherKeyPair keyPair) {
        BigInteger privateKey = ((ECPrivateKeyParameters) keyPair.getPrivate()).getD();
        String hexPrivateKey = privateKey.toString(16);
        return hexPrivateKey;
    }

    public static String getBase64PrivateKey(AsymmetricCipherKeyPair keyPair) {
        BigInteger privateKey = ((ECPrivateKeyParameters) keyPair.getPrivate()).getD();
        String pk = new String(Base64.encode(privateKey.toByteArray()));
        return pk;
    }

    public static ECPublicKeyParameters publicKeyPair(String publicKey) {
        ECPoint ecPoint = ecParameters.getCurve().decodePoint(Hex.decode(publicKey));
        return new ECPublicKeyParameters(ecPoint, DOMAIN_PARAMS);
    }

    public static ECPrivateKeyParameters privateKeyPair(String privateKey) {
        return new ECPrivateKeyParameters(new BigInteger(privateKey, 16), DOMAIN_PARAMS);
    }


    /**
     * 生成SM4算法密钥
     *
     * @return {@link SecretKey}
     */
    public static SecretKey generateKey() {
        return generateKey(KEY_SIZE_DEFAULT);
    }

    /**
     * 生成SM4算法密钥
     *
     * @param keySize 密钥长度
     * @return {@link SecretKey}
     */
    public static SecretKey generateKey(int keySize) {
        return generateKey(keySize, null);
    }

    /**
     * 生成SM4算法密钥
     *
     * @param keySize 密钥长度
     * @param random  随机数生成器，null表示默认
     * @return {@link SecretKey}
     */
    public static SecretKey generateKey(int keySize, SecureRandom random) {
        SecretKey secretKey = null;
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM_SM4);
//            SecureRandom random = new SecureRandom("stq123".getBytes());
            if (keySize > 0) {
                if (null == random) {
                    keyGenerator.init(keySize);
                } else {
                    keyGenerator.init(keySize, random);
                }
            }
            secretKey = keyGenerator.generateKey();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        return secretKey;
    }

}
