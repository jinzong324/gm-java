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

import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.Security;


public class SM2KeyHelper {

    static{
        Security.addProvider(new BouncyCastleProvider());
    }

    public static final X9ECParameters ecParameters = GMNamedCurves.getByName("sm2p256v1");
    public static final ECDomainParameters DOMAIN_PARAMS = new ECDomainParameters(ecParameters.getCurve(), ecParameters.getG(), ecParameters.getN());


    /**
     * 生成公私钥
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
     * @param keyPair
     * @return String
     */
    public static String getHexPublicKey(AsymmetricCipherKeyPair keyPair){
        ECPoint ecPoint = ((ECPublicKeyParameters) keyPair.getPublic()).getQ();
        String hexPublicKey = Hex.toHexString(ecPoint.getEncoded(false));
        return hexPublicKey;
//        return buildECPublicKeyParameters(sm2KeyPair.getPublicKeyX(), sm2KeyPair.getPublicKeyY());
//        return buildECPublicKeyParameters(sm2KeyPair.getPublicKeyX(), sm2KeyPair.getPublicKeyY());
    }

    public static String getBase64PublicKey(AsymmetricCipherKeyPair keyPair){
        ECPoint ecPoint = ((ECPublicKeyParameters) keyPair.getPublic()).getQ();
        String publicKey = new String(Base64.encode(ecPoint.getEncoded(false)));
        return  publicKey;
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
     * @param keyPair
     * @return String
     */
    public static String getHexPrivateKey(AsymmetricCipherKeyPair keyPair){
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

    public static ECPrivateKeyParameters privateKeyPair(String privateKey){
        return new ECPrivateKeyParameters(new BigInteger(privateKey, 16), DOMAIN_PARAMS);
    }

}
