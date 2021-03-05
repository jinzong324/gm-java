package com.jin.util.secure;

import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import java.security.Security;

public class SM3 {
    static{
        Security.addProvider(new BouncyCastleProvider());
    }

    public static String digest(String source) throws Exception{
        byte[] input = source.getBytes("utf-8");
        SM3Digest sm3Digest = new SM3Digest();
        sm3Digest.update(input, 0, input.length);
        byte[] ret = new byte[sm3Digest.getDigestSize()];
        sm3Digest.doFinal(ret, 0);
        return Hex.toHexString(ret);
    }

}
