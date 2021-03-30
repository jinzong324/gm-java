package com.jin.util.secure;

import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import java.nio.charset.StandardCharsets;
import java.security.Security;

public class SM3 {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static String digest(String input) {
        if (null == input || input.length() == 0) {
            return null;
        }
        byte[] bytes = digest(input.getBytes(StandardCharsets.UTF_8));
        return Hex.toHexString(bytes);
    }

    public static byte[] digest(byte[] bytes) {
        if (null == bytes) {
            return null;
        }
        SM3Digest sm3Digest = new SM3Digest();
        sm3Digest.update(bytes, 0, bytes.length);
        byte[] ret = new byte[sm3Digest.getDigestSize()];
        sm3Digest.doFinal(ret, 0);
        return ret;
    }

}
