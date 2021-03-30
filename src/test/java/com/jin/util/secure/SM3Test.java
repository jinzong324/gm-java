package com.jin.util.secure;


import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.junit.Test;

import java.nio.charset.StandardCharsets;

public class SM3Test {

    @Test
    public void testDigest() {
        String source = "d546a14308fd209035695ed993e2c785";
        String digest = SM3.digest(source);
        System.out.println(digest);

        byte[] bytes = SM3.digest(source.getBytes(StandardCharsets.UTF_8));
        String sign = Hex.toHexString(bytes);
        System.out.println(sign);

        Assert.assertEquals(digest, sign);
    }

    @Test
    public void testRandom() {
        int length = 16;
        String result = "";
        for (int i = 0; i < length; i++) {
//            Random random = new Random();
            int r = (int) (Math.random() * 10);
            result = result + r;
        }
        System.out.println(result);
    }
}
