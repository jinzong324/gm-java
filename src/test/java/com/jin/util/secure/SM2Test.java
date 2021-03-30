package com.jin.util.secure;

import org.junit.Before;
import org.junit.Test;

import java.util.UUID;

public class SM2Test {

    String publicKey = "";
    String privateKey = "";

    @Before
    public void before() {
        publicKey = "048c73a66919e2915a403f182bd39cda9e1fa66c3dedeb42616abebd296084b165dea21205f1a3ba2953c9c962624ece93a2b6a88a59b897b253beb78145e52094";
        privateKey = "37c42cffad7064f2684c8e92fd04d5b0328c80ec0ed48311b2167e243c1ee3ad";
    }

    @Test
    public void testEncrypt() {
        String source = "my password";

        String sm2Str = SM2.encrypt(source, publicKey);
        System.out.println("after encrypt: " + sm2Str);

    }

    @Test
    public void testDecrypt() {
        String secret = "0494113519af841b43880c2396f31b47c81857da58eb57d53bc0c3c8c5618ed7d7673fbb6e55b6890a65a6c8be749ff63beb937d93fc6193324674dd454b3570f985dd1c9aaa239ad6a188aa31886185355758cc48ee8c648d65e8c7436eaae21496ae794bcb39e01f861240";
        String decryptStr = SM2.decrypt(secret, privateKey);
        System.out.println("after decrypt : " + decryptStr);
    }

    @Test
    public void testUUID() {
        String uuid = UUID.randomUUID().toString().replace("-", "");
        System.out.println(uuid);
        long timestamp = System.currentTimeMillis() / 1000;
        System.out.println(timestamp);

    }

    @Test
    public void testSign() {
        String input = "input message";
        String sign = SM2.sign(input, privateKey);
        System.out.println(sign);
    }

    @Test
    public void testVerify() {
        String input = "input message";
        String sign = "3045022100df6070938249716f16cc35a4d098e0c5dc994742fa5c80c49ee24f88657dab3002205494618033053e8a5389e175fd57dd9f69c509a619c2d8ca9adf13c676b10fd1";
        boolean result = SM2.verify(input, sign, publicKey);
        System.out.println(result);
    }
}
