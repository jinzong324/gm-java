package com.jin.util.secure;

import org.junit.Before;
import org.junit.Test;

public class SM2Test {

    String publicKey = "";
    String privateKey = "";

    @Before
    public void before(){
        publicKey = "048c73a66919e2915a403f182bd39cda9e1fa66c3dedeb42616abebd296084b165dea21205f1a3ba2953c9c962624ece93a2b6a88a59b897b253beb78145e52094";
        privateKey = "37c42cffad7064f2684c8e92fd04d5b0328c80ec0ed48311b2167e243c1ee3ad";
    }

    @Test
    public void testEncrypt() throws Exception {
        String source = "my password";

        String sm2Str = SM2.encrypt(source, publicKey);
        System.out.println("after encrypt: " + sm2Str);

    }

    @Test
    public void testDecrypt() throws Exception {
        String secret = "0482e52fb782b1b2c5e34d4f5568906e798af7b54a9d984cc7a89d11f9db93a2e9297793e2d6609b3985e1f64a3d1c58728ad24604347a4b59dc46da7879cf880e49d1ad0499cbca7c92cbac271eed22644fa73db4aeee4e52adc47cdc489f1aade89682fce3240599c13b04";
        String decryptStr = SM2.decrypt(secret, privateKey);
        System.out.println("after decrypt : " + decryptStr);
    }
}
