package com.jin.util.secure;


import org.junit.Test;

public class SM3Test {

    @Test
    public void testSign() throws Exception {
        String source = "sm3 test";
        String sd = SM3.digest(source);
        System.out.println(sd);

    }
}
