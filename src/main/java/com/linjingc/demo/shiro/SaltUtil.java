package com.linjingc.demo.shiro;

import org.apache.shiro.crypto.hash.SimpleHash;
import org.apache.shiro.util.ByteSource;

/**
 * @author cxc
 * @date 2018/10/12 11:42
 * 加盐测试类
 */
public class SaltUtil {
    /**
     * 加盐测试类
     *
     * @param args
     */
    public static void main(String[] args) {
        String user = "admin";
        String hashAlgorithmName = "MD5";//加密方式
        Object crdentials = "a123456";//密码原值
        ByteSource salt = ByteSource.Util.bytes(user + "ABCDEFG");//以账号作为盐值+ABCDEFG
        int hashIterations = 1024;//加密1024次
        Object result = new SimpleHash(hashAlgorithmName, crdentials, salt, hashIterations);
        System.out.println(user + ":" + result);
    }
}
