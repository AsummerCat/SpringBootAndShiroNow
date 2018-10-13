package com.linjingc.demo.shiro;

import lombok.extern.slf4j.Slf4j;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authc.credential.SimpleCredentialsMatcher;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.springframework.beans.factory.annotation.Value;

/**
 * @author cxc
 * 自定义密码校验器
 * 加盐校验
 */
@Slf4j
public class CredentialsSaltMatcher extends SimpleCredentialsMatcher {
    @Value("${shiro.encrypt.type}")
    private String encryptType;
    @Value("${shiro.HashIterations}")
    private int hashIterations;
    @Value("${shiro.salt}")
    private String shiroSalt;

    /**
     * 自定义密码校验器
     */
    @Override
    public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) {

        log.info("进入自定义密码加盐校验器");
        UsernamePasswordToken utoken = (UsernamePasswordToken) token;
        //获得用户输入的密码:(可以采用加盐(salt)的方式去检验)
        String inPassword = new SimpleHash(encryptType, utoken.getPassword(), utoken.getUsername() + shiroSalt, hashIterations).toString();

        //获得数据库中的密码
        String dbPassword = (String) info.getCredentials();

        //进行密码的比对
        boolean flag = this.equals(inPassword, dbPassword);
        return flag;
    }
}