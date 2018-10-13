package com.linjingc.demo.shiro;

import lombok.extern.slf4j.Slf4j;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authc.credential.SimpleCredentialsMatcher;

/**
 * @author cxc
 * 自定义密码校验器
 * 简单密码对比校验
 */
@Slf4j
public class CredentialsMatcher extends SimpleCredentialsMatcher {

    /**
     * 自定义密码校验器
     */
    @Override
    public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) {

        log.info("进入自定义密码校验器");
        UsernamePasswordToken utoken = (UsernamePasswordToken) token;
        //获得用户输入的密码:(可以采用加盐(salt)的方式去检验)
        String inPassword = new String(utoken.getPassword());
        //获得数据库中的密码
        String dbPassword = (String) info.getCredentials();
        //进行密码的比对
        boolean flag = this.equals(inPassword, dbPassword);
        return flag;
    }


}