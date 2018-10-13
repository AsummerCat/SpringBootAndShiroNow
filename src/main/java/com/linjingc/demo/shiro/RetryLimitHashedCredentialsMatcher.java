package com.linjingc.demo.shiro;

import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.ExcessiveAttemptsException;
import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.cache.Cache;
import org.apache.shiro.cache.CacheManager;
import org.springframework.beans.factory.annotation.Value;

import java.util.concurrent.atomic.AtomicInteger;

/**
 * @author cxc
 * 自定义密码校验器误次数
 */
public class RetryLimitHashedCredentialsMatcher extends HashedCredentialsMatcher {
    private Cache<String, AtomicInteger> passwordRetryCache;

    @Value("${shiro.password.error.size}")
    private int passwordErrorSize;

    public RetryLimitHashedCredentialsMatcher(CacheManager cacheManager) {
        //用于记录缓存的名称 passwordRetryCache
        passwordRetryCache = cacheManager.getCache("passwordRetryCache");
    }

    @Override
    public boolean doCredentialsMatch(AuthenticationToken token,
                                      AuthenticationInfo info) {
        String username = (String) token.getPrincipal();
        // retry count + 1  
        AtomicInteger retryCount = passwordRetryCache.get(username);
        if (retryCount == null) {
            retryCount = new AtomicInteger(0);
            passwordRetryCache.put(username, retryCount);
        }
        if (retryCount.incrementAndGet() > passwordErrorSize) {
            // if retry count > 5 throw
            //超出定义的错误次数后 抛出一个异常
            throw new ExcessiveAttemptsException("密码错误次数达到上限,输入正确密码即可清除上限");
        }


        boolean matches = super.doCredentialsMatch(token, info);
        if (matches) {

            //密码输入正确后清除缓存 其实如果被定义了密码错误上限应该等时间到了之后解开
            // clear retry count  
            passwordRetryCache.remove(username);
        }
        return matches;
    }

}
