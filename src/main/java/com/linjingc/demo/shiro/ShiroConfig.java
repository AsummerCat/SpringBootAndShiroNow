package com.linjingc.demo.shiro;

import at.pollux.thymeleaf.shiro.dialect.ShiroDialect;
import lombok.extern.slf4j.Slf4j;
import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.cache.ehcache.EhCacheManager;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.spring.security.interceptor.AuthorizationAttributeSourceAdvisor;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.mgt.CookieRememberMeManager;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.apache.shiro.web.servlet.SimpleCookie;
import org.springframework.aop.framework.autoproxy.DefaultAdvisorAutoProxyCreator;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * @author cxc
 * shiro配置类
 */
@Configuration
@Slf4j
public class ShiroConfig {

    @Value("${shiro.encrypt.type}")
    private String encryptType;
    @Value("${shiro.HashIterations}")
    private int hashIterations;
    @Value("${shiro.rememberMe.Max.time}")
    private int rememberMeMaxTime;


    /**
     * ShiroFilterFactoryBean 处理拦截资源文件问题。
     * 注意：单独一个ShiroFilterFactoryBean配置是或报错的，以为在
     * 初始化ShiroFilterFactoryBean的时候需要注入：SecurityManager
     * <p>
     * Filter Chain定义说明 1、一个URL可以配置多个Filter，使用逗号分隔 2、当设置多个过滤器时，全部验证通过，才视为通过
     * 3、部分过滤器可指定参数，如perms，roles
     */
    @Bean
    public ShiroFilterFactoryBean shirFilter(SecurityManager securityManager) {
        ShiroFilterFactoryBean shiroFilterFactoryBean = new ShiroFilterFactoryBean();
        // 必须设置 SecurityManager 核心
        shiroFilterFactoryBean.setSecurityManager(securityManager);

        // 如果不设置默认会自动寻找Web工程根目录下的"/login.jsp"页面
        //打开页面跳转的地址
        shiroFilterFactoryBean.setLoginUrl("/login");
        // 登录成功后要跳转的链接
        shiroFilterFactoryBean.setSuccessUrl("/index");
        // 未授权界面;
        shiroFilterFactoryBean.setUnauthorizedUrl("/403");
        // 拦截器.
        Map<String, String> filterChainDefinitionMap = new LinkedHashMap<String, String>();
        // 配置不会被拦截的链接 顺序判断
        filterChainDefinitionMap.put("/static/**", "anon");
        filterChainDefinitionMap.put("/index", "anon");
        filterChainDefinitionMap.put("/login", "anon");
        filterChainDefinitionMap.put("/loginUser", "anon");

        // 配置退出过滤器,其中的具体的退出代码Shiro已经替我们实现了
        filterChainDefinitionMap.put("/logout", "logout");

        //配置记住我的访问路径
        filterChainDefinitionMap.put("/success", "user");

        //配置权限
        filterChainDefinitionMap.put("/lo1", "perms[add]");
        filterChainDefinitionMap.put("/lo2", "perms[update]");
        filterChainDefinitionMap.put("/lo3", "perms[delete]");
        filterChainDefinitionMap.put("/lo4", "perms[User],perms[AAA]");
        filterChainDefinitionMap.put("/lo5", "authc,roles[管理员],perms[AAA]");
        // 这里为了测试，固定写死的值，也可以从数据库或其他配置中读取

        //需要通过认证
        filterChainDefinitionMap.put("/hello", "authc");


        // <!-- 过滤链定义，从上向下顺序执行，一般将 /**放在最为下边 -->:这是一个坑呢，一不小心代码就不好使了;
        // <!-- authc:所有url都必须认证通过才可以访问; anon:所有url都都可以匿名访问-->
        filterChainDefinitionMap.put("/**", "authc");

        //添加拦截器
        shiroFilterFactoryBean.setFilterChainDefinitionMap(filterChainDefinitionMap);
        log.info("--------------------------Shiro拦截器工厂类注入成功------------------------------------");
        return shiroFilterFactoryBean;
    }


    /**
     * 调用自定义方法
     * 安全管理器：securityManager 核心部分
     */
    @Bean(name = "securityManager")
    public SecurityManager securityManager(@Qualifier("authRealm") AuthRealm authRealm) {
        log.info("--------------------------shiro已经加载------------------------------------");
        DefaultWebSecurityManager manager = new DefaultWebSecurityManager();
        //设置realm
        manager.setRealm(authRealm);
        //注入缓存管理器;
        //这个如果执行多次，也是同样的一个对象;
        manager.setCacheManager(ehCacheManager());
        //注入记住我管理器
        manager.setRememberMeManager(rememberMeManager());
        return manager;
    }

    /**
     * shiro缓存管理器;
     * 需要注入对应的其它的实体类中：
     * EhCacheManager，缓存管理，用户登陆成功后，把用户信息和权限信息缓存起来，
     * 然后每次用户请求时，放入用户的session中，如果不设置这个bean，每个请求都会查询一次数据库。
     */
    @Bean(name = "ehCacheManager")
    //控制bean加载顺序 表示被注解的bean在初始化时,指定的bean需要先完成初始化。
    @DependsOn("lifecycleBeanPostProcessor")
    public EhCacheManager ehCacheManager() {
        log.info("------------------shiro缓存注入成功-------------------------------");
        EhCacheManager cacheManager = new EhCacheManager();
        cacheManager.setCacheManagerConfigFile("classpath:config/ehcache-shiro.xml");
        return cacheManager;
    }


    /**
     * 身份认证realm; (这个需要自己写，账号密码校验；权限等)
     * 配置自定义的权限登录器
     *
     * @param matcher 参数是密码比较器,注入到authRealm中 以下自定义凭证匹配器三选一注入
     */
    @Bean(name = "authRealm")
    public AuthRealm authRealm(HashedCredentialsMatcher matcher) {
        AuthRealm authRealm = new AuthRealm();
        authRealm.setCredentialsMatcher(matcher);
        return authRealm;
    }


    //配置自定义的凭证匹配器
    //方式一 加盐
    @Bean
    public HashedCredentialsMatcher hashedCredentialsMatcher() {
        //自定义的凭证匹配器 可以用来记录密码错误次数
        HashedCredentialsMatcher hashedCredentialsMatcher = new RetryLimitHashedCredentialsMatcher(ehCacheManager());
        //原先的自定义凭证匹配器
        //HashedCredentialsMatcher hashedCredentialsMatcher = new HashedCredentialsMatcher();

        //storedCredentialsHexEncoded默认是true，此时用的是密码加密用的是Hex编码；false时用Base64编码
        hashedCredentialsMatcher.setStoredCredentialsHexEncoded(true);
        //散列算法:md5,sha-1,sha-256
        hashedCredentialsMatcher.setHashAlgorithmName(encryptType);
        //散列次数
        hashedCredentialsMatcher.setHashIterations(hashIterations);
        return hashedCredentialsMatcher;
    }

    //方式二 加密
    @Bean
    public CredentialsSaltMatcher credentialsSaltMatcher() {
        CredentialsSaltMatcher credentialsSaltMatcher = new CredentialsSaltMatcher();
        return credentialsSaltMatcher;
    }

    //方式三 自定义加密
    @Bean
    public CredentialsMatcher credentialsMatcher() {
        CredentialsMatcher credentialsMatcher = new CredentialsMatcher();
        return credentialsMatcher;
    }


    /**
     * 开启Shiro的注解(如@RequiresRoles,@RequiresPermissions),需借助SpringAOP扫描使用Shiro注解的类,并在必要时进行安全逻辑验证
     * 配置以下两个bean(DefaultAdvisorAutoProxyCreator(可选)和AuthorizationAttributeSourceAdvisor)即可实现此功能
     */

    /**
     * 开启shiro aop注解支持.
     * 使用代理方式;所以需要开启代码支持;
     *
     * @param securityManager
     * @return
     */
    @Bean
    public AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor(SecurityManager securityManager) {
        AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor = new AuthorizationAttributeSourceAdvisor();
        authorizationAttributeSourceAdvisor.setSecurityManager(securityManager);
        return authorizationAttributeSourceAdvisor;
    }


    @Bean
    @DependsOn({"lifecycleBeanPostProcessor"})
    public DefaultAdvisorAutoProxyCreator advisorAutoProxyCreator() {
        DefaultAdvisorAutoProxyCreator advisorAutoProxyCreator = new DefaultAdvisorAutoProxyCreator();
        advisorAutoProxyCreator.setProxyTargetClass(true);
        return advisorAutoProxyCreator;
    }


    /**
     * 添加ShiroDialect 为了在thymeleaf里使用shiro的标签的bean
     */
    @Bean(name = "shiroDialect")
    public ShiroDialect shiroDialect() {
        return new ShiroDialect();
    }


    /**
     * 记住我
     */
    @Bean
    public SimpleCookie rememberMeCookie() {

        log.info("--------------------------shiro的记住我功能加载成功--------------------------");
        //这个参数是cookie的名称，对应前端的checkbox的name = rememberMe
        SimpleCookie simpleCookie = new SimpleCookie("rememberMe");
        //<!-- 记住我cookie生效时间30天 ,单位秒;-->
        simpleCookie.setMaxAge(rememberMeMaxTime);
        return simpleCookie;
    }

    /**
     * Cookie管理对象
     */
    @Bean
    public CookieRememberMeManager rememberMeManager() {

        log.info("--------------------------shiroCookie管理对象加载成功--------------------------");
        CookieRememberMeManager cookieRememberMeManager = new CookieRememberMeManager();
        cookieRememberMeManager.setCookie(rememberMeCookie());
        return cookieRememberMeManager;
    }
}
