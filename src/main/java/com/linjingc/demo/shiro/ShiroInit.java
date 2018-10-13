package com.linjingc.demo.shiro;

import org.apache.shiro.spring.LifecycleBeanPostProcessor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * @author cxc
 * @date 2018/10/12 15:52
 * shiro生命周期处理器(单独)
 * 如果放在shiroConfig中可能会导致@value无法注入 所以单独放在一个配置类中
 */
@Configuration
public class ShiroInit {
    /**
     * Shiro生命周期处理器
     *
     * @return
     */
    @Bean
    public LifecycleBeanPostProcessor lifecycleBeanPostProcessor() {
        return new LifecycleBeanPostProcessor();
    }
}
