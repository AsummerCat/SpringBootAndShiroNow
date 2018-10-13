package com.linjingc.demo.shiro;

import com.linjingc.demo.service.UserService;
import com.linjingc.demo.vo.User;
import lombok.extern.slf4j.Slf4j;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * @author cxc
 * shiro自定义授权类
 */
@Slf4j
public class AuthRealm extends AuthorizingRealm {
    @Autowired
    private UserService userService;
    @Value("${shiro.salt}")
    private String shiroSalt;

    //认证.登录
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        //UsernamePasswordToken对象用来存放提交的登录信息 登录表单
        UsernamePasswordToken utoken = (UsernamePasswordToken) token;
        String username = utoken.getUsername();

        //实际项目中，这里可以根据实际情况做缓存，如果不做，Shiro自己也是有时间间隔机制，2分钟内不会重复执行该方法
        User user = userService.findUserByUserName(username);

        //用户是否存在
        if (user == null) {
            throw new UnknownAccountException();
        }

        //加盐 可以自定义可以尝试  userName+salt
        ByteSource salt = ByteSource.Util.bytes(user.getUsername() + shiroSalt);

        //放入Shiro.调用CredentialsMatcher检验密码
        return new SimpleAuthenticationInfo(user, user.getPassword(), salt, getName());
    }

    //授权
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principal) {
        //获取session中的用户
        User user = (User) principal.getPrimaryPrincipal();
        log.info("当前用户授权中");
        List<String> permissions = new ArrayList<>();
        List<String> userRoles = new ArrayList<>();

        //用户角色
        Set roles = user.getRoles();
        if (roles.size() > 0) {
            //将查询到的用户权限放入一个权限集合中
            permissions.addAll(roles);
            //将查询到的用户角色放入一个角色集合中
            userRoles.add("root");
        }
        SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
        //将权限放入shiro中.
        info.addStringPermissions(permissions);
        //将用户角色放入session
        info.addRoles(userRoles);
        log.info("当前用户授权成功");
        return info;
    }
}