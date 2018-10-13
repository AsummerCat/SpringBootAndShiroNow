package com.linjingc.demo.service;

import com.linjingc.demo.vo.User;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * @author cxc
 * @date 2018/10/12 09:20
 */
@Service
public class UserService {

    public User findUserByUserName(String userName){
        User user=new User();
        if (("admin").equals(userName)){
           user.setAge(100);
           user.setUsername(userName);
            // 密码加密
           user.setPassword("da5a4afe9c20e1650f62c181bf669c22");
            //权限
            String[] role={"add","delete","update"};
            Set<String> roles = new HashSet<>(Arrays.asList(role));
            user.setRoles(roles);
        }
        if(("test").equals(userName)){
            user.setAge(100);
            user.setUsername(userName);
            // 密码加密
            user.setPassword("16e68f68087fa828cb5ce52ce89cb9af");
            //权限
            String[] role={"add"};
            Set<String> roles = new HashSet<>(Arrays.asList(role));
            user.setRoles(roles);
        }
        return user;
    }
}
