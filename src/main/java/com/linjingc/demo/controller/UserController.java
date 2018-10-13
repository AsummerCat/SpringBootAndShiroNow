package com.linjingc.demo.controller;

import com.linjingc.demo.vo.User;
import org.apache.catalina.servlet4preview.http.HttpServletRequest;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AccountException;
import org.apache.shiro.authc.ExcessiveAttemptsException;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.annotation.RequiresGuest;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.apache.shiro.subject.Subject;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.HashMap;
import java.util.Map;

/**
 * @author cxc
 * @date 2018/10/12 09:18
 */
@Controller
public class UserController {
    /**
     * 根地址跳转登录
     *
     * @return
     */
    @RequestMapping("/")
    public String show() {
        return "redirect:login";
    }

    @RequestMapping("/success")
    public String index() {
        return "index";
    }

    @GetMapping("/login")
    public String login(Model model) {
        User subject = (User) SecurityUtils.getSubject().getPrincipal();
        if (subject == null) {
            return "login";
        } else {
            model.addAttribute("user", subject);
            return "index";
        }
    }

    /**
     * 登录校验方法
     */
    @RequestMapping(value = "/loginUser", method = RequestMethod.POST)
    @ResponseBody
    public Object loginUser(String username, String password,boolean rememberMe, HttpServletRequest request) {
        UsernamePasswordToken usernamePasswordToken = new UsernamePasswordToken(username, password,rememberMe);
        Subject subject = SecurityUtils.getSubject();
        Map<String, Object> map = new HashMap<>();
        try {
            //完成登录
            subject.login(usernamePasswordToken);
            User user = (User) subject.getPrincipal();
            map.put("登录成功,用户名称:", user.getUsername());
            map.put("登录成功,用户密码", user.getPassword());
            return map;
        } catch (AccountException e) {
            map.put("登录失败信息", e.getMessage());
            return map;
        } catch (IncorrectCredentialsException e) {
            map.put("登录失败信息", "这下子真的是密码输出错误");
            return map;
        }
    }


    @RequestMapping(value = "/logout", method = RequestMethod.GET)
    public String logout(RedirectAttributes redirectAttributes) {
        //使用权限管理工具进行用户的退出，跳出登录，给出提示信息
        SecurityUtils.getSubject().logout();
        redirectAttributes.addFlashAttribute("message", "您已安全退出");
        return "redirect:/login";
    }

    /**
     * 查看用户是否拥有root这个角色
     */
    @RequiresRoles("root")
    @ResponseBody
    @RequestMapping(value = "/findRoles", method = RequestMethod.GET)
    public Map<String, Object> findRoles() {
        Map<String, Object> map = new HashMap<>();
        map.put("Roles", "你拥有当前角色");
        return map;
    }

    /**
     * 查看用户是否拥有游客这个角色
     */
    @RequiresGuest()
    @ResponseBody
    @RequestMapping(value = "/findRoleToGuest", method = RequestMethod.GET)
    public Map<String, Object> findRoleToGuest() {
        Map<String, Object> map = new HashMap<>();
        map.put("Roles", "当前角色为游客");
        return map;
    }
}
