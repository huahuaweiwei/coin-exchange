package com.baidu.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
public class UserInfoController {
    /**
     * 获取该用户的对象
     * @param principal
     * @return
     */
    //当前登录的用户对象
    @GetMapping("/user/info")
    // 此处的principal 由OAuth2.0 框架自动注入
    public Principal usrInfo(Principal principal){
        //使用ThreadLocal来实现的
        //原理：利用Context概念，将授权用户放在线程里面，利用ThreadLocal来获取当前的用户对象
        //Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return principal ;
    }
}
