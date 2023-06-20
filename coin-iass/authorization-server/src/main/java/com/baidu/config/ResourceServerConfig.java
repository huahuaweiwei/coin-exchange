package com.baidu.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;

@EnableResourceServer  //开启资源服务器
@Configuration  //声明配置类
public class ResourceServerConfig extends ResourceServerConfigurerAdapter {
}
