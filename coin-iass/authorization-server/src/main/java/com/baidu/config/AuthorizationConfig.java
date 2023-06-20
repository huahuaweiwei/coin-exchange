package com.baidu.config;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;
import org.springframework.security.oauth2.provider.token.store.redis.RedisTokenStore;

//授权服务配置类
@EnableAuthorizationServer  //开启授权服务器的功能
@Configuration  //声明配置类
public class AuthorizationConfig extends AuthorizationServerConfigurerAdapter {
    @Autowired
    public PasswordEncoder passwordEncoder ;  //第三方客户端的秘钥
    @Autowired
    private AuthenticationManager authenticationManager ;  //验证管理器
    @Autowired
    private UserDetailsService userDetailsService ;
//    @Autowired
//    private RedisConnectionFactory redisConnectionFactory;  //redis的连接工具


    //配置第三方客户端
    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.inMemory()
                .withClient("coin-api")  //第三方客户端的名称
                .secret(passwordEncoder.encode("coin-secret")) //第三方客户端的秘钥
                .scopes("all")  //第三方客户端的授权范围
//                .authorizedGrantTypes("password","refresh")
                .authorizedGrantTypes("password","refresh_token")  //授权类型  默认有一个密码 我们自己加一个refresh_token授权机制
//                .accessTokenValiditySeconds(24 * 7200)  //token的有效期
                .accessTokenValiditySeconds(7 * 24 * 3600)  //token的有效期
//                .refreshTokenValiditySeconds(7 *  24 * 7200) ;  //refresh—_token的有效期
                .refreshTokenValiditySeconds(30 *  24 * 3600) ;  //refresh—_token的有效期
    }

    //设置授权管理器和UserDetailsService
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints.tokenStore(new InMemoryTokenStore())
                .authenticationManager(authenticationManager)   //验证管理器
                .userDetailsService(userDetailsService)
                //.tokenStore(redisTokenStore())
                .tokenStore(jwtTokenStore())  //设置token 存储在哪里  采用jwt存储token
                .tokenEnhancer(jwtAccessTokenConverter());  //装换器  将登录的实体转换成json去处理
    }

    //使用jwt存储token
    public  TokenStore jwtTokenStore(){
        JwtTokenStore jwtTokenStore = new JwtTokenStore(jwtAccessTokenConverter());
        return jwtTokenStore ;
    }

    //加载我们生成的私钥
    public JwtAccessTokenConverter jwtAccessTokenConverter(){
        JwtAccessTokenConverter tokenConverter = new JwtAccessTokenConverter() ;
        // 读取classpath 下面的密钥文件
        ClassPathResource classPathResource = new ClassPathResource("coinexchange.jks");
        // 获取KeyStoreFactory
        KeyStoreKeyFactory keyStoreKeyFactory = new KeyStoreKeyFactory(classPathResource,"coinexchange".toCharArray()) ;
        // 给JwtAccessTokenConverter 设置一个密钥对
        tokenConverter.setKeyPair(keyStoreKeyFactory.getKeyPair("coinexchange","coinexchange".toCharArray()));
        return  tokenConverter ;
    }

//    public TokenStore redisTokenStore(){
//        return new RedisTokenStore(redisConnectionFactory);
//    }
}